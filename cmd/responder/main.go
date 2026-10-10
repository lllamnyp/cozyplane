/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// cozyplane-responder is the per-node split-horizon DNS resolver for VPC pods
// (docs/services-in-vpc.md). It binds the node address on a reserved port; the
// datapath steers VPC pods' cluster-DNS queries here with the pod's fabric IP
// as source. It is deliberately less privileged than the agent: no bpffs, no
// netlink — informers and a DNS socket. The metadata endpoint
// (docs/vm-provisioning.md) will join this process later.
package main

import (
	"context"
	"fmt"
	"github.com/lllamnyp/cozyplane/internal/httpserver"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/responder"
	"github.com/lllamnyp/cozyplane/internal/serviceidentity"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	localclient "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

const (
	fabricIPIndex    = "fabricIP" // on FabricIPs: the underlay address
	podUIDIndex      = "podUID"   // on Ports: the claiming pod
	podIndex         = "pod"
	svcIndex         = "service"
	localVPCIndex    = "localVPC"
	peeringPairIndex = "peeringPair"
	maxPeeringWork   = 65536
	maxDNSPeers      = 4096
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("responder: %v", err)
	}
}

func run() error {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME must be set (downward API)")
	}
	// The cluster domain: explicit env wins; otherwise autodetect from this
	// container's own kubelet-written resolv.conf. The DaemonSet runs
	// dnsPolicy: ClusterFirstWithHostNet, so despite hostNetwork the file
	// carries the cluster search path (…, svc.<domain>, <domain>) — distinct
	// from the *node's* resolv.conf mounted at RESOLV_CONF for upstreams.
	domain := os.Getenv("CLUSTER_DOMAIN")
	if domain == "" {
		domain = detectClusterDomain("/etc/resolv.conf")
	}
	if domain == "" {
		domain = "cluster.local"
	}

	// The node's resolv.conf (mounted by the DaemonSet — the pod-level
	// dnsPolicy points the container's own resolv.conf at the cluster DNS,
	// which is not what external names should be forwarded to).
	resolvConf := os.Getenv("RESOLV_CONF")
	if resolvConf == "" {
		resolvConf = "/etc/resolv.conf"
	}
	upstreams, err := upstreamsFromResolvConf(resolvConf)
	if err != nil {
		return err
	}
	// #nosec G706 -- Both untrusted strings are quoted with %q, escaping control characters and newlines.
	log.Printf("cluster domain %q, upstreams %q", domain, upstreams)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	local, err := localclient.NewForConfig(cfg)
	if err != nil {
		return err
	}
	sdn, err := sdnclient.NewForConfig(cfg)
	if err != nil {
		return err
	}

	// Bind exactly the node InternalIPs the agent programs into the datapath
	// (dns_steer's rewrite targets); same source of truth, no drift.
	nodeIP, nodeIP6, err := nodeInternalIPs(kube, nodeName)
	if err != nil {
		return err
	}
	if nodeIP == "" && nodeIP6 == "" {
		return fmt.Errorf("node %q has no InternalIP", nodeName)
	}

	stop := make(chan struct{})
	defer close(stop)

	sdnFactory := sdninformers.NewSharedInformerFactory(sdn, 0)
	vpcInf := sdnFactory.Sdn().V1alpha1().VPCs().Informer()
	peeringInf := sdnFactory.Sdn().V1alpha1().VPCPeerings().Informer()
	if err := peeringInf.AddIndexers(cache.Indexers{
		localVPCIndex:    peeringLocalIndexFunc,
		peeringPairIndex: peeringPairIndexFunc,
	}); err != nil {
		return err
	}
	svipInf := sdnFactory.Sdn().V1alpha1().ServiceVIPs().Informer()
	if err := svipInf.AddIndexers(cache.Indexers{
		svcIndex: func(obj any) ([]string, error) {
			sv, ok := obj.(*sdnv1alpha1.ServiceVIP)
			if !ok {
				return nil, nil
			}
			return []string{sv.Spec.ServiceRef.Namespace + "/" + sv.Spec.ServiceRef.Name}, nil
		},
	}); err != nil {
		return err
	}
	portInf := sdnFactory.Sdn().V1alpha1().Ports().Informer()
	bindingInf := sdnFactory.Sdn().V1alpha1().VPCBindings().Informer()
	if err := portInf.AddIndexers(cache.Indexers{
		podUIDIndex: func(obj any) ([]string, error) {
			p, ok := obj.(*sdnv1alpha1.Port)
			if !ok {
				return nil, nil
			}
			if uid := p.Labels[sdnv1alpha1.LabelPodUID]; uid != "" {
				return []string{uid}, nil
			}
			return nil, nil
		},
		podIndex: func(obj any) ([]string, error) {
			p, ok := obj.(*sdnv1alpha1.Port)
			if !ok || p.Spec.PodName == "" {
				return nil, nil
			}
			return []string{p.Spec.PodNamespace + "/" + p.Spec.PodName}, nil
		},
	}); err != nil {
		return err
	}

	kubeFactory := informers.NewSharedInformerFactory(kube, 0)
	svcInf := kubeFactory.Core().V1().Services().Informer()
	epsInf := kubeFactory.Discovery().V1().EndpointSlices().Informer()
	if err := epsInf.AddIndexers(cache.Indexers{
		svcIndex: func(obj any) ([]string, error) {
			s, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok {
				return nil, nil
			}
			svc := s.Labels[discoveryv1.LabelServiceName]
			if svc == "" {
				return nil, nil
			}
			return []string{s.Namespace + "/" + svc}, nil
		},
	}); err != nil {
		return err
	}

	// The querying pod is identified by its UNDERLAY address (the source of the
	// steered DNS packet), which lives in its FabricIP claim — not on the Port
	// (docs/api-groups.md). Resolve address -> pod UID -> Port.
	localFactory := localinformers.NewSharedInformerFactory(local, 0)
	fipInf := localFactory.Local().V1alpha1().FabricIPs().Informer()
	if err := fipInf.AddIndexers(cache.Indexers{
		fabricIPIndex: func(obj any) ([]string, error) {
			f, ok := obj.(*localv1alpha1.FabricIP)
			if !ok || f.Spec.Address == "" {
				return nil, nil
			}
			return []string{canonIP(f.Spec.Address)}, nil
		},
	}); err != nil {
		return err
	}

	sdnFactory.Start(stop)
	localFactory.Start(stop)
	kubeFactory.Start(stop)
	if !cache.WaitForCacheSync(stop, vpcInf.HasSynced, portInf.HasSynced, bindingInf.HasSynced, svcInf.HasSynced, epsInf.HasSynced, peeringInf.HasSynced, svipInf.HasSynced, fipInf.HasSynced) {
		return fmt.Errorf("informer caches did not sync")
	}

	state := &informerState{vpcs: vpcInf.GetIndexer(), bindings: bindingInf.GetIndexer(), ports: portInf.GetIndexer(), svcs: svcInf.GetIndexer(), eps: epsInf.GetIndexer(), peerings: peeringInf.GetIndexer(), svips: svipInf.GetIndexer(), fips: fipInf.GetIndexer()}
	res := &responder.Resolver{Domain: domain, Upstreams: upstreams, State: state}

	// DNS observability (docs/observability.md §D): opt-in like the rest of
	// observability (off by default, matching Cozystack's Hubble posture). When
	// enabled, count and serve the query/response aggregates on a distinct port
	// (the agent already holds :9411/:9412 in this shared hostNetwork namespace).
	// Disabled, the resolver never counts and binds no extra port.
	if os.Getenv("COZYPLANE_DNS_METRICS") == "1" {
		metrics := responder.NewDNSMetrics()
		res.Metrics = metrics // nil-safe when unset
		go serveDNSMetrics(metrics, nodeName)
	}

	var wg sync.WaitGroup
	errc := make(chan error, 8)
	tcpSlots := make(chan struct{}, 256)
	udpSlots := make(chan struct{}, 256)
	for _, ip := range []string{nodeIP, nodeIP6} {
		if ip == "" {
			continue
		}
		addr := net.JoinHostPort(ip, fmt.Sprint(datapath.ResolverPort))
		for _, proto := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: addr, Net: proto, Handler: res, ReusePort: true}
			if proto == "udp" {
				installDNSUDPAdmission(srv, udpSlots)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				// #nosec G706 -- addr is built from a parsed node IP and fixed port; protocol is one of two literals.
				log.Printf("listening on %s/%s", addr, proto)
				if proto == "tcp" {
					listener, err := listenDNSTCP(addr, tcpSlots)
					if err != nil {
						errc <- fmt.Errorf("listen %s/%s: %w", addr, proto, err)
						return
					}
					srv.Listener = listener
					if err := srv.ActivateAndServe(); err != nil {
						errc <- fmt.Errorf("serve %s/%s: %w", addr, proto, err)
					}
					return
				}
				if err := srv.ListenAndServe(); err != nil {
					errc <- fmt.Errorf("listen %s/%s: %w", addr, proto, err)
				}
			}()
		}
	}
	return <-errc
}

// dnsMetricsAddr is where the responder serves its DNS metrics. Distinct from
// the agent's :9411 (same hostNetwork namespace) and its :9412 flow loopback.
const dnsMetricsAddr = ":9413"

// serveDNSMetrics exposes the resolver's DNS counters as Prometheus text.
func serveDNSMetrics(m *responder.DNSMetrics, node string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		m.WriteMetrics(&b, node)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})
	log.Printf("serving DNS metrics on %s/metrics", dnsMetricsAddr)
	srv := httpserver.New(dnsMetricsAddr, mux)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("dns metrics server: %v", err)
	}
}

// nodeInternalIPs returns the node's InternalIP per family.
func nodeInternalIPs(kube kubernetes.Interface, nodeName string) (v4, v6 string, err error) {
	node, err := kube.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("get node %q: %w", nodeName, err)
	}
	for _, a := range node.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(a.Address)
		if ip == nil {
			continue
		}
		if ip.To4() != nil && v4 == "" {
			v4 = a.Address
		} else if ip.To4() == nil && v6 == "" {
			v6 = a.Address
		}
	}
	return v4, v6, nil
}

// upstreamsFromResolvConf reads the node's forwarders — the same upstreams
// kube-dns itself uses. In the DaemonSet the container runs with
// dnsPolicy: Default, so /etc/resolv.conf is the node's.
func upstreamsFromResolvConf(path string) ([]string, error) {
	cc, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var ups []string
	for _, s := range cc.Servers {
		ups = append(ups, net.JoinHostPort(s, cc.Port))
	}
	if len(ups) == 0 {
		return nil, fmt.Errorf("no upstream nameservers in %s", path)
	}
	return ups, nil
}

// informerState implements responder.State over the shared informer indexes.
type informerState struct {
	vpcs     cache.Indexer
	bindings cache.Indexer
	fips     cache.Indexer
	ports    cache.Indexer
	svcs     cache.Indexer
	eps      cache.Indexer
	peerings cache.Indexer
	svips    cache.Indexer
}

// ServiceVIPFor returns the VIP materialized for the service in the given
// VPC, nil while none exists (the controller may still be allocating).
func (s *informerState) ServiceVIPFor(ns, name string, vpc sdnv1alpha1.VPCRef) net.IP {
	if s.svips == nil || s.svcs == nil {
		return nil
	}
	object, found, err := s.svcs.GetByKey(ns + "/" + name)
	if err != nil || !found {
		return nil
	}
	service, ok := object.(*corev1.Service)
	if !ok {
		return nil
	}
	currentVPC := s.liveVPC(vpc)
	objs, err := s.svips.ByIndex(svcIndex, ns+"/"+name)
	if err != nil {
		return nil
	}
	for _, obj := range objs {
		sv, ok := obj.(*sdnv1alpha1.ServiceVIP)
		if !ok || !serviceidentity.MatchesService(sv, service) || !serviceidentity.MatchesVPC(sv, currentVPC) {
			continue
		}
		return net.ParseIP(sv.Spec.IP)
	}
	return nil
}

// Peers lists the VPCs actively peered with vpc: its namespace holds one half
// of each of its peerings; a half whose status is Ready is matched by its
// reciprocal, both VPCs are Ready, and the CIDRs are disjoint (the status
// controller owns those semantics — one source of truth with the datapath).
func (s *informerState) Peers(vpc sdnv1alpha1.VPCRef) []sdnv1alpha1.VPCRef {
	if s.peerings == nil || !vpnlimits.NamespaceName(vpc.Namespace) || !vpnlimits.ObjectName(vpc.Name) {
		return nil
	}
	objs, err := s.peerings.ByIndex(localVPCIndex, vpc.Namespace+"/"+vpc.Name)
	if err != nil || len(objs) > maxPeeringWork {
		return nil
	}
	local := s.liveVPC(vpc)
	if local == nil || len(local.Spec.CIDRs) > maxPeeringWork {
		return nil
	}
	work := len(objs)
	seen := map[sdnv1alpha1.VPCRef]bool{}
	var out []sdnv1alpha1.VPCRef
	for _, obj := range objs {
		p, ok := obj.(*sdnv1alpha1.VPCPeering)
		if !ok || !p.DeletionTimestamp.IsZero() || p.Status.Phase != sdnv1alpha1.VPCPeeringPhaseReady || !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
			continue
		}
		if seen[p.Spec.PeerRef] {
			continue
		}
		seen[p.Spec.PeerRef] = true
		reciprocals, err := s.peerings.ByIndex(peeringPairIndex, peeringPairKey(p.Spec.PeerRef, vpc))
		if err != nil {
			continue
		}
		if len(reciprocals) > maxPeeringWork-work {
			return nil
		}
		work += len(reciprocals)
		if len(reciprocals) == 0 {
			continue
		}
		remote := s.liveVPC(p.Spec.PeerRef)
		if remote == nil {
			continue
		}
		if len(remote.Spec.CIDRs) > (maxPeeringWork-work)/len(local.Spec.CIDRs) {
			return nil
		}
		work += len(local.Spec.CIDRs) * len(remote.Spec.CIDRs)
		if sdnv1alpha1.CIDRsOverlap(local.Spec.CIDRs, remote.Spec.CIDRs) {
			continue
		}
		for _, object := range reciprocals {
			if reciprocal, ok := object.(*sdnv1alpha1.VPCPeering); ok && p.Matches(reciprocal) {
				if len(out) >= maxDNSPeers {
					return nil
				}
				out = append(out, p.Spec.PeerRef)
				break
			}
		}
	}
	return out
}

func peeringPairKey(local, remote sdnv1alpha1.VPCRef) string {
	return local.Namespace + "/" + local.Name + "/" + remote.Namespace + "/" + remote.Name
}

func peeringPairIndexFunc(obj any) ([]string, error) {
	p, ok := obj.(*sdnv1alpha1.VPCPeering)
	if !ok || !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
		return nil, nil
	}
	return []string{peeringPairKey(p.LocalRef(), p.Spec.PeerRef)}, nil
}

func peeringLocalIndexFunc(obj any) ([]string, error) {
	p, ok := obj.(*sdnv1alpha1.VPCPeering)
	if !ok || !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
		return nil, nil
	}
	return []string{p.Namespace + "/" + p.Spec.VPCRef.Name}, nil
}

func (s *informerState) liveVPC(ref sdnv1alpha1.VPCRef) *sdnv1alpha1.VPC {
	if s.vpcs == nil {
		return nil
	}
	object, found, err := s.vpcs.GetByKey(ref.Namespace + "/" + ref.Name)
	if err != nil || !found {
		return nil
	}
	vpc, ok := object.(*sdnv1alpha1.VPC)
	if !ok || !vpc.DeletionTimestamp.IsZero() || vpc.Status.VNI == 0 || len(vpc.Spec.CIDRs) == 0 {
		return nil
	}
	return vpc
}

// detectClusterDomain parses kubelet's search path for the "svc.<domain>"
// entry. Empty when the file has no cluster search path (e.g. dnsPolicy
// Default), in which case the caller falls back.
func detectClusterDomain(path string) string {
	cc, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return ""
	}
	for _, s := range cc.Search {
		if rest, ok := strings.CutPrefix(s, "svc."); ok && rest != "" {
			return rest
		}
	}
	return ""
}

// PortByFabricIP identifies the querying VPC pod from the underlay source
// address of its DNS packet: FabricIP (address -> pod) then Port (pod -> VPC
// identity). Two lookups instead of one, and no denormalized address that can
// go stale when a pod is re-created or a VM migrates.
func (s *informerState) PortByFabricIP(ip string) *sdnv1alpha1.Port {
	fobjs, err := s.fips.ByIndex(fabricIPIndex, ip)
	if err != nil || len(fobjs) == 0 {
		return nil
	}
	fip, ok := fobjs[0].(*localv1alpha1.FabricIP)
	if !ok || !fip.DeletionTimestamp.IsZero() || fip.Spec.PodUID == "" {
		return nil
	}
	objs, err := s.ports.ByIndex(podUIDIndex, fip.Spec.PodUID)
	if err != nil || len(objs) == 0 {
		return nil
	}
	var result *sdnv1alpha1.Port
	for _, obj := range objs {
		p, ok := obj.(*sdnv1alpha1.Port)
		if !ok || !serviceidentity.MatchesPortVPC(p, s.liveVPC(p.Spec.VPCRef)) || !s.bindingExists(p.Spec.PodNamespace, p.Spec.VPCRef) {
			continue
		}
		if fip.Spec.ContainerID != "" {
			if p.Annotations[sdnv1alpha1.AnnotationContainerID] != fip.Spec.ContainerID ||
				p.Annotations[sdnv1alpha1.AnnotationCNIIfName] != fip.Spec.IfName ||
				p.Annotations[sdnv1alpha1.AnnotationCNIPrimary] != "true" {
				continue
			}
		} else if p.Annotations[sdnv1alpha1.AnnotationCNIPrimary] == "false" {
			continue
		}
		if result != nil {
			return nil
		} // ambiguous legacy or invalid duplicate primary
		result = p
	}
	return result
}

func (s *informerState) bindingExists(namespace string, vpc sdnv1alpha1.VPCRef) bool {
	if s.bindings == nil {
		return false
	}
	objects, err := s.bindings.ByIndex(cache.NamespaceIndex, namespace)
	if err != nil {
		return false
	}
	for _, obj := range objects {
		if binding, ok := obj.(*sdnv1alpha1.VPCBinding); ok && sdnv1alpha1.BindingAuthorizesAttachment(binding, namespace, vpc.Namespace, vpc.Name) {
			return true
		}
	}
	return false
}

func (s *informerState) Service(ns, name string) *corev1.Service {
	obj, ok, err := s.svcs.GetByKey(ns + "/" + name)
	if err != nil || !ok {
		return nil
	}
	svc, ok := obj.(*corev1.Service)
	if !ok || !svc.DeletionTimestamp.IsZero() {
		return nil
	}
	if annotation := svc.Annotations[sdnv1alpha1.AnnotationVPC]; annotation != "" {
		vpc := sdnv1alpha1.VPCRef{Namespace: ns, Name: annotation}
		if owner, name, explicit := strings.Cut(annotation, "/"); explicit {
			vpc.Namespace, vpc.Name = owner, name
		}
		if !s.bindingExists(ns, vpc) {
			return nil
		}
	}
	return svc
}

func (s *informerState) Endpoints(ns, svcName string, vpc sdnv1alpha1.VPCRef) ([]responder.Endpoint, error) {
	currentVPC := s.liveVPC(vpc)
	if currentVPC == nil {
		return nil, fmt.Errorf("current VPC identity is unavailable")
	}
	if s.svcs == nil {
		return nil, fmt.Errorf("Service cache is unavailable")
	}
	object, found, err := s.svcs.GetByKey(ns + "/" + svcName)
	if err != nil {
		return nil, err
	}
	svc, valid := object.(*corev1.Service)
	if !found || !valid || svc.UID == "" || !svc.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("current Service identity is unavailable")
	}
	objs, err := s.eps.ByIndex(svcIndex, ns+"/"+svcName)
	if err != nil {
		return nil, err
	}
	if len(objs) > responder.MaxEndpointWork {
		return nil, fmt.Errorf("DNS endpoint scan exceeds work budget")
	}
	var out []responder.Endpoint
	seen := map[string]bool{} // a pod may appear in more than one slice
	work := 0
	spend := func() bool { work++; return work <= responder.MaxEndpointWork }
	for _, obj := range objs {
		if !spend() {
			return nil, fmt.Errorf("DNS endpoint scan exceeds work budget")
		}
		slice, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok || !serviceidentity.OwnsEndpointSlice(svc, slice) {
			continue
		}
		for _, ep := range slice.Endpoints {
			if !spend() {
				return nil, fmt.Errorf("DNS endpoint scan exceeds work budget")
			}
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.UID == "" {
				continue
			}
			key := ep.TargetRef.Namespace + "/" + ep.TargetRef.Name
			if seen[key] {
				continue
			}
			ports, err := s.ports.ByIndex(podIndex, ep.TargetRef.Namespace+"/"+ep.TargetRef.Name)
			if err != nil {
				continue
			}
			for _, po := range ports {
				if !spend() {
					return nil, fmt.Errorf("DNS endpoint scan exceeds work budget")
				}
				port, ok := po.(*sdnv1alpha1.Port)
				if !ok || !serviceidentity.MatchesPortVPC(port, currentVPC) ||
					port.Labels[sdnv1alpha1.LabelPodUID] != string(ep.TargetRef.UID) {
					continue // the structural authz: only same-VPC backends exist
				}
				ip := net.ParseIP(port.Spec.IP)
				if ip == nil {
					continue
				}
				hostname := ep.TargetRef.Name
				if ep.Hostname != nil && *ep.Hostname != "" {
					hostname = *ep.Hostname
				}
				ready := ep.Conditions.Ready == nil || *ep.Conditions.Ready
				if len(out) >= responder.MaxEndpoints {
					return nil, fmt.Errorf("DNS endpoint view exceeds retention budget")
				}
				out = append(out, responder.Endpoint{Hostname: hostname, IP: ip, Ready: ready})
				seen[key] = true
			}
		}
	}
	return out, nil
}

func canonIP(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
		return ip.String()
	}
	return s
}
