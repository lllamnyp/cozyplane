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
	"log"
	"net"
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

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/responder"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

const (
	fabricIPIndex = "fabricIP"
	podIndex      = "pod"
	svcIndex      = "service"
	localVPCIndex = "localVPC"
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
	log.Printf("cluster domain %q, upstreams %v", domain, upstreams)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	kube, err := kubernetes.NewForConfig(cfg)
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
	peeringInf := sdnFactory.Sdn().V1alpha1().VPCPeerings().Informer()
	if err := peeringInf.AddIndexers(cache.Indexers{
		localVPCIndex: func(obj any) ([]string, error) {
			p, ok := obj.(*sdnv1alpha1.VPCPeering)
			if !ok {
				return nil, nil
			}
			return []string{p.Namespace + "/" + p.Spec.VPCRef.Name}, nil
		},
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
	if err := portInf.AddIndexers(cache.Indexers{
		fabricIPIndex: func(obj any) ([]string, error) {
			p, ok := obj.(*sdnv1alpha1.Port)
			if !ok || p.Spec.FabricIP == "" {
				return nil, nil
			}
			return []string{canonIP(p.Spec.FabricIP)}, nil
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

	sdnFactory.Start(stop)
	kubeFactory.Start(stop)
	if !cache.WaitForCacheSync(stop, portInf.HasSynced, svcInf.HasSynced, epsInf.HasSynced, peeringInf.HasSynced, svipInf.HasSynced) {
		return fmt.Errorf("informer caches did not sync")
	}

	state := &informerState{ports: portInf.GetIndexer(), svcs: svcInf.GetIndexer(), eps: epsInf.GetIndexer(), peerings: peeringInf.GetIndexer(), svips: svipInf.GetIndexer()}
	res := &responder.Resolver{Domain: domain, Upstreams: upstreams, State: state}

	var wg sync.WaitGroup
	errc := make(chan error, 8)
	for _, ip := range []string{nodeIP, nodeIP6} {
		if ip == "" {
			continue
		}
		addr := net.JoinHostPort(ip, fmt.Sprint(datapath.ResolverPort))
		for _, proto := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: addr, Net: proto, Handler: res, ReusePort: true}
			wg.Add(1)
			go func() {
				defer wg.Done()
				log.Printf("listening on %s/%s", addr, proto)
				if err := srv.ListenAndServe(); err != nil {
					errc <- fmt.Errorf("listen %s/%s: %w", addr, proto, err)
				}
			}()
		}
	}
	return <-errc
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
	ports    cache.Indexer
	svcs     cache.Indexer
	eps      cache.Indexer
	peerings cache.Indexer
	svips    cache.Indexer
}

// ServiceVIPFor returns the VIP materialized for the service in the given
// VPC, nil while none exists (the controller may still be allocating).
func (s *informerState) ServiceVIPFor(ns, name string, vpc sdnv1alpha1.VPCRef) net.IP {
	objs, err := s.svips.ByIndex(svcIndex, ns+"/"+name)
	if err != nil {
		return nil
	}
	for _, obj := range objs {
		sv, ok := obj.(*sdnv1alpha1.ServiceVIP)
		if !ok || sv.Spec.VPCRef != vpc {
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
	objs, err := s.peerings.ByIndex(localVPCIndex, vpc.Namespace+"/"+vpc.Name)
	if err != nil {
		return nil
	}
	var out []sdnv1alpha1.VPCRef
	for _, obj := range objs {
		p, ok := obj.(*sdnv1alpha1.VPCPeering)
		if !ok || p.Status.Phase != sdnv1alpha1.VPCPeeringPhaseReady {
			continue
		}
		out = append(out, p.Spec.PeerRef)
	}
	return out
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

func (s *informerState) PortByFabricIP(ip string) *sdnv1alpha1.Port {
	objs, err := s.ports.ByIndex(fabricIPIndex, ip)
	if err != nil || len(objs) == 0 {
		return nil
	}
	p, ok := objs[0].(*sdnv1alpha1.Port)
	if !ok {
		return nil
	}
	return p
}

func (s *informerState) Service(ns, name string) *corev1.Service {
	obj, ok, err := s.svcs.GetByKey(ns + "/" + name)
	if err != nil || !ok {
		return nil
	}
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return nil
	}
	return svc
}

func (s *informerState) Endpoints(ns, svcName string, vpc sdnv1alpha1.VPCRef) []responder.Endpoint {
	objs, err := s.eps.ByIndex(svcIndex, ns+"/"+svcName)
	if err != nil {
		return nil
	}
	var out []responder.Endpoint
	seen := map[string]bool{} // a pod may appear in more than one slice
	for _, obj := range objs {
		slice, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok {
			continue
		}
		for _, ep := range slice.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
				continue
			}
			key := ep.TargetRef.Namespace + "/" + ep.TargetRef.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			ports, err := s.ports.ByIndex(podIndex, ep.TargetRef.Namespace+"/"+ep.TargetRef.Name)
			if err != nil {
				continue
			}
			for _, po := range ports {
				port, ok := po.(*sdnv1alpha1.Port)
				if !ok || port.Spec.VPCRef != vpc {
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
				out = append(out, responder.Endpoint{Hostname: hostname, IP: ip, Ready: ready})
			}
		}
	}
	return out
}

func canonIP(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
		return ip.String()
	}
	return s
}
