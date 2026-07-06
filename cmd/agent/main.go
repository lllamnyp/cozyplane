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

// Command cozyplane-agent is the per-node datapath manager. It loads the eBPF
// overlay, manages the Geneve device, watches Node objects to learn remote pod
// CIDRs, publishes node state for the CNI plugin, and writes the CNI conf.
//
// It depends only on the core Kubernetes API (Nodes) — never on the aggregated
// sdn.cozystack.io API — so it can bring up the default network during cluster
// bootstrap before anything else is reachable.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	sdnv1alpha1informers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions/sdn/v1alpha1"
)

const (
	cniConfDir         = "/etc/cni/net.d"
	defaultCNIConfFile = "10-cozyplane.conflist"
	cniConfBody        = `{
  "cniVersion": "1.0.0",
  "name": "cozyplane",
  "plugins": [
    { "type": "cozyplane", "mtu": %d }
  ]
}
`
)

func main() {
	var (
		nodeName      = os.Getenv("NODE_NAME")
		mtu           int
		vni           uint
		cniConfName   string
		genevePort    uint
		clusterCIDR   string
		internalCIDRs string
		masqMode      string
		vpcDNS        bool
		clusterDNSIPs string
	)
	flag.IntVar(&mtu, "mtu", 1450, "pod MTU (underlay MTU minus Geneve overhead)")
	flag.UintVar(&vni, "vni", uint(datapath.DefaultVNI), "VNI for the default network")
	flag.StringVar(&cniConfName, "cni-conf-name", defaultCNIConfFile,
		"filename for the CNI conflist in /etc/cni/net.d (lower sorts first, winning over other CNIs)")
	flag.UintVar(&genevePort, "geneve-port", datapath.GenevePort,
		"Geneve UDP destination port (use a non-default port to coexist with another overlay on 6081)")
	flag.StringVar(&clusterCIDR, "cluster-cidr", "",
		"cluster pod supernet; when set, pod traffic leaving it is masqueraded to the node address (pod egress to the outside)")
	flag.StringVar(&masqMode, "masquerade", "bpf",
		"cluster-egress masquerade implementation: bpf (eBPF SNAT at the uplink, no netfilter), iptables (kernel MASQUERADE rule), off (the environment masquerades elsewhere)")
	flag.StringVar(&internalCIDRs, "internal-cidrs", "",
		"comma-separated cluster-internal CIDRs (pod, service, node networks) a floating pod's public-IP egress must not reach")
	flag.BoolVar(&vpcDNS, "vpc-dns", true,
		"steer VPC pods' cluster-DNS queries to the node-local split-horizon resolver (docs/services-in-vpc.md)")
	flag.StringVar(&clusterDNSIPs, "cluster-dns", "",
		"comma-separated cluster DNS ClusterIP(s) to steer; empty auto-discovers from the kube-system/kube-dns Service")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if nodeName == "" {
		log.Error("NODE_NAME must be set (downward API)")
		os.Exit(1)
	}

	if err := run(nodeName, mtu, uint32(vni), cniConfName, uint16(genevePort), clusterCIDR, internalCIDRs, masqMode, vpcDNS, clusterDNSIPs, log); err != nil {
		log.Error("agent failed", "err", err)
		os.Exit(1)
	}
}

func run(nodeName string, mtu int, vni uint32, cniConfName string, genevePort uint16, clusterCIDR, internalCIDRs, masqMode string, vpcDNS bool, clusterDNSIPs string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Permit forwarding and accept asymmetric/encapsulated return traffic.
	for path, val := range map[string]string{
		"net/ipv4/ip_forward":             "1",
		"net/ipv4/conf/all/rp_filter":     "0",
		"net/ipv4/conf/default/rp_filter": "0",
	} {
		if err := datapath.WriteProcSys(path, val); err != nil {
			log.Warn("set sysctl", "path", path, "err", err)
		}
	}

	if err := datapath.EnsureBPFFS(); err != nil {
		return fmt.Errorf("ensure bpffs: %w", err)
	}

	mgr := datapath.New()
	if err := mgr.Load(vni); err != nil {
		return fmt.Errorf("load datapath: %w", err)
	}
	defer mgr.Close()
	if err := mgr.EnsureGeneve(genevePort); err != nil {
		return fmt.Errorf("ensure geneve: %w", err)
	}
	if err := mgr.AttachOverlay(); err != nil {
		return fmt.Errorf("attach overlay hook: %w", err)
	}
	// Overlay FORWARD ACCEPTs: installed per family only where kube-proxy's
	// KUBE-FORWARD chain (whose INVALID drop they counter) exists (#10).
	if fams, err := datapath.EnsureForwardRules(); err != nil {
		return fmt.Errorf("ensure forward rules: %w", err)
	} else if len(fams) > 0 {
		log.Info("installed overlay FORWARD ACCEPTs (kube-proxy present)", "families", fams)
	}
	// Cluster-egress masquerade (#10): bpf (the default) programs it into the
	// datapath below once the node IP is known; iptables installs the classic
	// kernel rule; each mode tears the other's state down so a switch never
	// double-NATs.
	// --cluster-cidr may list both families; the legacy kernel rule is v4-only,
	// so iptables mode uses the v4 entry (v6 egress needs --masquerade=bpf).
	if v4cidr := firstV4CIDR(clusterCIDR); v4cidr != "" && masqMode == "iptables" {
		if err := datapath.EnsureMasquerade(v4cidr); err != nil {
			return fmt.Errorf("ensure masquerade: %w", err)
		}
	} else if v4cidr != "" {
		datapath.RemoveMasquerade(v4cidr)
	}
	if masqMode != "bpf" {
		// Clearing the sources alone disables the masquerade (masq_snat gates
		// on masq_srcs before anything else); the node IPs stay programmed —
		// the DNS steer addresses its resolver rewrites to them.
		if err := mgr.SyncMasqSources(nil); err != nil {
			log.Warn("clear bpf masquerade sources", "err", err)
		}
	}
	uplink, err := mgr.AttachUplink()
	if err != nil {
		return fmt.Errorf("attach uplink: %w", err)
	}
	// from_uplink at the uplink ingress: the entry point for floating-IP traffic.
	// A no-op for every non-floating packet, so it is always safe to attach.
	if _, err := mgr.AttachUplinkIngress(); err != nil {
		return fmt.Errorf("attach uplink ingress: %w", err)
	}
	// Cluster-internal CIDRs a floating pod's public-IP egress must not reach
	// (it bypasses the gateway that would otherwise deny them).
	if internal := splitCIDRs(internalCIDRs); len(internal) > 0 {
		if err := mgr.SetInternal(internal); err != nil {
			return fmt.Errorf("program internal CIDRs: %w", err)
		}
	}
	log.Info("datapath loaded", "vni", vni, "geneve", datapath.GeneveDevice, "uplink", uplink)

	// Restore the CNI-written map state (ports/locals/bridges) of existing local
	// pods from their veths' alias records, and swap every veth's classifiers to
	// the freshly pinned programs. Vital after a map-ABI recreate (issue #7 —
	// the maps came back empty); on a compatible restart it is a no-op re-put
	// plus a program refresh existing pods would otherwise miss. Best-effort:
	// a partly-rebuilt node beats a crash-looping agent.
	if recreated := mgr.RecreatedPins(); len(recreated) > 0 {
		log.Warn("recreated incompatible pinned maps (map-ABI change)", "maps", recreated)
	}
	stats, err := mgr.RebuildLocalState()
	if err != nil {
		log.Warn("local-state rebuild incomplete", "err", err)
	}
	if stats.Rebuilt > 0 || stats.Reattached > 0 || len(stats.Skipped) > 0 {
		log.Info("local pod state rebuilt", "rebuilt", stats.Rebuilt, "reattached", stats.Reattached, "skipped", stats.Skipped)
	}
	if len(stats.Skipped) > 0 && len(mgr.RecreatedPins()) > 0 {
		log.Warn("veths without a rebuild record lost their datapath state; restart their pods", "veths", stats.Skipped)
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kube client: %w", err)
	}

	self, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get self node %q: %w", nodeName, err)
	}
	podCIDR := self.Spec.PodCIDR
	if podCIDR == "" {
		return fmt.Errorf("node %q has no spec.podCIDR (is --allocate-node-cidrs enabled?)", nodeName)
	}
	// PodCIDRs carries every family (dual-stack: a v4 and a v6 CIDR); fall back to
	// the single PodCIDR on a single-stack node. A v6 VPC pod's fabric IP is drawn
	// from the v6 entry.
	podCIDRs := self.Spec.PodCIDRs
	if len(podCIDRs) == 0 {
		podCIDRs = []string{podCIDR}
	}
	state := &datapath.AgentState{
		NodeName:  nodeName,
		NodeIP:    internalIP(self),
		PodCIDR:   podCIDR,
		PodCIDRs:  podCIDRs,
		MTU:       mtu,
		Namespace: os.Getenv("AGENT_NAMESPACE"), // gates gateway-attach to the system namespace
	}
	if err := state.Save(); err != nil {
		return fmt.Errorf("publish agent state: %w", err)
	}
	// Keep the plugin's token copy fresh as kubelet rotates the projected SA
	// token (bound tokens expire ~hourly; the embedded-once copy only worked
	// via the API server's expired-token grace). Cheap poll, well inside the
	// refresh window.
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if rotated, err := datapath.SyncPluginToken(); err != nil {
					log.Warn("sync plugin token", "err", err)
				} else if rotated {
					log.Info("plugin SA token rotated")
				}
			}
		}
	}()
	if err := datapath.WritePluginKubeconfig(); err != nil {
		log.Warn("write plugin kubeconfig (VPC attachment unavailable)", "err", err)
	}
	// The node addresses are programmed unconditionally: the bpf masquerade
	// (gated separately on masq_srcs) SNATs to them, and the DNS steer
	// re-addresses VPC pods' resolver queries to them (dns_steer/dns_return).
	if v4 := internalIPv4(self); v4 != "" {
		if err := mgr.SetNodeIP(net.ParseIP(v4)); err != nil {
			return fmt.Errorf("program node IP: %w", err)
		}
	}
	// Without a node v6 address the v6 masquerade and v6 DNS steering stay
	// off — pod v6 egress has no off-cluster return path (matching v4-only
	// nodes), and a v6 cluster-DNS query has no resolver to be steered to.
	nodeV6 := internalIPv6(self)
	if nodeV6 != "" {
		if err := mgr.SetNodeIP6(net.ParseIP(nodeV6)); err != nil {
			return fmt.Errorf("program node IPv6: %w", err)
		}
	}
	if masqMode == "bpf" && clusterCIDR != "" {
		if err := mgr.SyncMasqSources(splitCIDRs(clusterCIDR)); err != nil {
			return fmt.Errorf("program masquerade sources: %w", err)
		}
		log.Info("bpf cluster-egress masquerade enabled", "sources", clusterCIDR, "nodeIP", state.NodeIP, "nodeIPv6", nodeV6)
	}

	// VPC DNS steering (docs/services-in-vpc.md): publish the cluster DNS
	// address(es) and the node-local resolver port; dns_steer in from_pod
	// re-addresses VPC pods' queries to the responder. Zero config disables.
	var rdnss net.IP // v6 resolver address the RA responder advertises
	if vpcDNS {
		dns4, dns6 := parseDNSIPs(clusterDNSIPs)
		if dns4 == nil && dns6 == nil {
			dns4, dns6 = discoverClusterDNS(ctx, client)
		}
		if dns4 == nil && dns6 == nil {
			log.Warn("VPC DNS steering disabled: no cluster DNS address found (set --cluster-dns)")
		} else {
			if err := mgr.SetClusterDNS(dns4, dns6); err != nil {
				return fmt.Errorf("program cluster DNS: %w", err)
			}
			if err := mgr.SetResolverPort(datapath.ResolverPort); err != nil {
				return fmt.Errorf("program resolver port: %w", err)
			}
			log.Info("VPC DNS steering enabled", "dnsV4", dns4, "dnsV6", dns6, "resolverPort", datapath.ResolverPort)
			rdnss = dns6
		}
	} else {
		if err := mgr.SetResolverPort(0); err != nil {
			log.Warn("clear resolver port", "err", err)
		}
	}

	// Router Advertisements for v6 VPC pods (#8): a bridge-bound VM guest
	// learns its pinned /128, the fe80::1 default route, and (when a v6
	// resolver path exists) its DNS server — no console, no DHCPv6.
	go datapath.RunRAResponder(ctx, mtu, rdnss, log)

	log.Info("published node state", "nodeIP", state.NodeIP, "podCIDR", podCIDR, "mtu", mtu)

	if err := watchNodes(ctx, client, mgr, nodeName, log); err != nil {
		return err
	}

	// VPC watching is best-effort: the default network must work even before the
	// sdn.cozystack.io API exists, so we don't block readiness on it. One shared
	// factory backs all sdn informers; it is started only after every handler is
	// registered.
	if sdnClient, err := sdnclientset.NewForConfig(cfg); err != nil {
		log.Warn("sdn client init failed; VPC networks won't be programmed", "err", err)
	} else {
		factory := sdninformers.NewSharedInformerFactory(sdnClient, 0)
		watchVPCs(factory, mgr, log)
		watchPorts(ctx, factory, sdnClient, client, mgr, nodeName, log)
		watchPeerings(ctx, factory, mgr, log)
		watchGateways(ctx, factory, mgr, nodeName, log)
		watchFloatingIPs(ctx, factory, mgr, nodeName, log)
		watchServiceVIPs(ctx, factory, mgr, log)
		// Per-VPC traffic metrics (#2): serve the datapath counters, labeled by
		// VPC via the same VPC lister the networks map is built from.
		serveMetrics(ctx, mgr, factory.Sdn().V1alpha1().VPCs(), nodeName, log)
		factory.Start(ctx.Done())
	}

	// Datapath is up and remotes are syncing; expose the CNI to kubelet.
	if err := writeCNIConf(cniConfName, mtu); err != nil {
		return fmt.Errorf("write CNI conf: %w", err)
	}
	log.Info("CNI configuration installed; agent ready")

	<-ctx.Done()
	log.Info("shutting down")
	return nil
}

// watchNodes starts a Node informer that mirrors every other node's pod CIDR
// into the remotes map. It blocks until the cache is synced.
func watchNodes(ctx context.Context, client kubernetes.Interface, mgr *datapath.Manager, selfName string, log *slog.Logger) error {
	factory := informers.NewSharedInformerFactory(client, 0)
	nodeInformer := factory.Core().V1().Nodes().Informer()

	apply := func(obj any) {
		node, ok := obj.(*corev1.Node)
		if !ok || node.Name == selfName || node.Spec.PodCIDR == "" {
			return
		}
		ip := internalIP(node)
		if ip == "" {
			log.Warn("node has no InternalIP", "node", node.Name)
			return
		}
		// Node pod CIDRs are the default network (scope 0). On a dual-stack node
		// there are two (a v4 and a v6); the Geneve endpoint stays the node's v4
		// IP for both (the underlay is v4). Overlay/fabric delivery of a v6 pod IP
		// then resolves the node just like a v4 one.
		for _, cidr := range nodePodCIDRs(node) {
			if err := mgr.SetRemote(0, cidr, net.ParseIP(ip)); err != nil {
				log.Error("set remote", "node", node.Name, "cidr", cidr, "err", err)
				continue
			}
			log.Info("remote set", "node", node.Name, "podCIDR", cidr, "nodeIP", ip)
		}
	}

	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			node, ok := obj.(*corev1.Node)
			if !ok || node.Name == selfName || node.Spec.PodCIDR == "" {
				return
			}
			for _, cidr := range nodePodCIDRs(node) {
				if err := mgr.DelRemote(0, cidr); err != nil {
					log.Error("del remote", "node", node.Name, "cidr", cidr, "err", err)
				}
			}
		},
	})
	if err != nil {
		return fmt.Errorf("add node handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), nodeInformer.HasSynced) {
		return fmt.Errorf("node cache failed to sync")
	}
	return nil
}

// watchVPCs mirrors VPC CIDR -> network id into the networks map. Best-effort:
// the caller starts the informer without blocking on cache sync, so a missing
// sdn API (during bootstrap) doesn't stall the agent.
func watchVPCs(factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	informer := factory.Sdn().V1alpha1().VPCs().Informer()

	apply := func(obj any) {
		vpc, ok := obj.(*sdnv1alpha1.VPC)
		if !ok || vpc.Status.VNI == 0 || len(vpc.Spec.CIDRs) == 0 {
			return
		}
		vni := uint32(vpc.Status.VNI)
		// A VPC's own CIDR resolves to itself within its own scope (scope==net).
		if err := mgr.SetNetwork(vni, vpc.Spec.CIDRs[0], vni); err != nil {
			log.Error("set network", "vpc", vpc.Name, "err", err)
			return
		}
		log.Info("network set", "vpc", vpc.Name, "cidr", vpc.Spec.CIDRs[0], "vni", vpc.Status.VNI)
	}

	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			vpc, ok := obj.(*sdnv1alpha1.VPC)
			if !ok || vpc.Status.VNI == 0 || len(vpc.Spec.CIDRs) == 0 {
				return
			}
			if err := mgr.DelNetwork(uint32(vpc.Status.VNI), vpc.Spec.CIDRs[0]); err != nil {
				log.Error("del network", "vpc", vpc.Name, "err", err)
			}
		},
	})
}

// watchPorts mirrors remote VPC ports (pods on other nodes) into the remotes
// map as /32 routes to their node's Geneve endpoint, and severs a *local* pod's
// datapath when its Port is reaped out from under it (revocation). Best-effort,
// like watchVPCs.
func watchPorts(ctx context.Context, factory sdninformers.SharedInformerFactory, sdn sdnclientset.Interface, core kubernetes.Interface, mgr *datapath.Manager, selfName string, log *slog.Logger) {
	informer := factory.Sdn().V1alpha1().Ports().Informer()

	apply := func(obj any) {
		port, ok := obj.(*sdnv1alpha1.Port)
		if !ok {
			return
		}
		// A terminating local Port is a revocation in flight: sever the live
		// pod (if any), then release the sever finalizer to acknowledge. The
		// informer's initial sync delivers still-terminating Ports, so a
		// revocation that landed while this agent was down replays here.
		if port.DeletionTimestamp != nil {
			if port.Spec.Node == selfName {
				releaseSeveredPort(ctx, sdn, core, port, log)
			}
			return
		}
		// A persistent (VM) Port's locals entry follows spec.node — the
		// staged-locals half of live migration: the target's entry appears
		// only at cutover (programmed here from the veth's alias record),
		// and the source's disappears at the same moment, so same-node
		// delivery flips exactly when cross-node delivery does.
		if port.Labels[sdnv1alpha1.LabelVMName] != "" && port.Spec.IP != "" {
			if net_, ok := vniFromPortName(port.Name); ok {
				if port.Spec.Node == selfName {
					if programmed, err := datapath.EnsureLocalFromVeth(net_, net.ParseIP(port.Spec.IP)); err != nil {
						log.Error("program persistent-port locals at cutover", "port", port.Name, "err", err)
					} else if programmed {
						log.Info("persistent port local delivery enabled (cutover)", "port", port.Name, "ip", port.Spec.IP)
					}
					// The route from when the VM lived elsewhere is stale now.
					if err := mgr.DelRemote(net_, hostCIDR(port.Spec.IP)); err != nil {
						log.Error("del stale remote for local persistent port", "port", port.Name, "err", err)
					}
				} else if err := datapath.DelLocal(net_, net.ParseIP(port.Spec.IP)); err != nil {
					log.Error("del persistent-port locals (moved away)", "port", port.Name, "err", err)
				}
			}
		}
		if port.Spec.Node == selfName || port.Spec.IP == "" || port.Spec.NodeIP == "" {
			return // local ports are reached directly; skip incomplete ones
		}
		net_, ok := vniFromPortName(port.Name)
		if !ok {
			return
		}
		// Remote VPC pods are reached within their VPC's scope, so overlapping
		// CIDRs on different nodes never collide.
		if err := mgr.SetRemote(net_, hostCIDR(port.Spec.IP), net.ParseIP(port.Spec.NodeIP)); err != nil {
			log.Error("set remote port", "port", port.Name, "err", err)
			return
		}
		log.Info("remote port set", "ip", port.Spec.IP, "nodeIP", port.Spec.NodeIP, "vpc", port.Spec.VPCRef.Namespace+"/"+port.Spec.VPCRef.Name)
	}

	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			port := portFromDelete(obj)
			if port == nil || port.Spec.IP == "" {
				return
			}
			net_, ok := vniFromPortName(port.Name)
			if !ok {
				return
			}
			if port.Spec.Node == selfName {
				// Belt for Ports created before the sever finalizer existed;
				// finalized Ports were already severed while terminating.
				severLocalPort(ctx, core, port, log)
				return
			}
			if err := mgr.DelRemote(net_, hostCIDR(port.Spec.IP)); err != nil {
				log.Error("del remote port", "port", port.Name, "err", err)
			}
		},
	})
}

// releaseSeveredPort handles a terminating Port on this node: sever the live
// pod if the Port was reaped out from under it, then remove the sever
// finalizer so the deletion completes. Idempotent — re-delivery is harmless.
func releaseSeveredPort(ctx context.Context, sdn sdnclientset.Interface, core kubernetes.Interface, port *sdnv1alpha1.Port, log *slog.Logger) {
	if !slices.Contains(port.Finalizers, sdnv1alpha1.FinalizerSever) {
		return
	}
	severLocalPort(ctx, core, port, log)
	for range 3 {
		latest, err := sdn.SdnV1alpha1().Ports().Get(ctx, port.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err != nil {
			log.Error("get terminating port", "port", port.Name, "err", err)
			return
		}
		trimmed := slices.DeleteFunc(slices.Clone(latest.Finalizers), func(f string) bool {
			return f == sdnv1alpha1.FinalizerSever
		})
		if len(trimmed) == len(latest.Finalizers) {
			return // already released
		}
		latest.Finalizers = trimmed
		_, err = sdn.SdnV1alpha1().Ports().Update(ctx, latest, metav1.UpdateOptions{})
		if err == nil {
			log.Info("sever acknowledged; finalizer released", "port", port.Name)
			return
		}
		if !apierrors.IsConflict(err) {
			log.Error("release sever finalizer", "port", port.Name, "err", err)
			return
		}
	}
}

// watchPeerings keeps the peers map equal to the set of *live* peerings: pairs
// of mutually-matched VPCPeering halves whose two VPCs both have VNIs. Every
// event triggers a full recompute from the listers, diffed against the pinned
// map itself — deliberately not keyed on the controller's status, so a
// revocation (either half deleted) severs at watch latency even if status is
// stale, and presence of the reciprocal grant remains the authorization.
func watchPeerings(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	peerings := factory.Sdn().V1alpha1().VPCPeerings()
	vpcs := factory.Sdn().V1alpha1().VPCs()

	var mu sync.Mutex
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		all, err := peerings.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list vpcpeerings", "err", err)
			return
		}
		vpc := func(namespace, name string) *sdnv1alpha1.VPC {
			v, err := vpcs.Lister().VPCs(namespace).Get(name)
			if err != nil {
				return nil
			}
			return v
		}
		links := desiredPeerLinks(all, vpc)

		// A live peering programs two datapath facts: the peers-map verdict
		// (may these two nets talk) and the networks delivery entries (each
		// side's CIDR resolves to the other from its own scope).
		desired := map[[2]uint32]bool{}
		var peerNets []datapath.PeerNet
		for _, l := range links {
			desired[[2]uint32{l.a, l.b}] = true
			peerNets = append(peerNets,
				datapath.PeerNet{Scope: l.a, CIDR: l.cidrB, Net: l.b},
				datapath.PeerNet{Scope: l.b, CIDR: l.cidrA, Net: l.a})
		}

		current, err := mgr.Peers()
		if err != nil {
			log.Error("read peers map", "err", err)
			return
		}
		for pair := range desired {
			if !current[pair] {
				if err := mgr.SetPeer(pair[0], pair[1]); err != nil {
					log.Error("set peer", "pair", pair, "err", err)
					continue
				}
				log.Info("peer set", "vni-a", pair[0], "vni-b", pair[1])
			}
		}
		for pair := range current {
			if !desired[pair] {
				if err := mgr.DelPeer(pair[0], pair[1]); err != nil {
					log.Error("del peer", "pair", pair, "err", err)
					continue
				}
				log.Info("peer removed", "vni-a", pair[0], "vni-b", pair[1])
			}
		}
		if err := mgr.SyncPeerNetworks(peerNets); err != nil {
			log.Error("sync peer networks", "err", err)
		}
	}

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = peerings.Informer().AddEventHandler(onAny)
	_, _ = vpcs.Informer().AddEventHandler(onAny)

	// One unconditional resync once the caches are synced: prunes pairs whose
	// peerings were deleted while this agent was down (no event would fire).
	go func() {
		if cache.WaitForCacheSync(ctx.Done(), peerings.Informer().HasSynced, vpcs.Informer().HasSynced) {
			resync()
		}
	}()
}

// watchGateways keeps the gateways map equal to the set of gateway Ports
// (spec.gateway), from this node's point of view: a local gateway is delivered
// by redirect, a remote one by encapsulation to its node. Like watchPeerings,
// every relevant event triggers a recompute diffed against the pinned map, so
// a restarted agent prunes gateways that vanished while it was down.
func watchGateways(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, selfName string, log *slog.Logger) {
	ports := factory.Sdn().V1alpha1().Ports()

	var mu sync.Mutex
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		all, err := ports.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list ports", "err", err)
			return
		}
		desired := desiredGateways(all, selfName)

		current, err := mgr.Gateways()
		if err != nil {
			log.Error("read gateways map", "err", err)
			return
		}
		for vni, gw := range desired {
			// Put unconditionally: an existing entry may be stale (gateway
			// moved nodes) and the write is idempotent.
			if err := mgr.SetGateway(vni, gw.ip, gw.nodeIP); err != nil {
				log.Error("set gateway", "vni", vni, "err", err)
				continue
			}
			if !current[vni] {
				log.Info("gateway set", "vni", vni, "ip", gw.ip, "nodeIP", gw.nodeIP)
			}
		}
		for vni := range current {
			if _, ok := desired[vni]; !ok {
				if err := mgr.DelGateway(vni); err != nil {
					log.Error("del gateway", "vni", vni, "err", err)
					continue
				}
				log.Info("gateway removed", "vni", vni)
			}
		}
	}

	isGateway := func(obj any) bool {
		port := portFromDelete(obj)
		return port != nil && port.Spec.Gateway
	}
	_, _ = ports.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: isGateway,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    func(any) { resync() },
			UpdateFunc: func(_, newObj any) { resync() },
			DeleteFunc: func(any) { resync() },
		},
	})

	go func() {
		if cache.WaitForCacheSync(ctx.Done(), ports.Informer().HasSynced) {
			resync()
		}
	}()
}

type gatewayView struct {
	ip     net.IP // the gateway's VPC-leg (.1) address
	nodeIP net.IP // nil when the gateway runs on this node
}

// desiredGateways computes, for this node, the gateway entry per VNI from the
// gateway Ports (the VNI comes from the Port name, v<vni>.<ip-dashed> — the
// documented naming contract).
func desiredGateways(ports []*sdnv1alpha1.Port, selfName string) map[uint32]gatewayView {
	desired := map[uint32]gatewayView{}
	for _, p := range ports {
		if !p.Spec.Gateway || p.Spec.IP == "" {
			continue
		}
		vni, ok := vniFromPortName(p.Name)
		if !ok {
			continue
		}
		ip := net.ParseIP(p.Spec.IP)
		if ip == nil {
			continue
		}
		gw := gatewayView{ip: ip}
		if p.Spec.Node != selfName {
			gw.nodeIP = net.ParseIP(p.Spec.NodeIP)
			if gw.nodeIP == nil {
				continue
			}
		}
		desired[vni] = gw
	}
	return desired
}

// watchFloatingIPs programs this node's floating IPs: for each FloatingIP whose
// target tenant IP is realized by a Port on THIS node, it writes the
// publicIP -> {net, VPC IP} floating-map entry and answers ARP for the public
// address on the uplink. Like watchGateways it recomputes and diffs against the
// pinned map on every relevant event, so a restarted agent prunes floating IPs
// whose FloatingIP or target Port vanished while it was down. Advertising only
// from the target's node keeps ingress local (DVR).
func watchFloatingIPs(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, selfName string, log *slog.Logger) {
	fips := factory.Sdn().V1alpha1().FloatingIPs()
	ports := factory.Sdn().V1alpha1().Ports()

	var mu sync.Mutex
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		allFips, err := fips.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list floatingips", "err", err)
			return
		}
		allPorts, err := ports.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list ports", "err", err)
			return
		}
		desired := desiredFloating(allFips, allPorts, selfName)

		current, err := mgr.Floatings()
		if err != nil {
			log.Error("read floating map", "err", err)
			return
		}
		for pub, v := range desired {
			// Put unconditionally: an existing entry may be stale (target moved).
			// Programming the map both delivers and advertises (from_uplink
			// answers ARP for it); there is no separate host-side advertise step.
			if err := mgr.SetFloating(pub, v.vpcIP, v.vni); err != nil {
				log.Error("set floating", "public", pub, "err", err)
				continue
			}
			if !current[pub] {
				// Newly local here (created, or moved from another node):
				// nudge external L2 caches at the old location (GARP /
				// unsolicited NA). Best-effort — new queries are answered by
				// the datapath regardless.
				if err := mgr.AnnounceAddress(net.ParseIP(pub)); err != nil {
					log.Warn("announce floating address", "public", pub, "err", err)
				}
				log.Info("floating set", "public", pub, "target", v.vpcIP, "vni", v.vni)
			}
		}
		for pub := range current {
			if _, ok := desired[pub]; !ok {
				if err := mgr.DelFloating(pub); err != nil {
					log.Error("del floating", "public", pub, "err", err)
					continue
				}
				log.Info("floating removed", "public", pub)
			}
		}
	}

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = fips.Informer().AddEventHandler(onAny)
	// Ports too: a target IP gaining or losing a live Port on this node — or a
	// Port moving nodes — changes what this node advertises.
	_, _ = ports.Informer().AddEventHandler(onAny)

	go func() {
		if cache.WaitForCacheSync(ctx.Done(), fips.Informer().HasSynced, ports.Informer().HasSynced) {
			resync()
		}
	}()
}

// floatingView is what this node must program for one floating IP: the target
// tenant IP and its network id (VNI).
type floatingView struct {
	vpcIP string
	vni   uint32
}

// desiredFloating computes the floating IPs this node must program: those whose
// target tenant IP is realized by a live Port on THIS node (the node that
// advertises and delivers). The VNI comes from the target Port's name. A
// FloatingIP's local vpcRef resolves in its own namespace, which is the target
// Port's VPCRef namespace.
func desiredFloating(fips []*sdnv1alpha1.FloatingIP, ports []*sdnv1alpha1.Port, selfName string) map[string]floatingView {
	type portKey struct{ ns, name, ip string }
	local := map[portKey]uint32{}
	for _, p := range ports {
		if p.Spec.Node != selfName || p.Spec.IP == "" {
			continue
		}
		vni, ok := vniFromPortName(p.Name)
		if !ok {
			continue
		}
		local[portKey{p.Spec.VPCRef.Namespace, p.Spec.VPCRef.Name, p.Spec.IP}] = vni
	}

	out := map[string]floatingView{}
	for _, f := range fips {
		if f.Status.Address == "" {
			continue
		}
		vni, ok := local[portKey{f.Namespace, f.Spec.VPCRef.Name, f.Spec.Target}]
		if !ok {
			continue // target not a live Port on this node
		}
		out[f.Status.Address] = floatingView{vpcIP: f.Spec.Target, vni: vni}
	}
	return out
}

// hostCIDR appends the host-route prefix length for a bare IP: /32 for IPv4,
// /128 for IPv6. A remote VPC pod is a single host in the remotes trie, so the
// prefix must match the address width (a v6 IP with /32 would match a whole
// block, not the host).
func hostCIDR(ip string) string {
	if p := net.ParseIP(ip); p != nil && p.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
}

// splitCIDRs parses a comma-separated CIDR list, dropping blanks.
func splitCIDRs(s string) []string {
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// vniFromPortName parses the VNI out of a Port name (v<vni>.<ip-dashed>).
func vniFromPortName(name string) (uint32, bool) {
	if !strings.HasPrefix(name, "v") {
		return 0, false
	}
	dot := strings.IndexByte(name, '.')
	if dot <= 1 {
		return 0, false
	}
	vni, err := strconv.ParseUint(name[1:dot], 10, 32)
	if err != nil || vni == 0 {
		return 0, false
	}
	return uint32(vni), true
}

// peerLink is a live peering between two VPCs, normalized so a < b, carrying
// each side's VNI and first CIDR (for the networks delivery entries).
type peerLink struct {
	a, b         uint32
	cidrA, cidrB string
}

// desiredPeerLinks computes the live peerings: one per pair of mutually-matched
// halves whose local and peer VPCs both have assigned VNIs and whose CIDRs are
// disjoint — peered traffic is routed natively, so overlapping address spaces
// cannot be connected (the one restriction overlap carries).
func desiredPeerLinks(peerings []*sdnv1alpha1.VPCPeering, vpc func(namespace, name string) *sdnv1alpha1.VPC) []peerLink {
	seen := map[[2]uint32]bool{}
	var out []peerLink
	for _, p := range peerings {
		va := vpc(p.Namespace, p.Spec.VPCRef.Name)
		vb := vpc(p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name)
		if va == nil || vb == nil || va.Status.VNI == 0 || vb.Status.VNI == 0 {
			continue
		}
		if len(va.Spec.CIDRs) == 0 || len(vb.Spec.CIDRs) == 0 {
			continue
		}
		if sdnv1alpha1.CIDRsOverlap(va.Spec.CIDRs, vb.Spec.CIDRs) {
			continue
		}
		matched := false
		for _, q := range peerings {
			if p != q && p.Matches(q) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		a, b := uint32(va.Status.VNI), uint32(vb.Status.VNI)
		ca, cb := va.Spec.CIDRs[0], vb.Spec.CIDRs[0]
		if a > b {
			a, b = b, a
			ca, cb = cb, ca
		}
		if seen[[2]uint32{a, b}] {
			continue
		}
		seen[[2]uint32{a, b}] = true
		out = append(out, peerLink{a: a, b: b, cidrA: ca, cidrB: cb})
	}
	return out
}

// portFromDelete extracts a Port from a delete event, unwrapping the
// tombstone the informer may deliver if a delete was missed.
func portFromDelete(obj any) *sdnv1alpha1.Port {
	if port, ok := obj.(*sdnv1alpha1.Port); ok {
		return port
	}
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if port, ok := tombstone.Obj.(*sdnv1alpha1.Port); ok {
			return port
		}
	}
	return nil
}

// severLocalPort cuts a still-running local pod off its VPC when its Port is
// reaped (binding revoked), as opposed to ordinary pod deletion where CNI DEL
// has already cleaned up. It only severs if the owning pod still exists, is not
// being deleted, and is the same pod (UID) that claimed the Port — so a stale
// delete for a name-reused pod can't cut off an unrelated one.
func severLocalPort(ctx context.Context, core kubernetes.Interface, port *sdnv1alpha1.Port, log *slog.Logger) {
	if port.Spec.PodNamespace == "" || port.Spec.PodName == "" {
		return
	}
	net_, ok := vniFromPortName(port.Name)
	if !ok {
		return
	}
	pod, err := core.CoreV1().Pods(port.Spec.PodNamespace).Get(ctx, port.Spec.PodName, metav1.GetOptions{})
	if err != nil {
		return // gone or unreachable: ordinary deletion path handles cleanup
	}
	if pod.DeletionTimestamp != nil {
		return // being deleted normally
	}
	if uid := port.Labels[sdnv1alpha1.LabelPodUID]; uid != "" && string(pod.UID) != uid {
		return // a different pod reused the name; not the one this Port belonged to
	}
	severed, err := datapath.SeverLocal(net_, net.ParseIP(port.Spec.IP), port.Spec.FabricIP)
	if err != nil {
		log.Error("sever local port", "port", port.Name, "err", err)
		return
	}
	if severed {
		log.Info("severed local port (VPC access revoked)",
			"ip", port.Spec.IP, "pod", port.Spec.PodNamespace+"/"+port.Spec.PodName)
	}
}

func writeCNIConf(name string, mtu int) error {
	if err := os.MkdirAll(cniConfDir, 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf(cniConfBody, mtu)
	tmp := filepath.Join(cniConfDir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(cniConfDir, name))
}

func internalIP(node *corev1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}

// firstV4CIDR returns the first IPv4 CIDR in a comma-separated list.
func firstV4CIDR(cidrs string) string {
	for _, c := range splitCIDRs(cidrs) {
		if ip, _, err := net.ParseCIDR(c); err == nil && ip.To4() != nil {
			return c
		}
	}
	return ""
}

// internalIPv4 returns the node's v4 InternalIP, if it has one.
func internalIPv4(node *corev1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			if ip := net.ParseIP(a.Address); ip != nil && ip.To4() != nil {
				return a.Address
			}
		}
	}
	return ""
}

// parseDNSIPs splits an explicit --cluster-dns list into per-family addresses.
func parseDNSIPs(s string) (v4, v6 net.IP) {
	for _, part := range strings.Split(s, ",") {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = ip
		} else {
			v6 = ip
		}
	}
	return v4, v6
}

// discoverClusterDNS reads the kube-system/kube-dns Service's ClusterIPs (the
// conventional name CoreDNS deployments keep for compatibility).
func discoverClusterDNS(ctx context.Context, client kubernetes.Interface) (v4, v6 net.IP) {
	svc, err := client.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
	if err != nil {
		return nil, nil
	}
	ips := svc.Spec.ClusterIPs
	if len(ips) == 0 && svc.Spec.ClusterIP != "" {
		ips = []string{svc.Spec.ClusterIP}
	}
	return parseDNSIPs(strings.Join(ips, ","))
}

// internalIPv6 returns the node's v6 InternalIP, if it has one (dual-stack).
func internalIPv6(node *corev1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			if ip := net.ParseIP(a.Address); ip != nil && ip.To4() == nil {
				return a.Address
			}
		}
	}
	return ""
}

// nodePodCIDRs returns a node's pod CIDRs across all families: Spec.PodCIDRs on a
// dual-stack node (a v4 and a v6), falling back to the single Spec.PodCIDR.
func nodePodCIDRs(node *corev1.Node) []string {
	if len(node.Spec.PodCIDRs) > 0 {
		return node.Spec.PodCIDRs
	}
	if node.Spec.PodCIDR != "" {
		return []string{node.Spec.PodCIDR}
	}
	return nil
}

// watchServiceVIPs projects every ServiceVIP into the svc_vips datapath map
// (docs/services-in-vpc.md increment 2). Full-state resync on any ServiceVIP
// or VPC change — the objects are few and the map diff is cheap.
func watchServiceVIPs(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	svips := factory.Sdn().V1alpha1().ServiceVIPs()
	vpcs := factory.Sdn().V1alpha1().VPCs()

	var mu sync.Mutex
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		all, err := svips.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list servicevips", "err", err)
			return
		}
		var entries []datapath.SvcEntry
		for _, sv := range all {
			vpc, err := vpcs.Lister().VPCs(sv.Spec.VPCRef.Namespace).Get(sv.Spec.VPCRef.Name)
			if err != nil || vpc.Status.VNI == 0 {
				continue
			}
			vip := net.ParseIP(sv.Spec.IP)
			if vip == nil {
				continue
			}
			for _, p := range sv.Spec.Ports {
				var proto uint8
				switch p.Protocol {
				case "TCP":
					proto = unix.IPPROTO_TCP
				case "UDP":
					proto = unix.IPPROTO_UDP
				default:
					continue
				}
				var backends []datapath.SvcBackend
				for _, b := range sv.Status.Backends {
					for _, bp := range b.Ports {
						if bp.Protocol != p.Protocol || bp.Port != p.Port {
							continue
						}
						if ip := net.ParseIP(b.IP); ip != nil {
							backends = append(backends, datapath.SvcBackend{IP: ip, Port: uint16(bp.TargetPort)})
						}
					}
				}
				if len(backends) > datapath.SvcMaxBackends {
					log.Warn("service VIP backends truncated", "vip", sv.Name, "have", len(backends), "max", datapath.SvcMaxBackends)
				}
				entries = append(entries, datapath.SvcEntry{
					Net:      uint32(vpc.Status.VNI),
					VIP:      vip,
					Proto:    proto,
					Port:     uint16(p.Port),
					Backends: backends,
					Affinity: sv.Spec.SessionAffinity == "ClientIP",
				})
			}
		}
		if err := mgr.SyncServiceVIPs(entries); err != nil {
			log.Error("sync service VIPs", "err", err)
			return
		}
	}

	_, _ = svips.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
	_, _ = vpcs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
	})
}

// serveMetrics exposes the per-VPC datapath traffic counters (#2) as Prometheus
// text on :9411/metrics, labeled by the owning VPC. Hand-rolled exposition (no
// client dependency), read fresh on each scrape from the PERCPU map and the VPC
// lister (net id -> VPC namespace/name).
func serveMetrics(ctx context.Context, mgr *datapath.Manager, vpcs sdnv1alpha1informers.VPCInformer, nodeName string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		counters, err := mgr.VPCCounters()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// net id -> VPC identity, from the lister.
		names := map[uint32][2]string{}
		if all, err := vpcs.Lister().List(labels.Everything()); err == nil {
			for _, v := range all {
				if v.Status.VNI != 0 {
					names[uint32(v.Status.VNI)] = [2]string{v.Namespace, v.Name}
				}
			}
		}

		var b strings.Builder
		for _, m := range []struct {
			name, help string
			pick       func(datapath.VPCCounter) uint64
		}{
			{"cozyplane_vpc_tx_bytes_total", "VPC pod egress bytes", func(c datapath.VPCCounter) uint64 { return c.TxBytes }},
			{"cozyplane_vpc_tx_packets_total", "VPC pod egress packets", func(c datapath.VPCCounter) uint64 { return c.TxPackets }},
			{"cozyplane_vpc_rx_bytes_total", "VPC pod east-west ingress bytes", func(c datapath.VPCCounter) uint64 { return c.RxBytes }},
			{"cozyplane_vpc_rx_packets_total", "VPC pod east-west ingress packets", func(c datapath.VPCCounter) uint64 { return c.RxPackets }},
		} {
			fmt.Fprintf(&b, "# HELP %s %s (this node).\n# TYPE %s counter\n", m.name, m.help, m.name)
			for net, c := range counters {
				id := names[net]
				fmt.Fprintf(&b, "%s{vni=\"%d\",vpc_namespace=\"%s\",vpc=\"%s\",node=\"%s\"} %d\n",
					m.name, net, id[0], id[1], nodeName, m.pick(c))
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})

	srv := &http.Server{Addr: ":9411", Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		log.Info("serving per-VPC metrics", "addr", ":9411/metrics")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warn("metrics server", "err", err)
		}
	}()
}
