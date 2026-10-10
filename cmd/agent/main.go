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
	"github.com/lllamnyp/cozyplane/internal/httpserver"
	"github.com/lllamnyp/cozyplane/pkg/netid"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/floatingvalidation"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	sdnv1alpha1informers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions/sdn/v1alpha1"
	sdnv1alpha1listers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/listers/sdn/v1alpha1"
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
	// migrateFwdGrace is how long a former source node keeps re-encapsulating a
	// migrated VM's traffic to its new node after cutover, covering the window in
	// which remote agents still route to the old node. Comfortably longer than
	// informer propagation across the fleet.
	migrateFwdGrace = 15 * time.Second
)

func main() {
	var (
		nodeName            = os.Getenv("NODE_NAME")
		mtu                 int
		vni                 uint
		cniConfName         string
		writeCNI            bool
		genevePort          uint
		clusterCIDR         string
		internalCIDRs       string
		masqMode            string
		vpcDNS              bool
		clusterDNSIPs       string
		floatingNextHopIPv4 string
		metricsAddr         string
		metricsSecure       bool
		flowsEnabled        bool
	)
	flag.IntVar(&mtu, "mtu", 1450, "pod MTU (underlay MTU minus Geneve overhead)")
	flag.UintVar(&vni, "vni", uint(datapath.DefaultVNI), "VNI for the default network")
	flag.StringVar(&cniConfName, "cni-conf-name", defaultCNIConfFile,
		"filename for the CNI conflist in /etc/cni/net.d (lower sorts first, winning over other CNIs)")
	flag.BoolVar(&writeCNI, "write-cni-conf", true, "install the CNI conflist; disable when the platform owns a chained CNI")
	flag.UintVar(&genevePort, "geneve-port", datapath.GenevePort,
		"Geneve UDP destination port (use a non-default port to coexist with another overlay on 6081)")
	flag.StringVar(&clusterCIDR, "cluster-cidr", "",
		"cluster pod supernet; when set, pod traffic leaving it is masqueraded to the node address (pod egress to the outside)")
	flag.StringVar(&masqMode, "masquerade", "bpf",
		"cluster-egress masquerade implementation: bpf (eBPF SNAT at the uplink, no netfilter), iptables (kernel MASQUERADE rule), off (the environment masquerades elsewhere)")
	flag.StringVar(&internalCIDRs, "internal-cidrs", "",
		"comma-separated cluster-internal CIDRs (pod, service, node networks) a floating pod's public-IP egress must not reach")
	flag.StringVar(&floatingNextHopIPv4, "floating-next-hop-ipv4", "",
		"router IPv4 address for connected external pools; empty uses the first host, explicit FIB gateways take priority")
	flag.BoolVar(&vpcDNS, "vpc-dns", true,
		"steer VPC pods' cluster-DNS queries to the node-local split-horizon resolver (docs/services-in-vpc.md)")
	flag.StringVar(&clusterDNSIPs, "cluster-dns", "",
		"comma-separated cluster DNS ClusterIP(s) to steer; empty auto-discovers from the kube-system/kube-dns Service")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9411",
		"listen address for the Prometheus /metrics endpoint; the agent is hostNetwork, so bind a specific node address to keep it off public interfaces; empty disables it")
	flag.BoolVar(&metricsSecure, "metrics-secure", true,
		"gate /metrics behind delegated authn/authz (TokenReview + SubjectAccessReview against the kube-apiserver); a scraper then needs a ServiceAccount token authorized for get on nonResourceURL /metrics")
	flag.BoolVar(&flowsEnabled, "flows", false,
		"arm flow observability: per-flow events with verdicts and reasons, served on :9411/flows (docs/observability.md; ~14MiB extra map memlock)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	// datapath warns through the default logger; this also routes the stdlib
	// log package (and any dependency using it) through the same handler.
	slog.SetDefault(log)

	if nodeName == "" {
		log.Error("NODE_NAME must be set (downward API)")
		os.Exit(1)
	}

	if err := run(nodeName, mtu, uint32(vni), cniConfName, writeCNI, uint16(genevePort), clusterCIDR, internalCIDRs, masqMode, vpcDNS, clusterDNSIPs, floatingNextHopIPv4, metricsAddr, metricsSecure, flowsEnabled, log); err != nil {
		log.Error("agent failed", "err", err)
		os.Exit(1)
	}
}

func run(nodeName string, mtu int, vni uint32, cniConfName string, writeCNI bool, genevePort uint16, clusterCIDR, internalCIDRs, masqMode string, vpcDNS bool, clusterDNSIPs, floatingNextHopIPv4, metricsAddr string, metricsSecure, flowsEnabled bool, log *slog.Logger) error {
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
	if err := mgr.SetFloatingNextHopIPv4(floatingNextHopIPv4); err != nil {
		return err
	}
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
	// (it bypasses the gateway that would otherwise deny them). Called even
	// with an empty list: SetInternal diffs against the pinned map, and a CIDR
	// dropped from the flag must be pruned, not left behind.
	if err := mgr.SetInternal(splitCIDRs(internalCIDRs)); err != nil {
		return fmt.Errorf("program internal CIDRs: %w", err)
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
	// Cilium programs endpoint veths asynchronously after CNI ADD. Periodically
	// restore the required order: Cilium connection tracking first, Cozyplane
	// overlay redirection second. Existing correctly ordered links are no-ops.
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := mgr.ExpireMigrateForwards(time.Now(), migrateFwdGrace); err != nil {
					log.Warn("expire migration source-forwards", "err", err)
				}
				moved, err := mgr.ReconcilePodTCXOrder()
				if err != nil {
					log.Warn("reconcile pod tcx order", "err", err)
				} else if moved > 0 {
					log.Info("reconciled pod tcx order", "moved", moved)
				}
			}
		}
	}()

	// A peer CNI sharing a veth programs its endpoint asynchronously, AFTER CNI
	// ADD has returned, so the order we set at attach time is not the order that
	// survives. An anchor decides where we land; only this loop keeps us there.
	// Correctly ordered hooks are a query and no writes, so the steady state is
	// cheap and silent.
	//
	// A count that stays non-zero tick after tick is worth reading as a signal,
	// not noise: it means the peer keeps re-taking the position, and each repair
	// opens a brief unclassified window.
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				moved, err := mgr.ReconcilePodTCXOrder()
				if err != nil {
					log.Warn("reconcile pod tcx order", "err", err)
				}
				if moved > 0 {
					log.Info("reconciled pod tcx order", "moved", moved)
				}
			}
		}
	}()

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
	// The FLAT pool (docs/api-groups.md): every pod address is drawn from the
	// cluster-wide supernet, not from this node's slice of it. --cluster-cidr
	// already carries it (it is the masquerade supernet), so there is nothing
	// new to configure. Unset, the CNI falls back to the node's slice, which is
	// the pre-flat behaviour.
	state := &datapath.AgentState{
		NodeName:        nodeName,
		NodeIP:          internalIP(self),
		PodCIDR:         podCIDR,
		PodCIDRs:        podCIDRs,
		ClusterPodCIDRs: splitCIDRs(clusterCIDR),
		MTU:             mtu,
		Namespace:       os.Getenv("AGENT_NAMESPACE"), // gates gateway-attach to the system namespace
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
		// SNAT to the default-route source, not the InternalIP: the masqueraded
		// packet egresses that link and must carry an address valid for it (they
		// differ on a multi-NIC node, and a spoof-guarding underlay drops a
		// mismatch). On a single-NIC node this equals the InternalIP.
		masqIP, err := datapath.DefaultRouteSrcIP()
		if err != nil {
			return fmt.Errorf("determine masquerade source address: %w", err)
		}
		if err := mgr.SetMasqIP(masqIP); err != nil {
			return fmt.Errorf("program masquerade IP: %w", err)
		}
		if err := mgr.SyncMasqSources(splitCIDRs(clusterCIDR)); err != nil {
			return fmt.Errorf("program masquerade sources: %w", err)
		}
		log.Info("bpf cluster-egress masquerade enabled", "sources", clusterCIDR, "masqIP", masqIP.String(), "nodeIP", state.NodeIP, "nodeIPv6", nodeV6)
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

	// Advertise the address host-originated traffic sources from, so peers can
	// encapsulate their pods' replies to this node over the overlay (node_remotes)
	// instead of emitting a pod-sourced frame the underlay may drop.
	advertiseNodeAddrs(ctx, client, nodeName, log)

	// The local layer (docs/api-groups.md): FabricIP claims are the flat pool's
	// delivery table — one remotes entry per pod, keyed by address. This is the
	// default network's forwarding state, so it is FATAL, like watchNodes: a
	// node that cannot learn where pods live must not serve.
	lc, err := localclientset.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("local sdn client: %w", err)
	}
	if err := healLocalFabricIPs(ctx, client, lc, nodeName, stats.FabricIPs, log); err != nil {
		log.Warn("local FabricIP repair incomplete", "err", err)
	}
	localFactory := localinformers.NewSharedInformerFactory(lc, 0)
	nodeIPs := newNodeIPIndex()
	// Who is Ready — the node set the VPC NAT port shards are derived from
	// (docs/north-south.md § increment 2). Fed by the same Node informer below.
	nodePools := newNodePoolIndex()

	// A node's tunnel endpoint may arrive after the FabricIPs that reference it
	// (informer ordering is not ours to choose), so a node event re-drives the
	// fabric handlers rather than leaving those pods unreachable.
	fabricRoutes := &fabricRemoteReconciler{
		store:  localFactory.Local().V1alpha1().FabricIPs().Informer().GetStore(),
		writer: mgr, nodeIPOf: nodeIPs.get, self: nodeName, log: log,
	}
	fabricResync := fabricRoutes.resync

	if err := watchNodes(ctx, client, mgr, nodeName, nodeIPs, nodePools, fabricResync, log); err != nil {
		return err
	}
	if err := watchFabricIPs(ctx, localFactory, fabricRoutes, log); err != nil {
		return err
	}
	fabricResync() // nodes are known now; catch FabricIPs seen before their node

	// A claim is derived state, so heal the ones CNI ADD is no longer around to
	// have written: a running pod without one is reachable from its own node and
	// nowhere else (cmd/agent/fabricip_heal.go). The claim lister is already
	// cached by the watch above; the pods are one node-scoped List per pass.
	go healFabricIPs(ctx, client, lc,
		localFactory.Local().V1alpha1().FabricIPs().Lister(),
		nodeName, fabricHealInterval, log)

	// Default-net NetworkPolicy (docs/network-policy.md): compile upstream
	// NetworkPolicies into the pinned NP maps. Fatal on failure like
	// watchNodes — policy must be fed or the node must not serve.
	if err := watchNetworkPolicies(ctx, client, mgr, log); err != nil {
		return err
	}

	// LoadBalancer-ingress uplinks are driven by core Services, not by
	// sdn.cozystack.io. They live outside the gate below so they keep being
	// programmed while the aggregated group is absent.
	watchServiceUplinks(ctx, client, mgr, log)

	// VPC watching is best-effort: the default network must work even before the
	// sdn.cozystack.io API exists, so we don't block readiness on it. One shared
	// factory backs all sdn informers; it is started only after every handler is
	// registered.
	if sdnClient, err := sdnclientset.NewForConfig(cfg); err != nil {
		log.Warn("sdn client init failed; VPC networks won't be programmed", "err", err)
		if flowsEnabled {
			log.Warn("flow observability needs the sdn API for enrichment and the :9411 server; disarming")
		}
		// Clear a pinned leftover either way: params survives agent restarts.
		if err := mgr.SetFlowEnabled(false); err != nil {
			log.Warn("disarm flow observability", "err", err)
		}
	} else {
		factory := sdninformers.NewSharedInformerFactory(sdnClient, 0)
		// Flow observability (docs/observability.md): arm the datapath, drain
		// the ring, serve /flows beside /metrics. The listers reuse informers
		// the watches above already registered — zero new watches. Off (the
		// default), the pinned toggle is explicitly cleared: params survives
		// agent restarts, and a leftover 1 would fill the ring for nobody.
		var flows *flowPipeline
		if flowsEnabled {
			if err := mgr.SetFlowEnabled(true); err != nil {
				log.Error("arm flow observability", "err", err)
			} else {
				flows = newFlowPipeline(mgr,
					factory.Sdn().V1alpha1().VPCs().Lister(),
					factory.Sdn().V1alpha1().Ports().Lister(),
					localFactory.Local().V1alpha1().FabricIPs().Lister(),
					nodeName, log)
				go flows.run(ctx)
				// Raw flow records are served on the node loopback only —
				// unreachable from any pod's netns; the operator reads them by
				// exec-ing into the agent (cozyplane-flowctl). The aggregate
				// cozyplane_flows_total still rides :9411/metrics below.
				flows.serveLoopback(ctx)
			}
		} else if err := mgr.SetFlowEnabled(false); err != nil {
			log.Warn("disarm flow observability", "err", err)
		}

		serveMetrics(ctx, mgr, factory.Sdn().V1alpha1().VPCs(), cfg, nodeName, metricsAddr, metricsSecure, flows, log)
		register := func(context.Context) error {
			resyncVPCs := watchVPCs(ctx, factory, mgr, log)
			watchVPCGateways(ctx, factory, mgr, nodePools, nodeIPs, nodeName, state.NodeIP, log)
			if err := watchPorts(ctx, factory, localFactory, sdnClient, client, mgr, nodeName, state.NodeIP, log); err != nil {
				return fmt.Errorf("watch Ports: %w", err)
			}
			watchBindingGrants(ctx, factory, localFactory, client, nodeName, log)
			watchPeerings(ctx, factory, mgr, log, resyncVPCs)
			watchGateways(ctx, factory, mgr, nodeName, log)
			watchRoutes(ctx, factory, mgr, nodeName, log)
			watchFloatingIPs(ctx, factory, mgr, log)
			watchServiceUplinks(ctx, client, mgr, log)
			watchServiceVIPs(ctx, factory, mgr, log)
			watchSecurityGroups(ctx, factory, mgr, log)
			if err := watchHostFirewalls(ctx, factory, client, mgr, nodeName, log); err != nil {
				log.Error("watch hostfirewalls", "err", err)
			}
			watchBoundaries(ctx, factory, sdnClient, mgr, nodeName, log)
			factory.Start(ctx.Done())
			go recoverLegacySandboxes(ctx, client, lc, sdnClient, nodeName, fabricHealInterval, log)
			return nil
		}
		if err := gateSDNInformers(ctx, cfg, register, log); err != nil {
			log.Warn("sdn discovery initialization failed", "err", err)
			if err := register(ctx); err != nil {
				return err
			}
		}
	}

	// Datapath is up and remotes are syncing; expose the CNI to kubelet — unless
	// another CNI already owns the directory, in which case say which one. A
	// silent abstention here would read exactly like a bug.
	winner, err := configureCNIConf(cniConfDir, cniConfName, mtu, writeCNI)
	if err != nil {
		return fmt.Errorf("write CNI conf: %w", err)
	}
	if !writeCNI {
		log.Info("CNI configuration managed by platform; agent ready")
	} else if winner != "" {
		log.Info("CNI configuration left to another owner; agent ready",
			"owner", winner, "ours", cniConfName)
	} else {
		log.Info("CNI configuration installed; agent ready")
	}

	<-ctx.Done()
	log.Info("shutting down")
	return nil
}

// nodeAddrsAnnotation carries the addresses host-originated traffic on a node
// sources from, beyond the InternalIP already in the node status — comma
// separated. Peers map each to the node's Geneve endpoint (node_remotes) so a
// pod's reply to that address is encapsulated instead of leaving pod-sourced.
const nodeAddrsAnnotation = "cozyplane.io/node-addresses"

const startupBestEffortTimeout = 5 * time.Second

// advertiseNodeAddrs publishes this node's default-route source address in the
// node annotation, so peers can encapsulate their pods' replies to this node.
// The InternalIP is already discoverable from the node status, so only the
// default-route source (which differs from it on a multi-NIC node) is published.
// Best-effort: on failure peers fall back to the InternalIP alone.
func advertiseNodeAddrs(ctx context.Context, client kubernetes.Interface, nodeName string, log *slog.Logger) {
	src, err := datapath.DefaultRouteSrcIP()
	if err != nil {
		log.Warn("determine default-route source; pod->node overlay may be incomplete on multi-NIC nodes", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, startupBestEffortTimeout)
	defer cancel()
	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, nodeAddrsAnnotation, src.String()))
	if _, err := client.CoreV1().Nodes().Patch(ctx, nodeName, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		log.Warn("advertise node address", "err", err)
		return
	}
	log.Info("advertised node address", "addr", src.String())
}

// nodeAddresses returns the set of a node's own addresses that node_remotes
// maps to its Geneve endpoint — the same set the policy exemptions use
// (npNodeAddresses): every InternalIP/ExternalIP, BOTH families, plus the
// annotation. v6 matters: without a v6 entry a pod's dial of a node's v6
// address takes the kernel route to the uplink, where the cluster-egress
// masquerade rewrites it to a NODE source — invisible to a spoof-guarding
// underlay, but it laundered the pod identity straight through the host
// firewall's node exemption (docs/host-firewall.md; caught by its e2e). On
// the overlay the true source survives and the destination node gates it.
func nodeAddresses(node *corev1.Node) []net.IP { return npNodeAddresses(node) }

// watchNodes starts a Node informer that indexes every other node's tunnel
// endpoint and mirrors their addresses into node_remotes. It blocks until the
// cache is synced. (Pod delivery is keyed per address by watchFabricIPs; nothing
// here reads `spec.podCIDR` any more — see docs/api-groups.md.)
func watchNodes(ctx context.Context, client kubernetes.Interface, mgr *datapath.Manager, selfName string,
	nodeIPs *nodeIPIndex, nodePools *nodePoolIndex, fabricResync func(), log *slog.Logger) error {
	factory := informers.NewSharedInformerFactory(client, 0)
	nodeInformer := factory.Core().V1().Nodes().Informer()

	// Node readiness, feeding the NAT shard partition. Includes THIS node: every
	// agent must derive the same partition, so the set cannot exclude self.
	poolApply := func(obj any) {
		if node, ok := obj.(*corev1.Node); ok {
			nodePools.set(node)
		}
	}
	if _, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			poolApply(obj)
			if node, ok := obj.(*corev1.Node); ok {
				if ip := net.ParseIP(internalIP(node)); ip.To4() != nil {
					if err := mgr.SetOverlayNode(ip); err != nil {
						log.Error("authorize overlay node", "node", node.Name, "err", err)
					}
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			poolApply(newObj)
			oldNode, oldOK := oldObj.(*corev1.Node)
			newNode, newOK := newObj.(*corev1.Node)
			if !oldOK || !newOK {
				return
			}
			if internalIP(oldNode) != internalIP(newNode) {
				if err := mgr.DelOverlayNode(net.ParseIP(internalIP(oldNode))); err != nil {
					log.Error("revoke old overlay node", "node", oldNode.Name, "err", err)
					return
				}
			}
			if ip := net.ParseIP(internalIP(newNode)); ip.To4() != nil {
				if err := mgr.SetOverlayNode(ip); err != nil {
					log.Error("authorize overlay node", "node", newNode.Name, "err", err)
				}
			}
		},
		DeleteFunc: func(obj any) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			if node, ok := obj.(*corev1.Node); ok {
				nodePools.del(node.Name)
				if err := mgr.DelOverlayNode(net.ParseIP(internalIP(node))); err != nil {
					log.Error("revoke overlay node", "node", node.Name, "err", err)
				}
			}
		},
	}); err != nil {
		return fmt.Errorf("add node pool handler: %w", err)
	}

	apply := func(obj any) {
		// No PodCIDR condition here, deliberately. The pool is FLAT
		// (docs/api-groups.md): `spec.podCIDR` is not read any more, so gating
		// on it only meant that a cluster without the node-ipam controller got
		// an EMPTY nodeIPs index and an EMPTY node_remotes map — no delivery
		// entry for any pod, and every cross-node flow black-holed. kind always
		// assigns podCIDRs, so no e2e could see it.
		node, ok := obj.(*corev1.Node)
		if !ok || node.Name == selfName {
			return
		}
		nodeIPs.set(node)
		fabricResync() // also revoke routes when this node loses its endpoint
		ip := internalIP(node)
		if ip == "" {
			log.Warn("node has no InternalIP", "node", node.Name)
			return
		}
		// The pool is FLAT (docs/api-groups.md): a pod's address says nothing
		// about which node holds it, so there is no per-node CIDR to program.
		// Delivery keys on the address — watchFabricIPs writes one remotes entry
		// per pod. All this watch owes it is the node -> tunnel-endpoint index.
		// Map the node's own addresses to its Geneve endpoint, so a pod's reply to
		// this node is encapsulated over the overlay (never emitted pod-sourced).
		geneveIP := net.ParseIP(ip)
		for _, addr := range nodeAddresses(node) {
			if err := mgr.SetNodeRemote(addr, geneveIP); err != nil {
				log.Error("set node remote", "node", node.Name, "addr", addr, "err", err)
			}
		}
	}

	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: apply,
		UpdateFunc: func(oldObj, newObj any) {
			oldNode, oldOK := oldObj.(*corev1.Node)
			newNode, newOK := newObj.(*corev1.Node)
			if oldOK && newOK && oldNode.Name != selfName {
				for _, addr := range removedNodeAddresses(nodeAddresses(oldNode), nodeAddresses(newNode)) {
					if err := mgr.DelNodeRemote(addr); err != nil {
						log.Error("del old node remote", "node", oldNode.Name, "addr", addr, "err", err)
					}
				}
			}
			apply(newObj)
		},
		DeleteFunc: func(obj any) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			node, ok := obj.(*corev1.Node)
			if !ok || node.Name == selfName {
				return
			}
			nodeIPs.del(node.Name)
			fabricResync()
			for _, addr := range nodeAddresses(node) {
				if err := mgr.DelNodeRemote(addr); err != nil {
					log.Error("del node remote", "node", node.Name, "addr", addr, "err", err)
				}
			}
		},
	})
	if err != nil {
		return fmt.Errorf("add node handler: %w", err)
	}

	// np_nodes (docs/network-policy.md): every node's addresses — INCLUDING
	// this node's, unlike the remotes above — are ingress-policy exempt
	// (kubelet probes, hostNetwork pods). Same-node probes source from the
	// local node's own addresses, hence no self-skip.
	npApply := func(obj any) {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return
		}
		// Only the LOCAL node's addresses are unconditionally ingress-exempt
		// (docs/policy-layers.md): remote-node origin is gated, admitted by
		// the `nodes` entity. The flag rides in the np_nodes value.
		local := node.Name == selfName
		for _, addr := range npNodeAddresses(node) {
			if err := mgr.SetNPNode(addr, local); err != nil {
				log.Error("set np node", "node", node.Name, "addr", addr, "err", err)
			}
		}
		// The same self address set is what "host-destined" means to the
		// host firewall (docs/host-firewall.md).
		if local {
			if err := mgr.SyncHFSelf(npNodeAddresses(node)); err != nil {
				log.Error("sync hf self", "node", node.Name, "err", err)
			}
		}
	}
	_, err = nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: npApply,
		UpdateFunc: func(oldObj, newObj any) {
			oldNode, oldOK := oldObj.(*corev1.Node)
			newNode, newOK := newObj.(*corev1.Node)
			if oldOK && newOK {
				for _, addr := range removedNodeAddresses(npNodeAddresses(oldNode), npNodeAddresses(newNode)) {
					if err := mgr.DelNPNode(addr); err != nil {
						log.Error("revoke old np node", "node", oldNode.Name, "addr", addr, "err", err)
					}
				}
			}
			npApply(newObj)
		},
		DeleteFunc: func(obj any) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			for _, addr := range npNodeAddresses(node) {
				if err := mgr.DelNPNode(addr); err != nil {
					log.Error("del np node", "node", node.Name, "addr", addr, "err", err)
				}
			}
		},
	})
	if err != nil {
		return fmt.Errorf("add np node handler: %w", err)
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
type ownNetworkSink interface {
	SyncOwnNetworks([]datapath.PeerNet) error
	SyncVPCCounterScopes([]uint32) error
	EnsureVPCCounter(uint32) error
}

func watchVPCs(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr ownNetworkSink, log *slog.Logger) func() {
	vpcs := factory.Sdn().V1alpha1().VPCs()
	knownCounters := map[uint32]bool{}
	apply := func() {
		all, err := vpcs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list own VPC networks", "err", err)
			return
		}
		desired, err := compileOwnNetworks(ctx, all)
		if err != nil {
			log.Error("compile own VPC networks", "err", err)
			return
		}
		// Object existence owns the counter lifetime, even when CIDRs are empty,
		// invalid legacy data, or the VPC is still completing deletion.
		scopes := make([]uint32, 0, len(all))
		for _, vpc := range all {
			if ctx.Err() != nil {
				return
			}
			if vpc != nil && vpc.Status.VNI > 0 && vpc.Status.VNI < 1<<22 {
				scopes = append(scopes, uint32(vpc.Status.VNI))
			}
		}
		if err := mgr.SyncVPCCounterScopes(scopes); err != nil {
			log.Error("sync VPC counter scopes", "err", err)
			return
		}
		if err := mgr.SyncOwnNetworks(desired); err != nil {
			log.Error("sync own VPC networks", "err", err)
			return
		}
		seeded := map[uint32]bool{}
		for _, entry := range desired {
			if seeded[entry.Net] {
				continue
			}
			seeded[entry.Net] = true
			if knownCounters[entry.Net] {
				continue
			}
			if err := mgr.EnsureVPCCounter(entry.Net); err != nil {
				log.Warn("seed vpc counter", "vni", entry.Net, "err", err)
			} else {
				knownCounters[entry.Net] = true
			}
		}
		for net := range knownCounters {
			if !seeded[net] {
				delete(knownCounters, net)
			}
		}
	}
	resync := resyncAfterCacheSync(ctx, apply, vpcs.Informer().HasSynced)
	_, _ = vpcs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
	return resync
}

// watchPorts mirrors remote VPC ports (pods on other nodes) into the remotes
// map as /32 routes to their node's Geneve endpoint, and severs a *local* pod's
// datapath when its Port is reaped out from under it (revocation). Best-effort,
// like watchVPCs.
func watchPorts(ctx context.Context, factory sdninformers.SharedInformerFactory, localFactory localinformers.SharedInformerFactory, sdn sdnclientset.Interface, core kubernetes.Interface, mgr *datapath.Manager, selfName, selfIP string, log *slog.Logger) error {
	informer := factory.Sdn().V1alpha1().Ports().Informer()
	requestSever, err := portSeverNotifications(ctx, informer, localFactory, sdn, core, selfName, log)
	if err != nil {
		return err
	}

	// Guest-announcement cutover (stage 3): a reconcile loop, keyed on veth
	// presence rather than Port events, runs a GARP/NA listener for every local
	// VM veth whose Port is active elsewhere. It is started once here.
	go watchGuestAnnouncements(ctx, factory.Sdn().V1alpha1().Ports().Lister(), sdn, core, localFactory, selfName, selfIP, log)

	apply := func(obj any) {
		port, ok := obj.(*sdnv1alpha1.Port)
		if !ok {
			return
		}
		current, found, err := currentPortSnapshot(informer.GetStore(), port)
		if err != nil {
			log.Error("read current Port cache", "port", port.Name, "err", err)
			return
		}
		if !found {
			return
		}
		port = current
		// A terminating local Port is a revocation in flight: sever the live
		// pod (if any), then release the sever finalizer to acknowledge. The
		// informer's initial sync delivers still-terminating Ports, so a
		// revocation that landed while this agent was down replays here.
		if port.DeletionTimestamp != nil {
			if n, ok := vniFromPortName(port.Name); ok && port.Spec.IP != "" {
				if err := mgr.DelMigrateFwd(n, net.ParseIP(port.Spec.IP)); err != nil {
					log.Error("revoke migration forward", "port", port.Name, "err", err)
				}
				if err := mgr.DelRemote(n, hostCIDR(port.Spec.IP)); err != nil {
					log.Error("revoke remote port", "port", port.Name, "err", err)
				}
			}
			// Keep proven-owner quarantine independent of acknowledgement and
			// uncertain legacy API reads. Old notifications coalesce to one replay.
			if err := severKnownLocalPort(ctx, core, localFactory, port, selfName, log); err != nil {
				log.Error("sever proven terminating port", "port", port.Name, "err", err)
			}
			requestSever()
			return
		}
		// A persistent (VM) Port's locals entry follows spec.node — the
		// staged-locals half of live migration: the target's entry appears
		// only at cutover (programmed here from the veth's alias record),
		// and the source's disappears at the same moment, so same-node
		// delivery flips exactly when cross-node delivery does.
		if port.Labels[sdnv1alpha1.LabelVMName] != "" && port.Spec.IP != "" {
			if net_, ok := vniFromPortName(port.Name); ok {
				vmIP := net.ParseIP(port.Spec.IP)
				if port.Spec.Node == selfName {
					if err := mgr.DelMigrateFwd(net_, vmIP); err != nil {
						log.Error("clear local migration forward", "port", port.Name, "err", err)
					}
					if programmed, err := datapath.EnsureLocalFromVeth(net_, vmIP, port.Annotations[sdnv1alpha1.AnnotationContainerID], port.Annotations[sdnv1alpha1.AnnotationCNIIfName], string(port.UID)); err != nil {
						log.Error("program persistent-port locals at cutover", "port", port.Name, "err", err)
					} else if programmed {
						log.Info("persistent port local delivery enabled (cutover)", "port", port.Name, "ip", port.Spec.IP)
					}
					// The route from when the VM lived elsewhere is stale now.
					if err := mgr.DelRemote(net_, hostCIDR(port.Spec.IP)); err != nil {
						log.Error("del stale remote for local persistent port", "port", port.Name, "err", err)
					}
				} else if err := datapath.SetLocalStaging(net_, vmIP, string(port.UID), true); err != nil {
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

	// migrateAway installs the source-forward safety net (docs/live-migration.md
	// stage 2). When a VM Port's spec.node moves off this node, remote nodes'
	// `remotes` entries still point here until their agents catch the update.
	// For that window this (former source) node re-encapsulates the VM's traffic
	// to the new node from its overlay hook, so in-flight east-west traffic isn't
	// black-holed. The entry is torn down after the propagation grace period.
	migrateAway := func(oldObj, newObj any) {
		oldPort, ok := oldObj.(*sdnv1alpha1.Port)
		if !ok {
			return
		}
		newPort, ok := newObj.(*sdnv1alpha1.Port)
		if !ok {
			return
		}
		if newPort.Labels[sdnv1alpha1.LabelVMName] == "" {
			return // only VM Ports migrate
		}
		if oldPort.UID != newPort.UID || newPort.DeletionTimestamp != nil {
			return
		}
		current, found, err := currentPortSnapshot(informer.GetStore(), newPort)
		if err != nil || !found || current.UID != newPort.UID || current.ResourceVersion != newPort.ResourceVersion {
			return
		}
		if oldPort.Spec.Node != selfName || newPort.Spec.Node == selfName || newPort.Spec.Node == "" {
			return // not a move off this node
		}
		if newPort.Spec.IP == "" || newPort.Spec.NodeIP == "" {
			return
		}
		net_, ok := vniFromPortName(newPort.Name)
		if !ok {
			return
		}
		vmIP := net.ParseIP(newPort.Spec.IP)
		err = installMigrationForward(ctx, mgr, net_, vmIP, net.ParseIP(newPort.Spec.NodeIP))
		if err != nil {
			log.Error("install migration source-forward", "port", newPort.Name, "err", err)
			return
		}
		log.Info("migration source-forward installed", "port", newPort.Name, "ip", newPort.Spec.IP, "target", newPort.Spec.NodeIP)
	}

	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: apply,
		UpdateFunc: func(oldObj, newObj any) {
			migrateAway(oldObj, newObj)
			apply(newObj)
		},
		DeleteFunc: func(obj any) {
			port := portFromDelete(obj)
			if port == nil || port.Spec.IP == "" {
				return
			}
			current, found, err := currentPortSnapshot(informer.GetStore(), port)
			if err != nil {
				log.Error("read Port cache for deletion", "port", port.Name, "err", err)
				return
			}
			if found {
				if current.UID != port.UID {
					if err := severLocalPort(ctx, core, localFactory, port, selfName, log); err != nil {
						log.Error("sever replaced Port generation", "port", port.Name, "err", err)
					}
				}
				apply(current)
				return
			}
			net_, ok := vniFromPortName(port.Name)
			if !ok {
				return
			}
			if err := mgr.DelMigrateFwd(net_, net.ParseIP(port.Spec.IP)); err != nil {
				log.Error("remove deleted migration forward", "port", port.Name, "err", err)
			}
			if err := severLocalPort(ctx, core, localFactory, port, selfName, log); err != nil {
				log.Error("sever deleted port endpoints", "port", port.Name, "err", err)
			}
			if port.Spec.Node == selfName {
				// Belt for Ports created before the sever finalizer existed;
				// finalized Ports were already severed while terminating.
				return
			}
			if err := mgr.DelRemote(net_, hostCIDR(port.Spec.IP)); err != nil {
				log.Error("del remote port", "port", port.Name, "err", err)
			}
		},
	})
	return nil
}

// watchGuestAnnouncements drives the stage-3 cutover (docs/live-migration.md).
// It reconciles, every couple of seconds, one GARP/NA listener per local VM
// veth whose Port is active on another node — the set of migration-involved
// veths on this node (a staged target waiting for the guest to arrive, or a
// former source that would reclaim the VM if the migration rolls back). The
// trigger is veth presence, not Port events, because a CNI ADD staging a
// migration target emits no Port event. When the guest announces itself the
// listener patches the Port's node to this one; the guest resumes on exactly
// one node, so exactly one listener ever fires, and it is always the right one.
func watchGuestAnnouncements(ctx context.Context, ports sdnv1alpha1listers.PortLister, sdn sdnclientset.Interface, core kubernetes.Interface, localFactory localinformers.SharedInformerFactory, selfName, selfIP string, log *slog.Logger) {
	var mu sync.Mutex
	type listener struct {
		cancel  context.CancelFunc
		uid     types.UID
		rv      string
		ifindex int
	}
	running := map[string]*listener{}

	fire := func(apiCtx context.Context, port *sdnv1alpha1.Port, ip string, v datapath.LocalPortVeth) {
		// The guest is live on this node. Claim the Port; the controller's
		// VMI-watch would reach the same value, just later.
		binding, err := guestBindingForVeth(apiCtx, core, localFactory, port, v, selfName)
		if err != nil {
			log.Warn("guest cutover ownership check failed", "port", port.Name, "err", err)
			return
		}
		moved, err := claimPortOnGuestAnnouncement(apiCtx, sdn, port, selfName, selfIP, binding)
		if err != nil {
			log.Error("flip port to self on guest announcement", "port", port.Name, "err", err)
			return
		}
		if moved {
			log.Info("migration cutover driven by guest announcement", "port", port.Name, "ip", ip, "node", selfName)
		}
	}

	reconcile := func() {
		// Index VM Ports active elsewhere by (net, ip).
		type target struct {
			port    *sdnv1alpha1.Port
			ifindex int
			mac     net.HardwareAddr
			ip      net.IP
			veth    datapath.LocalPortVeth
		}
		desired := map[string]target{} // Port name -> handle
		inventory, err := datapath.ListLocalPortVeths()
		if err != nil {
			log.Error("list guest endpoints", "err", err)
			return
		}
		all, err := guestPortCandidates(ports, inventory)
		if err != nil {
			return // lister not synced yet
		}
		index := indexLocalPortVeths(inventory)
		for _, p := range all {
			if p.Labels[sdnv1alpha1.LabelVMName] == "" || p.Spec.IP == "" || p.Spec.Node == selfName || p.DeletionTimestamp != nil {
				continue
			}
			veths, err := ownedPortVeths(ctx, core, localFactory, p, selfName, index.forPort(p))
			if err != nil {
				log.Warn("cannot prove guest endpoint ownership", "port", p.Name, "err", err)
				continue
			}
			active := veths[:0]
			for _, v := range veths {
				if v.RawNet != datapath.QuarantineNet {
					active = append(active, v)
				}
			}
			veths = active
			if len(veths) != 1 {
				continue
			} // ambiguous sandboxes cannot drive cutover
			v := veths[0]
			desired[p.Name] = target{port: p.DeepCopy(), ifindex: v.Ifindex, mac: v.MAC, ip: net.ParseIP(p.Spec.IP), veth: v}
		}

		mu.Lock()
		defer mu.Unlock()
		for name, t := range desired {
			if old := running[name]; old != nil {
				if old.uid == t.port.UID && old.rv == t.port.ResourceVersion && old.ifindex == t.ifindex {
					continue
				}
				old.cancel()
			}
			wctx, cancel := context.WithCancel(ctx)
			watch := &listener{cancel: cancel, uid: t.port.UID, rv: t.port.ResourceVersion, ifindex: t.ifindex}
			running[name] = watch
			log.Info("watching for migrated guest announcement", "port", name, "ip", t.ip.String())
			go func(name, ip string, t target) {
				defer cancel() // release the parent registration even on natural completion
				runGuestCutover(wctx,
					func(waitCtx context.Context) error {
						return datapath.WatchGuestAnnounce(waitCtx, t.ifindex, t.mac, t.ip)
					},
					func(apiCtx context.Context) { fire(apiCtx, t.port, ip, t.veth) },
					func() {
						mu.Lock()
						if running[name] == watch {
							delete(running, name) // never remove a replacement listener
						}
						mu.Unlock()
					})
			}(name, t.ip.String(), t)
		}
		for name, watch := range running {
			if _, ok := desired[name]; !ok {
				watch.cancel()
				delete(running, name)
			}
		}
	}

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			reconcile()
		}
	}
}

const severAcknowledgementTimeout = 5 * time.Second

// releaseSeveredPort handles a terminating Port on this node: sever the live
// pod if the Port was reaped out from under it, then remove the sever
// finalizer so the deletion completes. Idempotent — re-delivery is harmless.
func releaseSeveredPort(ctx context.Context, sdn sdnclientset.Interface, core kubernetes.Interface, localFactory localinformers.SharedInformerFactory, port *sdnv1alpha1.Port, log *slog.Logger) {
	if !slices.Contains(port.Finalizers, sdnv1alpha1.FinalizerSever) {
		return
	}
	// One budget covers confirmation, ownership reads and conflict retries.
	// A stalled API must not inherit the lifetime of the watch's agent context.
	ctx, cancel := context.WithTimeout(ctx, severAcknowledgementTimeout)
	defer cancel()
	current, err := sdn.SdnV1alpha1().Ports().Get(ctx, port.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		log.Error("retain sever finalizer: cannot read current port", "port", port.Name, "err", err)
		return
	}
	if current.UID != port.UID || current.DeletionTimestamp.IsZero() || current.Spec.Node != port.Spec.Node {
		log.Debug("skip obsolete sever acknowledgement", "port", port.Name)
		return
	}
	port = current
	if err := severLocalPort(ctx, core, localFactory, port, port.Spec.Node, log); err != nil {
		log.Error("retain sever finalizer", "port", port.Name, "err", err)
		return
	}
	for range 3 {
		latest, err := sdn.SdnV1alpha1().Ports().Get(ctx, port.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err != nil {
			log.Error("get terminating port", "port", port.Name, "err", err)
			return
		}
		if latest.UID != port.UID || latest.DeletionTimestamp.IsZero() || latest.Spec != port.Spec || latest.Labels[sdnv1alpha1.LabelPodUID] != port.Labels[sdnv1alpha1.LabelPodUID] {
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
type peeringSink interface {
	Peers() (map[[2]uint32]bool, error)
	SetPeer(uint32, uint32) error
	DelPeer(uint32, uint32) error
	SyncPeerNetworks([]datapath.PeerNet) error
}

func watchPeerings(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr peeringSink, log *slog.Logger, resyncOwn func()) {
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
			for _, cidr := range l.cidrsB {
				peerNets = append(peerNets, datapath.PeerNet{Scope: l.a, CIDR: cidr, Net: l.b})
			}
			for _, cidr := range l.cidrsA {
				peerNets = append(peerNets, datapath.PeerNet{Scope: l.b, CIDR: cidr, Net: l.a})
			}
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
		} else {
			resyncOwn() // a pruned legacy peer partition may release startup capacity
		}
	}
	resync = resyncAfterCacheSync(ctx, resync, peerings.Informer().HasSynced, vpcs.Informer().HasSynced)

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = peerings.Informer().AddEventHandler(onAny)
	_, _ = vpcs.Informer().AddEventHandler(onAny)

}

// watchGateways keeps the gateways map equal to the current boundary-authorized
// gateway Ports, from this node's point of view: a local gateway is delivered
// by redirect, a remote one by encapsulation to its node. Like watchPeerings,
// every relevant event triggers a recompute diffed against the pinned map, so
// a restarted agent prunes gateways that vanished while it was down.
func watchGateways(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr interface {
	Gateways() (map[uint32]bool, error)
	SetGateway(uint32, net.IP, net.IP) error
	DelGateway(uint32) error
}, selfName string, log *slog.Logger) {
	ports := factory.Sdn().V1alpha1().Ports()
	vpcs := factory.Sdn().V1alpha1().VPCs()
	boundaries := factory.Sdn().V1alpha1().VPCGateways()

	resync := func() {
		all, err := ports.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list ports", "err", err)
			return
		}
		allVPCs, err := vpcs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list VPCs for gateways", "err", err)
			return
		}
		allBoundaries, err := boundaries.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list VPCGateways for gateways", "err", err)
			return
		}
		desired := desiredGateways(all, allVPCs, allBoundaries, selfName)

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

	resync = resyncAfterCacheSync(ctx, resync, ports.Informer().HasSynced, vpcs.Informer().HasSynced, boundaries.Informer().HasSynced)

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
	_, _ = vpcs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
	_, _ = boundaries.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
}

// watchRoutes keeps the vpc_routes map equal to the resolved per-VPC route
// tables (VPCGateway.status.routes, issue #6), from this node's point of view.
// The controller resolves each route's selector to a next-hop Port; the agent
// turns that Port's current location into a datapath entry (local redirect or
// encapsulation to its node), and re-resolves when the Port moves. Diffed
// against the pinned map so a restarted agent prunes routes that vanished.
func watchRoutes(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr interface {
	SyncRoutesScoped([]datapath.RouteEntry, []uint32) error
	RouteCapacity() uint32
	BlockRoutes() error
}, selfName string, log *slog.Logger) {
	gws := factory.Sdn().V1alpha1().VPCGateways()
	vpnGWs := factory.Sdn().V1alpha1().VPNGateways()
	ports := factory.Sdn().V1alpha1().Ports()
	vpcs := factory.Sdn().V1alpha1().VPCs()
	const maxRouteCompileWork = 1 << 20
	maxRows := uint64(mgr.RouteCapacity())
	work := 0 // only the bounded reconciliation worker compiles these inputs
	charge := func(n int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n > maxRouteCompileWork-work {
			return fmt.Errorf("route compilation exceeds %d input operations", maxRouteCompileWork)
		}
		work += n
		return nil
	}

	// resolveRoutes turns a set of status routes (the shape both VPCGateway and
	// VPNGateway publish) into datapath entries, resolving each next-hop Port to
	// its IP and node. Unresolved next hops retain a blackhole prefix.
	resolveRoutes := func(ref sdnv1alpha1.VPCRef, routes []sdnv1alpha1.VPCGatewayRouteStatus, out *[]datapath.RouteEntry) error {
		vpc, err := vpcs.Lister().VPCs(ref.Namespace).Get(ref.Name)
		if err != nil || vpc.DeletionTimestamp != nil || vpc.Status.VNI <= 0 {
			return nil
		}
		vni := uint32(vpc.Status.VNI)
		for _, rt := range routes {
			if err := charge(1); err != nil {
				return err
			}
			if len(rt.Ports) > 2 {
				return fmt.Errorf("route has more than two next-hop ports")
			}
			if err := charge(len(rt.CIDRs)); err != nil {
				return err
			}
			portNames := rt.Ports
			if len(portNames) == 0 && rt.Port != "" {
				portNames = []string{rt.Port}
			}
			if err := charge(len(portNames)); err != nil {
				return err
			}
			var nextHops []datapath.RouteNextHop
			for _, portName := range portNames {
				port, err := ports.Lister().Get(portName)
				if err != nil || port.Spec.IP == "" || port.DeletionTimestamp != nil || port.Spec.VPCRef != ref {
					continue
				}
				portVNI, ok := vniFromPortName(port.Name)
				if !ok || portVNI != vni {
					continue
				}
				gwIP := net.ParseIP(port.Spec.IP)
				if gwIP == nil || port.Name != sdn.PortName(vpc.Status.VNI, gwIP.String()) {
					continue
				}
				var nodeIP net.IP
				if port.Spec.Node != selfName {
					nodeIP = net.ParseIP(port.Spec.NodeIP)
					if nodeIP == nil || nodeIP.To4() == nil {
						continue
					}
				}
				nextHops = append(nextHops, datapath.RouteNextHop{GwIP: gwIP, NodeIP: nodeIP})
			}
			for _, cidr := range rt.CIDRs {
				if uint64(len(*out)) >= maxRows {
					return fmt.Errorf("route candidates exceed map capacity %d", maxRows)
				}
				*out = append(*out, datapath.RouteEntry{
					Scope: vni, CIDR: cidr, NextHops: nextHops,
				})
			}
		}
		return nil
	}

	resync := func() {
		if err := mgr.BlockRoutes(); err != nil {
			log.Error("arm route compilation guard", "err", err)
			return
		}
		work = 0
		var desired []datapath.RouteEntry
		// A VPCGateway's explicit spec.routes (increment 1) and a VPNGateway's
		// connection-derived routes (increment 4) merge into one route table —
		// docs/vpn.md §3.2. Both address the same vpc_routes map.
		allGW, err := gws.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list vpcgateways for routes", "err", err)
			return
		}
		if err := charge(len(allGW)); err != nil {
			log.Error("reject route snapshot", "err", err)
			return
		}
		groups := map[string]*routeNamespace{}
		add := func(ref sdnv1alpha1.VPCRef, routes []sdnv1alpha1.VPCGatewayRouteStatus) error {
			vpc, err := vpcs.Lister().VPCs(ref.Namespace).Get(ref.Name)
			if err != nil || vpc.DeletionTimestamp != nil || vpc.Status.VNI <= 0 {
				return nil
			}
			if vpc.Status.VNI >= 1<<22 {
				return fmt.Errorf("VPC route scope outside tenant VNI range")
			}
			group := groups[ref.Namespace]
			if group == nil {
				group = &routeNamespace{scopes: map[uint32]struct{}{}}
				groups[ref.Namespace] = group
			}
			group.scopes[uint32(vpc.Status.VNI)] = struct{}{}
			if len(routes) == 0 {
				return nil
			}
			if group.invalid || group.demand > maxRows {
				return nil // The owner is already denied; only scope proof remains.
			}
			// Reject oversized legacy arrays before expanding them. Keep each
			// owner's demand saturated at capacity+1, never attacker-controlled.
			if len(routes) > 4096 {
				group.invalid = true
				return nil
			}
			for _, route := range routes {
				if err := charge(1); err != nil {
					return err
				}
				if len(route.CIDRs) > 4096 || len(route.Ports) > 2 {
					group.invalid = true
					return nil
				}
				group.demand = min(maxRows+1, group.demand+uint64(len(route.CIDRs)))
				if group.demand > maxRows {
					return nil // No fair share can admit this owner's complete intent.
				}
				if err := charge(len(route.CIDRs)); err != nil {
					return err
				}
				for _, cidr := range route.CIDRs {
					if len(cidr) > 64 {
						group.invalid = true
						return nil
					}
					if _, _, err := net.ParseCIDR(cidr); err != nil {
						group.invalid = true
						return nil
					}
				}
			}
			group.inputs = append(group.inputs, routeInput{ref: ref, routes: routes})
			return nil
		}
		for ref, candidates := range gatewayCandidatesByVPC(allGW) {
			gw := sdnv1alpha1.EffectiveGateway(candidates, ref.Name)
			if gw != nil {
				if err := add(ref, gw.Status.Routes); err != nil {
					log.Error("reject route snapshot", "err", err)
					return
				}
			}
		}
		allVPN, err := vpnGWs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list vpngateways for routes", "err", err)
			return
		}
		if err := charge(len(allVPN)); err != nil {
			log.Error("reject route snapshot", "err", err)
			return
		}
		for _, gw := range allVPN {
			if gw.DeletionTimestamp != nil {
				continue
			}
			allowed := map[string]bool{gw.Spec.VPCRef.Name: true}
			invalid := len(gw.Spec.AdditionalVPCRefs) > 9 || len(gw.Status.Routes) > 4096
			for _, ref := range gw.Spec.AdditionalVPCRefs[:min(9, len(gw.Spec.AdditionalVPCRefs))] {
				if ref.Name == "" || allowed[ref.Name] {
					invalid = true
				}
				allowed[ref.Name] = true
			}
			// Prove only declared scopes. An invalid legacy hub denies its owner,
			// while unrelated namespaces retain their complete route snapshot.
			for name := range allowed {
				if err := add(sdnv1alpha1.VPCRef{Namespace: gw.Namespace, Name: name}, nil); err != nil {
					invalid = true
				}
			}
			byVPC := make(map[string][]sdnv1alpha1.VPCGatewayRouteStatus, len(allowed))
			if !invalid {
				for _, route := range gw.Status.Routes {
					name := route.VPCRef.Name
					if name == "" {
						name = gw.Spec.VPCRef.Name
					}
					if !allowed[name] {
						invalid = true
						break
					}
					byVPC[name] = append(byVPC[name], route)
				}
			}
			if invalid {
				if group := groups[gw.Namespace]; group != nil {
					group.invalid = true
				}
				continue
			}
			for name, routes := range byVPC {
				if err := add(sdnv1alpha1.VPCRef{Namespace: gw.Namespace, Name: name}, routes); err != nil {
					log.Error("reject VPN route snapshot", "err", err)
					return
				}
			}
		}
		budgets := routeBudgets(groups, maxRows)
		var blocked []uint32
		warnings := 0
		for namespace, group := range groups {
			if group.invalid || group.demand > budgets[namespace] {
				for scope := range group.scopes {
					blocked = append(blocked, scope)
				}
				if warnings < 32 {
					log.Warn("block owner route scopes", "namespace", namespace, "invalid", group.invalid, "demand", group.demand, "budget", budgets[namespace])
				}
				warnings++
				continue
			}
			for _, input := range group.inputs {
				if err := resolveRoutes(input.ref, input.routes, &desired); err != nil {
					log.Error("reject route snapshot", "err", err)
					return
				}
			}
		}
		if warnings > 32 {
			log.Warn("additional blocked route owners", "count", warnings-32)
		}
		if err := ctx.Err(); err != nil {
			return // keep the guard closed; never publish after cancellation
		}
		if err := mgr.SyncRoutesScoped(desired, blocked); err != nil {
			log.Error("sync routes", "err", err)
		}
	}

	if err := mgr.BlockRoutes(); err != nil {
		log.Error("arm initial route cache guard", "err", err)
	}
	resync = periodicResyncAfterCacheSync(ctx, revocationRetryPeriod, resync, gws.Informer().HasSynced, vpnGWs.Informer().HasSynced, ports.Informer().HasSynced, vpcs.Informer().HasSynced)

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = gws.Informer().AddEventHandler(onAny)
	_, _ = vpnGWs.Informer().AddEventHandler(onAny)
	_, _ = ports.Informer().AddEventHandler(onAny)
	_, _ = vpcs.Informer().AddEventHandler(onAny)
}

type gatewayView struct {
	ip     net.IP // the gateway's VPC-leg (.1) address
	nodeIP net.IP // nil when the gateway runs on this node
}

// desiredGateways computes gateway entries from current VPC claims authorized
// by each VPC's effective boundary. The claim name must match the current VNI.
func desiredGateways(ports []*sdnv1alpha1.Port, vpcs []*sdnv1alpha1.VPC, gws []*sdnv1alpha1.VPCGateway, selfName string) map[uint32]gatewayView {
	byVPC := map[sdnv1alpha1.VPCRef]*sdnv1alpha1.VPC{}
	for _, vpc := range vpcs {
		byVPC[sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}] = vpc
	}
	boundaries := map[sdnv1alpha1.VPCRef]*sdnv1alpha1.VPCGateway{}
	for ref, candidates := range gatewayCandidatesByVPC(gws) {
		boundaries[ref] = sdnv1alpha1.EffectiveGateway(candidates, ref.Name)
	}
	desired := map[uint32]gatewayView{}
	for _, p := range ports {
		if !p.Spec.Gateway || p.DeletionTimestamp != nil {
			continue
		}
		vpc := byVPC[p.Spec.VPCRef]
		if vpc == nil || vpc.DeletionTimestamp != nil || vpc.Status.VNI <= 0 {
			continue
		}
		ip := net.ParseIP(p.Spec.IP)
		if ip == nil || p.Name != sdn.PortName(vpc.Status.VNI, ip.String()) {
			continue
		}
		boundary := boundaries[p.Spec.VPCRef]
		if boundary == nil {
			continue
		}
		if boundary.Spec.Appliance != nil {
			if boundary.Status.AppliancePort != p.Name {
				continue
			}
		} else {
			if !boundary.Spec.NAT.Enabled || len(vpc.Spec.CIDRs) == 0 {
				continue
			}
			prefix, err := netip.ParsePrefix(vpc.Spec.CIDRs[0])
			if err != nil {
				continue
			}
			reserved := prefix.Masked().Addr().Next()
			if !prefix.Contains(reserved) || reserved.Unmap().String() != ip.String() {
				continue
			}
		}
		gw := gatewayView{ip: ip}
		if p.Spec.Node != selfName {
			gw.nodeIP = net.ParseIP(p.Spec.NodeIP)
			if gw.nodeIP == nil {
				continue
			}
		}
		desired[uint32(vpc.Status.VNI)] = gw
	}
	return desired
}

// watchServiceUplinks keeps the datapath serving the link that carries every
// LoadBalancer ingress address, on EVERY node. LB/NodePort frontends
// (docs/lb-ingress.md) arrive wherever the provider attracts them — including
// on nodes that host no floating-IP target, and an etp: Cluster DSR reply must
// leave by that same link (found live: a MetalLB-announced LB IP black-holed on
// a node whose only VLAN attach trigger was a local FloatingIP). ExternalPool
// CIDRs used to make the attach unconditional; with pools retired
// (docs/external-addresses.md §9) the trigger is the addresses that actually
// exist: every `status.loadBalancer.ingress` IP, plus floating addresses
// (watchFloatingIPs) and VPC NAT identities (watchVPCGateways). The FIB decides
// which link serves each one; EnsureFloatingUplink is idempotent.
func watchServiceUplinks(ctx context.Context, client kubernetes.Interface, mgr *datapath.Manager, log *slog.Logger) {
	factory := informers.NewSharedInformerFactory(client, 0)
	svcs := factory.Core().V1().Services()

	resync := func() {
		list, err := svcs.Lister().List(labels.Everything())
		if err != nil {
			log.Warn("list services for uplinks", "err", err)
			return
		}
		for _, s := range list {
			// Both kinds of external address kpr writes rows for need the same
			// thing here: if the address lands on a secondary NIC rather than
			// the default uplink, from_uplink must be attached there too, or
			// nothing intercepts the traffic. EnsureFloatingUplink no-ops only
			// when the address arrives on the default uplink; a gateway'd or
			// node-owned address on another NIC binds there.
			for _, ing := range s.Status.LoadBalancer.Ingress {
				if ing.IP == "" {
					continue
				}
				if err := mgr.EnsureFloatingUplink(ing.IP); err != nil {
					log.Warn("ensure LB uplink", "service", s.Namespace+"/"+s.Name, "ip", ing.IP, "err", err)
				}
			}
			for _, ext := range s.Spec.ExternalIPs {
				if ext == "" {
					continue
				}
				if err := mgr.EnsureFloatingUplink(ext); err != nil {
					log.Warn("ensure externalIP uplink", "service", s.Namespace+"/"+s.Name, "ip", ext, "err", err)
				}
			}
		}
	}
	resync = resyncAfterCacheSync(ctx, resync, svcs.Informer().HasSynced)

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = svcs.Informer().AddEventHandler(onAny)
	factory.Start(ctx.Done())
}

// watchFloatingIPs programs the publicIP -> {net, VPC IP} mapping on EVERY node,
// for every FloatingIP with a live target Port.
//
// Cozyplane does not attract the address (docs/north-south.md, tenet 3) — a CCM,
// MetalLB, a static route or an address configured on a node does. That is why
// every node programs the map: whichever node the fabric hands the packet to,
// from_uplink resolves it and reaches the pod, locally or over the overlay.
//
// Recompute-and-diff against the pinned map on every relevant event, so a
// restarted agent prunes entries whose FloatingIP or target Port vanished while
// it was down.
func watchFloatingIPs(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	fips := factory.Sdn().V1alpha1().FloatingIPs()
	ports := factory.Sdn().V1alpha1().Ports()
	vpcs := factory.Sdn().V1alpha1().VPCs()

	resync := func() {
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
		allVPCs, err := vpcs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list VPCs for floating targets", "err", err)
			return
		}
		desired := desiredFloating(allFips, allPorts, allVPCs)

		targets := map[string]datapath.FloatingTarget{}
		for pub, v := range desired {
			// The FIB decides which link serves this address: on a multi-NIC node
			// the pool may live on a non-default link (an OCI VLAN), where
			// from_uplink must attach and the egress must leave.
			if err := mgr.EnsureFloatingUplink(pub); err != nil {
				log.Warn("ensure floating uplink", "public", pub, "err", err)
			}
			targets[pub] = datapath.FloatingTarget{VNI: v.vni, VPCIP: v.vpcIP}
		}
		if err := mgr.SyncFloating(targets); err != nil {
			log.Error("sync floating projection", "err", err)
		}
	}

	resync = resyncAfterCacheSync(ctx, resync, fips.Informer().HasSynced, ports.Informer().HasSynced, vpcs.Informer().HasSynced)

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = fips.Informer().AddEventHandler(onAny)
	_, _ = ports.Informer().AddEventHandler(onAny)
	_, _ = vpcs.Informer().AddEventHandler(onAny)
}

// floatingView is what a node must program for one floating IP: the target tenant
// IP, its network id (VNI), and the node its Port currently lives on.
type floatingView struct {
	vpcIP string
	vni   uint32
	node  string
}

// desiredFloating computes the floating IPs to program — those whose target
// tenant IP is realized by a live Port ANYWHERE in the cluster, not just here.
// Every node needs the mapping: the announcer must be able to resolve an address
// whose pod is elsewhere (from_uplink then forwards it over the overlay), and the
// host must be able to SNAT the pod's replies back to it. The VNI comes from the
// target Port's name. A FloatingIP's local vpcRef resolves in its own namespace,
// which is the target Port's VPCRef namespace.
func desiredFloating(fips []*sdnv1alpha1.FloatingIP, ports []*sdnv1alpha1.Port, vpcs []*sdnv1alpha1.VPC) map[string]floatingView {
	type portKey struct{ ns, name, ip string }
	type portVal struct {
		vni  uint32
		node string
	}
	live := map[portKey]portVal{}
	byVPC := map[sdnv1alpha1.VPCRef]*sdnv1alpha1.VPC{}
	for _, v := range vpcs {
		if v.DeletionTimestamp == nil && v.Status.VNI > 0 {
			byVPC[sdnv1alpha1.VPCRef{Namespace: v.Namespace, Name: v.Name}] = v
		}
	}
	for _, p := range ports {
		vpc := byVPC[p.Spec.VPCRef]
		if p.Spec.Node == "" || p.Spec.IP == "" || p.DeletionTimestamp != nil || vpc == nil {
			continue
		}
		vni, ok := vniFromPortName(p.Name)
		if !ok || vni != uint32(vpc.Status.VNI) {
			continue
		}
		ip := net.ParseIP(p.Spec.IP)
		if ip == nil || p.Name != sdn.PortName(vpc.Status.VNI, ip.String()) {
			continue
		}
		live[portKey{p.Spec.VPCRef.Namespace, p.Spec.VPCRef.Name, ip.String()}] = portVal{vni, p.Spec.Node}
	}

	out := map[string]floatingView{}
	byTarget := map[portKey][]sdnv1alpha1.FloatingIP{}
	for _, f := range fips {
		ip := floatingvalidation.Target(f.Spec.VPCRef.Name, f.Spec.Target)
		if ip == "" {
			continue
		}
		key := portKey{f.Namespace, f.Spec.VPCRef.Name, ip}
		byTarget[key] = append(byTarget[key], *f)
	}
	for key, candidates := range byTarget {
		f := sdnv1alpha1.EffectiveFloatingIP(candidates, key.name, key.ip)
		if f == nil {
			continue
		}
		if len(floatingvalidation.Validate(f.Spec.VPCRef.Name, f.Spec.Target, f.Spec.LoadBalancerClass, f.Spec.AddressClaimName)) != 0 {
			continue
		}
		if f.Status.Address == "" || f.DeletionTimestamp != nil {
			continue
		}
		v, ok := live[key]
		if !ok {
			continue // no live Port for the target: the address stays dark
		}
		out[f.Status.Address] = floatingView{vpcIP: key.ip, vni: v.vni, node: v.node}
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
	if err != nil || vni < uint64(netid.FirstVNI) || vni > uint64(netid.LastVNI) {
		return 0, false
	}
	return uint32(vni), true
}

// peerLink is a live peering between two VPCs, normalized so a < b, carrying
// each side's VNI and all CIDRs (for dual-stack delivery entries).
type peerLink struct {
	a, b           uint32
	cidrsA, cidrsB []string
}

// desiredPeerLinks computes the live peerings: one per pair of mutually-matched
// halves whose local and peer VPCs both have assigned VNIs and whose CIDRs are
// disjoint — peered traffic is routed natively, so overlapping address spaces
// cannot be connected (the one restriction overlap carries).
func desiredPeerLinks(peerings []*sdnv1alpha1.VPCPeering, vpc func(namespace, name string) *sdnv1alpha1.VPC) []peerLink {
	type vpcValidation struct {
		object *sdnv1alpha1.VPC
		valid  bool
	}
	validated := map[sdnv1alpha1.VPCRef]vpcValidation{}
	eligible := func(ref sdnv1alpha1.VPCRef, object *sdnv1alpha1.VPC) bool {
		if previous, ok := validated[ref]; ok && previous.object == object {
			return previous.valid
		}
		valid := object != nil && object.DeletionTimestamp.IsZero() && netid.ValidVNI(object.Status.VNI) &&
			sdnv1alpha1.ValidateVPCCIDRs(object.Spec.CIDRs) == nil
		validated[ref] = vpcValidation{object: object, valid: valid}
		return valid
	}
	type consent struct {
		first    *sdnv1alpha1.VPCPeering
		distinct bool
	}
	index := map[[2]sdnv1alpha1.VPCRef]consent{}
	for _, p := range peerings {
		if p == nil || !p.DeletionTimestamp.IsZero() || !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
			continue
		}
		key := [2]sdnv1alpha1.VPCRef{p.LocalRef(), p.Spec.PeerRef}
		bucket := index[key]
		if bucket.first == nil {
			bucket.first = p
		} else if bucket.first != p {
			bucket.distinct = true
		}
		index[key] = bucket
	}
	seen := map[[2]uint32]bool{}
	var out []peerLink
	for _, p := range peerings {
		if p == nil || !p.DeletionTimestamp.IsZero() || !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
			continue
		}
		bucket := index[[2]sdnv1alpha1.VPCRef{p.Spec.PeerRef, p.LocalRef()}]
		if bucket.first == nil || (bucket.first == p && !bucket.distinct) {
			continue
		}
		va := vpc(p.Namespace, p.Spec.VPCRef.Name)
		vb := vpc(p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name)
		if !eligible(p.LocalRef(), va) || !eligible(p.Spec.PeerRef, vb) {
			continue
		}
		if len(va.Spec.CIDRs) == 0 || len(vb.Spec.CIDRs) == 0 {
			continue
		}
		if sdnv1alpha1.CIDRsOverlap(va.Spec.CIDRs, vb.Spec.CIDRs) {
			continue
		}
		a, b := netid.VNI(va.Status.VNI), netid.VNI(vb.Status.VNI)
		ca, cb := slices.Clone(va.Spec.CIDRs), slices.Clone(vb.Spec.CIDRs)
		if a > b {
			a, b = b, a
			ca, cb = cb, ca
		}
		if seen[[2]uint32{a, b}] {
			continue
		}
		seen[[2]uint32{a, b}] = true
		out = append(out, peerLink{a: a, b: b, cidrsA: ca, cidrsB: cb})
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
// has already cleaned up. It also drains lingering sandboxes after pod deletion;
// its finalizer still reserves the address when a new Pod reuses the name.
func severLocalPort(ctx context.Context, core kubernetes.Interface, localFactory localinformers.SharedInformerFactory, port *sdnv1alpha1.Port, self string, log *slog.Logger, inventory ...[]datapath.LocalPortVeth) error {
	if port.Spec.PodNamespace == "" || port.Spec.PodName == "" {
		return fmt.Errorf("port %s has no owning pod", port.Name)
	}
	net_, ok := vniFromPortName(port.Name)
	if !ok {
		return fmt.Errorf("port %s has no valid VNI", port.Name)
	}
	// A terminating or already-gone pod can still have a live sandbox until
	// CNI DEL completes. Drain it too; the Port's finalizer reserves its IP.
	// The live Port UID alias proves ownership without a Pod API dependency.
	// Legacy endpoints still need their sandbox/launcher proof in ownedPortVeths.
	// The underlay address comes from the pod's FabricIP claim, not from a copy
	// on the Port (docs/api-groups.md).
	fabric := fabricByPodUID(localFactory, port.Labels[sdnv1alpha1.LabelPodUID], port.Annotations[sdnv1alpha1.AnnotationContainerID], port.Annotations[sdnv1alpha1.AnnotationCNIIfName])
	var veths []datapath.LocalPortVeth
	if len(inventory) > 0 {
		veths = inventory[0]
	} else {
		var err error
		veths, err = datapath.ListLocalPortVeths()
		if err != nil {
			return err
		}
	}
	var known, legacy []datapath.LocalPortVeth
	for _, v := range veths {
		if v.PortUID == "" {
			legacy = append(legacy, v)
		} else {
			known = append(known, v)
		}
	}
	var firstErr error
	drain := func(candidates []datapath.LocalPortVeth) {
		endpoints, err := ownedPortVeths(ctx, core, localFactory, port, self, candidates)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		for _, v := range endpoints {
			severed, err := datapath.SeverVethIfOwned(net_, net.ParseIP(port.Spec.IP), v.Ifindex, v.Alias, fabric)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("sever local port: %w", err)
				}
				continue
			}
			if severed {
				log.Info("severed local port (VPC access revoked)",
					"ip", port.Spec.IP, "pod", port.Spec.PodNamespace+"/"+port.Spec.PodName)
			}
		}
	}
	// Proven UID owners are drained before any uncertain legacy API work.
	drain(known)
	// One ambiguous legacy endpoint cannot hide another proven sandbox.
	for _, v := range legacy {
		drain([]datapath.LocalPortVeth{v})
	}
	return firstErr
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
	ctx, cancel := context.WithTimeout(ctx, startupBestEffortTimeout)
	defer cancel()
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

// watchServiceVIPs projects every ServiceVIP into the svc_vips datapath map
// (docs/services-in-vpc.md increment 2). Full-state resync on any ServiceVIP
// or VPC change — the objects are few and the map diff is cheap.
// watchSecurityGroups projects intra-VPC policy into the datapath
// (docs/security-groups.md): SecurityGroups' ingress rules become sg_rules
// (resolving from.group names to per-VPC ids and cidr 0.0.0.0/0 to the reserved
// world pseudo-group), and Ports' resolved membership (status.groups) becomes
// sg_members. Both are full-state resyncs, keyed on SecurityGroup, Port, and
// VPC (for the VNI) changes — the same shape as watchServiceVIPs.
func watchSecurityGroups(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	sgs := factory.Sdn().V1alpha1().SecurityGroups()
	ports := factory.Sdn().V1alpha1().Ports()
	vpcs := factory.Sdn().V1alpha1().VPCs()

	type vpcKey struct{ ns, name string }

	var mu sync.Mutex
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		allSGs, err := sgs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list securitygroups", "err", err)
			return
		}
		// Per-VPC name -> id, for resolving from.group references (same VPC).
		allPorts, err := ports.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list ports for sg_members", "err", err)
			return
		}
		if err := validateSGCompilation(allSGs, allPorts); err != nil {
			log.Error("reject SecurityGroup compilation; arming deny guard", "err", err)
			if err := mgr.BlockSecurityGroups(); err != nil {
				log.Error("arm SecurityGroup deny guard", "err", err)
			}
			return
		}
		nameID := map[vpcKey]map[string]uint16{}
		for _, sg := range allSGs {
			if !sg.DeletionTimestamp.IsZero() || sg.Status.ID <= 0 || sg.Status.ID >= datapath.SGWorldGroup || !vpnlimits.NamespaceName(sg.Namespace) || !vpnlimits.ObjectName(sg.Spec.VPCRef.Name) {
				continue
			}
			k := vpcKey{sg.Namespace, sg.Spec.VPCRef.Name}
			if nameID[k] == nil {
				nameID[k] = map[string]uint16{}
			}
			nameID[k][sg.Name] = netid.Group(sg.Status.ID)
		}

		var rules []datapath.SGRule
		var cidrRules []datapath.SGCidr
		var egressRules []datapath.SGEgress
		var egressCidrRules []datapath.SGEgressCidr
		nets := map[uint32]bool{}
		for _, sg := range allSGs {
			if !sg.DeletionTimestamp.IsZero() || sg.Status.ID <= 0 || sg.Status.ID >= datapath.SGWorldGroup || !vpnlimits.NamespaceName(sg.Namespace) || !vpnlimits.ObjectName(sg.Spec.VPCRef.Name) {
				continue
			}
			vpc, err := vpcs.Lister().VPCs(sg.Namespace).Get(sg.Spec.VPCRef.Name)
			if err != nil || !netid.ValidVNI(vpc.Status.VNI) {
				continue
			}
			net_ := netid.VNI(vpc.Status.VNI)
			nets[net_] = true
			k := vpcKey{sg.Namespace, sg.Spec.VPCRef.Name}
			for _, ing := range sg.Spec.Ingress {
				var allowed uint64
				srcNet := net_ // same-VPC by default
				switch {
				case ing.From.Group != "":
					if !securityGroupPeerReference(ing.From) {
						continue
					}
					// A peer-VPC ref resolves the group's id in the peer VPC's id
					// space, keyed by the peer's VNI so it can't collide with a
					// same-VPC id.
					srcKey := k
					if v := ing.From.VPC; v != nil {
						srcKey = vpcKey{v.Namespace, v.Name}
						pvpc, err := vpcs.Lister().VPCs(v.Namespace).Get(v.Name)
						if err != nil || !netid.ValidVNI(pvpc.Status.VNI) {
							continue // peer VPC unknown/not ready yet
						}
						srcNet = netid.VNI(pvpc.Status.VNI)
					}
					id, ok := nameID[srcKey][ing.From.Group]
					if !ok {
						continue // unknown/unallocated source group admits nothing yet
					}
					allowed = 1 << uint(id)
				case isAnyCIDR(ing.From.CIDR):
					allowed = 1 << uint(datapath.SGWorldGroup)
				case ing.From.CIDR != "":
					// A specific north-south range compiles into the sg_cidr LPM
					// map (v2 stage 2), not the group-bitmap sg_rules.
					_, ipnet, err := net.ParseCIDR(ing.From.CIDR)
					if err != nil {
						log.Warn("security group: bad cidr; rule ignored", "group", sg.Name, "cidr", ing.From.CIDR, "err", err)
						continue
					}
					cidrRules = append(cidrRules, compileCidrPorts(net_, ipnet, 1<<uint(netid.Group(sg.Status.ID)), ing.Ports)...)
					continue
				default:
					continue
				}
				for _, r := range compileRulePorts(net_, srcNet, netid.Group(sg.Status.ID), allowed, ing.Ports) {
					rules = append(rules, r)
				}
			}
			// Egress rules (v2): resolve the destination group's id + VNI (same
			// VPC by default, or a peered VPC) and key the entry from the source
			// side. cidr egress destinations are not supported yet.
			for _, eg := range sg.Spec.Egress {
				// A cidr destination (north-south egress) compiles into the
				// sg_egress_cidr LPM, keyed from the source side.
				if eg.To.CIDR != "" {
					_, ipnet, err := net.ParseCIDR(eg.To.CIDR)
					if err != nil {
						log.Warn("security group: bad egress cidr; rule ignored", "group", sg.Name, "cidr", eg.To.CIDR, "err", err)
						continue
					}
					egressCidrRules = append(egressCidrRules, compileEgressCidrPorts(net_, ipnet, 1<<uint(netid.Group(sg.Status.ID)), eg.Ports)...)
					continue
				}
				if eg.To.Group == "" {
					continue
				}
				if !securityGroupPeerReference(eg.To) {
					continue
				}
				dstKey := k
				dstNet := net_
				if v := eg.To.VPC; v != nil {
					dstKey = vpcKey{v.Namespace, v.Name}
					dvpc, err := vpcs.Lister().VPCs(v.Namespace).Get(v.Name)
					if err != nil || !netid.ValidVNI(dvpc.Status.VNI) {
						continue
					}
					dstNet = netid.VNI(dvpc.Status.VNI)
				}
				dstID, ok := nameID[dstKey][eg.To.Group]
				if !ok {
					continue
				}
				allowedDst := uint64(1) << uint(dstID)
				for _, e := range compileEgressPorts(net_, dstNet, netid.Group(sg.Status.ID), allowedDst, eg.Ports) {
					egressRules = append(egressRules, e)
				}
			}
		}
		for n := range nets {
			if err := mgr.EnsureSGDrop(n); err != nil {
				log.Error("seed sg_drops", "net", n, "err", err)
			}
		}

		members := securityGroupMembers(allPorts, allSGs)
		if err := mgr.ApplySecurityGroups(members, rules, cidrRules, egressRules, egressCidrRules); err != nil {
			log.Error("apply SecurityGroups; update guard retained", "err", err)
		}
	}
	resync = resyncAfterCacheSync(ctx, resync, sgs.Informer().HasSynced,
		ports.Informer().HasSynced, vpcs.Informer().HasSynced)

	_, _ = sgs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
	_, _ = ports.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
	_, _ = vpcs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
	})
}

// A selected but unrealized SG retains a nonempty bitmap with no user rules.
// This denies new SG-gated TCP/UDP admissions, preserving established traffic
// and the existing SG protocol semantics. Empty means no selected groups.
func securityGroupMembership(ids []int32) uint64 {
	var bitmap uint64
	for _, id := range ids {
		if !netid.ValidGroup(id) {
			return 1
		} // bit 0: pending, never allowed by a user rule.
		bitmap |= 1 << id
	}
	return bitmap
}

// compileRulePorts expands an ingress rule's port list into datapath rules for
// (net, dst group, allowed sources). No ports means every protocol and port
// (an any-port rule per protocol); a listed port with no protocol match is
// skipped.
func compileRulePorts(net_, srcNet uint32, group uint16, allowed uint64, ports []sdnv1alpha1.SecurityGroupPort) []datapath.SGRule {
	var out []datapath.SGRule
	if len(ports) == 0 {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			out = append(out, datapath.SGRule{Net: net_, SrcNet: srcNet, Group: group, Proto: proto, Port: 0, Allowed: allowed})
		}
		return out
	}
	for _, pp := range ports {
		proto, port, valid := compileSGPort(pp)
		if !valid {
			continue
		}
		out = append(out, datapath.SGRule{Net: net_, SrcNet: srcNet, Group: group, Proto: proto, Port: port, Allowed: allowed})
	}
	return out
}

// compileEgressPorts expands an egress rule's port list into sg_egress entries
// for (src net, dst net, source group) admitting the destination group bitmap.
func compileEgressPorts(srcNet, dstNet uint32, group uint16, allowedDst uint64, ports []sdnv1alpha1.SecurityGroupPort) []datapath.SGEgress {
	var out []datapath.SGEgress
	if len(ports) == 0 {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			out = append(out, datapath.SGEgress{SrcNet: srcNet, DstNet: dstNet, Group: group, Proto: proto, Port: 0, Allowed: allowedDst})
		}
		return out
	}
	for _, pp := range ports {
		proto, port, valid := compileSGPort(pp)
		if !valid {
			continue
		}
		out = append(out, datapath.SGEgress{SrcNet: srcNet, DstNet: dstNet, Group: group, Proto: proto, Port: port, Allowed: allowedDst})
	}
	return out
}

// compileEgressCidrPorts expands a north-south egress rule into sg_egress_cidr
// entries: (src net, proto, dst port, destination CIDR) admitting the source
// group bitmap.
func compileEgressCidrPorts(srcNet uint32, cidr *net.IPNet, allowedSrc uint64, ports []sdnv1alpha1.SecurityGroupPort) []datapath.SGEgressCidr {
	var out []datapath.SGEgressCidr
	if len(ports) == 0 {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			out = append(out, datapath.SGEgressCidr{SrcNet: srcNet, Proto: proto, Port: 0, CIDR: cidr, AllowedGroups: allowedSrc})
		}
		return out
	}
	for _, pp := range ports {
		proto, port, valid := compileSGPort(pp)
		if !valid {
			continue
		}
		out = append(out, datapath.SGEgressCidr{SrcNet: srcNet, Proto: proto, Port: port, CIDR: cidr, AllowedGroups: allowedSrc})
	}
	return out
}

// isAnyCIDR reports whether c is the all-addresses CIDR of either family, which
// takes the SG_WORLD pseudo-group path rather than the sg_cidr LPM.
func isAnyCIDR(c string) bool {
	return c == "0.0.0.0/0" || c == "::/0"
}

// compileCidrPorts expands a specific-CIDR ingress rule into sg_cidr entries for
// (net, proto, port) admitting the given destination group. No ports means
// every protocol and port (an any-port entry per protocol).
func compileCidrPorts(net_ uint32, cidr *net.IPNet, allowedGroups uint64, ports []sdnv1alpha1.SecurityGroupPort) []datapath.SGCidr {
	var out []datapath.SGCidr
	if len(ports) == 0 {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			out = append(out, datapath.SGCidr{Net: net_, Proto: proto, Port: 0, CIDR: cidr, AllowedGroups: allowedGroups})
		}
		return out
	}
	for _, pp := range ports {
		proto, port, valid := compileSGPort(pp)
		if !valid {
			continue
		}
		out = append(out, datapath.SGCidr{Net: net_, Proto: proto, Port: port, CIDR: cidr, AllowedGroups: allowedGroups})
	}
	return out
}

func watchServiceVIPs(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	svips := factory.Sdn().V1alpha1().ServiceVIPs()
	vpcs := factory.Sdn().V1alpha1().VPCs()

	var mu sync.Mutex
	apply := func() {
		mu.Lock()
		defer mu.Unlock()

		all, err := svips.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list servicevips", "err", err)
			return
		}
		entries, err := compileServiceVIPs(all, func(ref sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error) {
			return vpcs.Lister().VPCs(ref.Namespace).Get(ref.Name)
		}, log)
		if err != nil {
			log.Error("reject service VIP snapshot", "err", err)
			entries = nil
		}
		if err := mgr.SyncServiceVIPs(entries); err != nil {
			log.Error("sync service VIPs", "err", err)
			return
		}
	}

	resync := resyncAfterCacheSync(ctx, apply, svips.Informer().HasSynced, vpcs.Informer().HasSynced)
	_, _ = svips.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
	_, _ = vpcs.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	})
}

// normalizeBindAddr brackets a bare IPv6 host: "fd00::1:9411" -> "[fd00::1]:9411".
// The chart concatenates the node's primary InternalIP with ":9411", which does
// not parse when that address is v6, and the only symptom is a warn log and no
// metrics. Rewrites only when the host parses as an IP, so a malformed value is
// passed through rather than mangled.
func normalizeBindAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr // already well formed, brackets included
	}
	i := strings.LastIndex(addr, ":")
	if i <= 0 {
		return addr
	}
	host, port := addr[:i], addr[i+1:]
	if net.ParseIP(host) == nil {
		return addr
	}
	cand := "[" + host + "]:" + port
	if _, _, err := net.SplitHostPort(cand); err != nil {
		return addr
	}
	return cand
}

// serveMetrics exposes the per-VPC datapath traffic counters (#2) as Prometheus
// text on :9411/metrics, labeled by the owning VPC. Hand-rolled exposition (no
// client dependency), sharing a one-second snapshot of the PERCPU maps and VPC
// lister (net id -> VPC namespace/name).
type metricsReader interface {
	VPCCounters() (map[uint32]datapath.VPCCounter, error)
	MapMemlock() (map[string]uint64, error)
	SGDrops() (map[uint32]uint64, error)
	NPDrops() (map[uint8]uint64, error)
	HFDrops() (map[uint8]uint64, error)
}

func agentMetricsHandler(mgr metricsReader, vpcs sdnv1alpha1informers.VPCInformer, nodeName string, flows *flowPipeline) http.Handler {
	return cacheMetricsSnapshot(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		counters, err := mgr.VPCCounters()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// net id -> VPC identity, from the lister.
		names := map[uint32][2]string{}
		if all, err := vpcs.Lister().List(labels.Everything()); err == nil {
			for _, v := range all {
				if netid.ValidVNI(v.Status.VNI) {
					names[netid.VNI(v.Status.VNI)] = [2]string{v.Namespace, v.Name}
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

		// North-south metering (docs/north-south.md, #2): every crossing of a
		// VPC's boundary, attributed to the door it went through. This is the
		// number that was missing — a tenant could pull terabytes out through a
		// floating address or a LoadBalancer Service and nothing recorded it. The
		// `door` label is the point: it says which of the three mechanisms carried
		// the traffic, which is what makes the case for consolidating them.
		for _, m := range []struct {
			name, help string
			pick       func(datapath.VPCCounter, int, int) uint64
		}{
			{"cozyplane_vpc_ns_bytes_total", "Bytes crossing a VPC's north-south boundary",
				func(c datapath.VPCCounter, d, in int) uint64 { return c.NSBytes[d][in] }},
			{"cozyplane_vpc_ns_packets_total", "Packets crossing a VPC's north-south boundary",
				func(c datapath.VPCCounter, d, in int) uint64 { return c.NSPackets[d][in] }},
		} {
			fmt.Fprintf(&b, "# HELP %s %s (this node), by the door it used.\n# TYPE %s counter\n", m.name, m.help, m.name)
			for net, c := range counters {
				id := names[net]
				for door, doorName := range datapath.NSDoorNames {
					for in, dir := range []string{"out", "in"} {
						fmt.Fprintf(&b, "%s{vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q,door=%q,direction=%q} %d\n",
							m.name, net, id[0], id[1], nodeName, doorName, dir, m.pick(c, door, in))
					}
				}
			}
		}

		// Refused at the boundary — kept out of the byte meter above (a refused
		// packet did not cross), but an operator debugging "my LoadBalancer never
		// reaches the VPC" needs exactly this number.
		fmt.Fprintf(&b, "# HELP cozyplane_vpc_ns_denied_total Packets refused at a VPC's north-south boundary (this node).\n# TYPE cozyplane_vpc_ns_denied_total counter\n")
		for net, c := range counters {
			id := names[net]
			for door, doorName := range datapath.NSDoorNames {
				fmt.Fprintf(&b, "cozyplane_vpc_ns_denied_total{vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q,door=%q} %d\n",
					net, id[0], id[1], nodeName, doorName, c.NSDenied[door])
			}
		}

		// How much of the agent's memory cgroup each eBPF map is charging. Almost
		// all of the agent's memory IS its maps, not its heap — so RSS is a lie
		// here, and an operator watching container_memory_rss sees nothing wrong
		// right up until the OOM kill (the killer measures working_set, which
		// includes the kernel charge). This is the metric that makes that
		// debuggable: it names the map.
		if ml, err := mgr.MapMemlock(); err == nil {
			fmt.Fprintf(&b, "# HELP cozyplane_bpf_map_memlock_bytes Kernel memory an eBPF map charges to the agent's memory cgroup.\n# TYPE cozyplane_bpf_map_memlock_bytes gauge\n")
			var total uint64
			for name, bytes := range ml {
				total += bytes
				fmt.Fprintf(&b, "cozyplane_bpf_map_memlock_bytes{map=%q,node=%q} %d\n", name, nodeName, bytes)
			}
			fmt.Fprintf(&b, "# HELP cozyplane_bpf_map_memlock_bytes_total Kernel memory ALL eBPF maps charge to the agent's cgroup.\n# TYPE cozyplane_bpf_map_memlock_bytes_total gauge\n")
			fmt.Fprintf(&b, "cozyplane_bpf_map_memlock_bytes_total{node=%q} %d\n", nodeName, total)
		}

		// Security-group policy drops (#7), same per-VPC labeling.
		if drops, err := mgr.SGDrops(); err == nil {
			fmt.Fprintf(&b, "# HELP cozyplane_sg_drops_total Packets dropped by security-group policy (this node).\n# TYPE cozyplane_sg_drops_total counter\n")
			for net, d := range drops {
				id := names[net]
				fmt.Fprintf(&b, "cozyplane_sg_drops_total{vni=\"%d\",vpc_namespace=\"%s\",vpc=\"%s\",node=\"%s\"} %d\n",
					net, id[0], id[1], nodeName, d)
			}
		}

		// Default-net NetworkPolicy drops + compiler sync failures
		// (failed updates retain the enforcement guard and must be visible).
		if drops, err := mgr.NPDrops(); err == nil {
			fmt.Fprintf(&b, "# HELP cozyplane_np_drops_total Packets dropped by default-net NetworkPolicy (this node).\n# TYPE cozyplane_np_drops_total counter\n")
			dirs := map[uint8]string{datapath.NPDirIn: "ingress", datapath.NPDirEg: "egress"}
			for dir, d := range drops {
				fmt.Fprintf(&b, "cozyplane_np_drops_total{direction=\"%s\",node=\"%s\"} %d\n", dirs[dir], nodeName, d)
			}
		}
		fmt.Fprintf(&b, "# HELP cozyplane_np_sync_errors_total NetworkPolicy compiler sync failures (this node).\n# TYPE cozyplane_np_sync_errors_total counter\n")
		fmt.Fprintf(&b, "cozyplane_np_sync_errors_total{node=\"%s\"} %d\n", nodeName, npSyncErrors.Load())

		// Underlay claims (docs/bringup-field-notes.md §14). fabric_ips_missing
		// is the one to alert on: non-zero means pods on this node are
		// unreachable from every other node, which has no local symptom at all.
		fmt.Fprintf(&b, "# HELP cozyplane_fabric_ips_missing Pods on this node holding an address with no FabricIP claim (last heal pass).\n# TYPE cozyplane_fabric_ips_missing gauge\n")
		fmt.Fprintf(&b, "cozyplane_fabric_ips_missing{node=\"%s\"} %d\n", nodeName, fabricMissing.Load())
		fmt.Fprintf(&b, "# HELP cozyplane_fabric_ips_conflicted FabricIP claims wanted by a pod on this node but held by a different pod (last heal pass).\n# TYPE cozyplane_fabric_ips_conflicted gauge\n")
		fmt.Fprintf(&b, "cozyplane_fabric_ips_conflicted{node=\"%s\"} %d\n", nodeName, fabricConflict.Load())
		fmt.Fprintf(&b, "# HELP cozyplane_fabric_ips_healed_total FabricIP claims this agent re-created for a pod that already held the address.\n# TYPE cozyplane_fabric_ips_healed_total counter\n")
		fmt.Fprintf(&b, "cozyplane_fabric_ips_healed_total{node=\"%s\"} %d\n", nodeName, fabricHealed.Load())

		// Host firewall (docs/host-firewall.md), by direction.
		if drops, err := mgr.HFDrops(); err == nil {
			fmt.Fprintf(&b, "# HELP cozyplane_hf_drops_total Packets dropped by the host firewall (this node).\n# TYPE cozyplane_hf_drops_total counter\n")
			dirs := map[uint8]string{datapath.NPDirIn: "ingress", datapath.NPDirEg: "egress"}
			for dir, d := range drops {
				fmt.Fprintf(&b, "cozyplane_hf_drops_total{direction=\"%s\",node=\"%s\"} %d\n", dirs[dir], nodeName, d)
			}
		}
		fmt.Fprintf(&b, "# HELP cozyplane_hf_sync_errors_total HostFirewall compiler sync failures (this node).\n# TYPE cozyplane_hf_sync_errors_total counter\n")
		fmt.Fprintf(&b, "cozyplane_hf_sync_errors_total{node=\"%s\"} %d\n", nodeName, hfSyncErrors.Load())

		// Flow-derived series (docs/observability.md §5) — bounded cardinality,
		// no IP/port/pod labels; fine-grained identity lives in /flows.
		if flows != nil {
			flows.writeMetrics(&b, names)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	}))

}

func serveMetrics(ctx context.Context, mgr *datapath.Manager, vpcs sdnv1alpha1informers.VPCInformer, cfg *rest.Config, nodeName, addr string, secure bool, flows *flowPipeline, log *slog.Logger) {
	if addr == "" {
		return
	}
	addr = normalizeBindAddr(addr)
	mux := http.NewServeMux()
	mux.Handle("/metrics", agentMetricsHandler(mgr, vpcs, nodeName, flows))
	// Delegated authn/authz, failing CLOSED: if the filter cannot be built, no
	// metrics is strictly better than unauthenticated metrics on a hostNetwork
	// listener.
	var handler http.Handler = mux
	if secure {
		httpClient, err := rest.HTTPClientFor(cfg)
		if err != nil {
			log.Error("metrics auth: http client; endpoint stays off", "err", err)
			return
		}
		filter, err := metricsfilters.WithAuthenticationAndAuthorization(cfg, httpClient)
		if err != nil {
			log.Error("metrics auth: build filter; endpoint stays off", "err", err)
			return
		}
		if handler, err = filter(logr.FromSlogHandler(log.Handler()), mux); err != nil {
			log.Error("metrics auth: wrap handler; endpoint stays off", "err", err)
			return
		}
	} else {
		log.Warn("metrics served without authentication (--metrics-secure=false)")
	}

	srv := httpserver.New(addr, handler)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		log.Info("serving per-VPC metrics", "addr", addr+"/metrics")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warn("metrics server", "err", err)
		}
	}()
}
func compileSGPort(pp sdnv1alpha1.SecurityGroupPort) (uint8, uint16, bool) {
	if pp.Port < 0 || pp.Port > 65535 {
		return 0, 0, false
	}
	switch pp.Protocol {
	case "TCP":
		return unix.IPPROTO_TCP, uint16(pp.Port), true
	case "UDP":
		return unix.IPPROTO_UDP, uint16(pp.Port), true
	default:
		return 0, 0, false
	}
}
