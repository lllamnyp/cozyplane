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
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	corev1 "k8s.io/api/core/v1"
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
		nodeName    = os.Getenv("NODE_NAME")
		mtu         int
		vni         uint
		cniConfName string
		genevePort  uint
		clusterCIDR string
	)
	flag.IntVar(&mtu, "mtu", 1450, "pod MTU (underlay MTU minus Geneve overhead)")
	flag.UintVar(&vni, "vni", uint(datapath.DefaultVNI), "VNI for the default network")
	flag.StringVar(&cniConfName, "cni-conf-name", defaultCNIConfFile,
		"filename for the CNI conflist in /etc/cni/net.d (lower sorts first, winning over other CNIs)")
	flag.UintVar(&genevePort, "geneve-port", datapath.GenevePort,
		"Geneve UDP destination port (use a non-default port to coexist with another overlay on 6081)")
	flag.StringVar(&clusterCIDR, "cluster-cidr", "",
		"cluster pod supernet; when set, pod traffic leaving it is masqueraded to the node address (pod egress to the outside)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if nodeName == "" {
		log.Error("NODE_NAME must be set (downward API)")
		os.Exit(1)
	}

	if err := run(nodeName, mtu, uint32(vni), cniConfName, uint16(genevePort), clusterCIDR, log); err != nil {
		log.Error("agent failed", "err", err)
		os.Exit(1)
	}
}

func run(nodeName string, mtu int, vni uint32, cniConfName string, genevePort uint16, clusterCIDR string, log *slog.Logger) error {
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
	if err := datapath.EnsureForwardRules(); err != nil {
		return fmt.Errorf("ensure forward rules: %w", err)
	}
	if err := datapath.EnsureBridgeChain(); err != nil {
		return fmt.Errorf("ensure bridge chain: %w", err)
	}
	uplink, err := mgr.AttachUplink()
	if err != nil {
		return fmt.Errorf("attach uplink: %w", err)
	}
	if clusterCIDR != "" {
		if err := datapath.EnsureMasquerade(clusterCIDR, uplink); err != nil {
			return fmt.Errorf("ensure masquerade: %w", err)
		}
	}
	log.Info("datapath loaded", "vni", vni, "geneve", datapath.GeneveDevice, "uplink", uplink)

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
	state := &datapath.AgentState{
		NodeName:  nodeName,
		NodeIP:    internalIP(self),
		PodCIDR:   podCIDR,
		MTU:       mtu,
		Namespace: os.Getenv("AGENT_NAMESPACE"), // gates gateway-attach to the system namespace
	}
	if err := state.Save(); err != nil {
		return fmt.Errorf("publish agent state: %w", err)
	}
	if err := datapath.WritePluginKubeconfig(); err != nil {
		log.Warn("write plugin kubeconfig (VPC attachment unavailable)", "err", err)
	}
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
		watchPorts(ctx, factory, client, mgr, nodeName, log)
		watchPeerings(ctx, factory, mgr, log)
		watchGateways(ctx, factory, mgr, nodeName, log)
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
		if err := mgr.SetRemote(node.Spec.PodCIDR, net.ParseIP(ip)); err != nil {
			log.Error("set remote", "node", node.Name, "err", err)
			return
		}
		log.Info("remote set", "node", node.Name, "podCIDR", node.Spec.PodCIDR, "nodeIP", ip)
	}

	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			node, ok := obj.(*corev1.Node)
			if !ok || node.Name == selfName || node.Spec.PodCIDR == "" {
				return
			}
			if err := mgr.DelRemote(node.Spec.PodCIDR); err != nil {
				log.Error("del remote", "node", node.Name, "err", err)
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
		if err := mgr.SetNetwork(vpc.Spec.CIDRs[0], uint32(vpc.Status.VNI)); err != nil {
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
			if !ok || len(vpc.Spec.CIDRs) == 0 {
				return
			}
			if err := mgr.DelNetwork(vpc.Spec.CIDRs[0]); err != nil {
				log.Error("del network", "vpc", vpc.Name, "err", err)
			}
		},
	})
}

// watchPorts mirrors remote VPC ports (pods on other nodes) into the remotes
// map as /32 routes to their node's Geneve endpoint, and severs a *local* pod's
// datapath when its Port is reaped out from under it (revocation). Best-effort,
// like watchVPCs.
func watchPorts(ctx context.Context, factory sdninformers.SharedInformerFactory, core kubernetes.Interface, mgr *datapath.Manager, selfName string, log *slog.Logger) {
	informer := factory.Sdn().V1alpha1().Ports().Informer()

	apply := func(obj any) {
		port, ok := obj.(*sdnv1alpha1.Port)
		if !ok || port.Spec.Node == selfName || port.Spec.IP == "" || port.Spec.NodeIP == "" {
			return // local ports are reached directly; skip incomplete ones
		}
		if err := mgr.SetRemote(port.Spec.IP+"/32", net.ParseIP(port.Spec.NodeIP)); err != nil {
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
			if port.Spec.Node == selfName {
				severLocalPort(ctx, core, port, log)
				return
			}
			if err := mgr.DelRemote(port.Spec.IP + "/32"); err != nil {
				log.Error("del remote port", "port", port.Name, "err", err)
			}
		},
	})
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
		vni := func(namespace, name string) (uint32, bool) {
			vpc, err := vpcs.Lister().VPCs(namespace).Get(name)
			if err != nil || vpc.Status.VNI == 0 {
				return 0, false
			}
			return uint32(vpc.Status.VNI), true
		}
		desired := desiredPeerPairs(all, vni)

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

// desiredPeerPairs computes the normalized (low, high) VNI pairs that should be
// programmed: one per pair of mutually-matched peering halves whose local and
// peer VPCs both have assigned VNIs.
func desiredPeerPairs(peerings []*sdnv1alpha1.VPCPeering, vni func(namespace, name string) (uint32, bool)) map[[2]uint32]bool {
	desired := map[[2]uint32]bool{}
	for _, p := range peerings {
		a, ok := vni(p.Namespace, p.Spec.VPCRef.Name)
		if !ok {
			continue
		}
		b, ok := vni(p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name)
		if !ok {
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
		if a > b {
			a, b = b, a
		}
		desired[[2]uint32{a, b}] = true
	}
	return desired
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
	severed, err := datapath.SeverLocal(net.ParseIP(port.Spec.IP), port.Spec.FabricIP)
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
