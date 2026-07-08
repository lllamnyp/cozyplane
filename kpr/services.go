// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// This is KPR increment 3, Half A (docs/kube-proxy-replacement.md): socket-LB
// (increments 1-2) rewrites a pod's or host's connect() to a ClusterIP, but a
// bridge-bound KubeVirt guest emits raw ethernet with no host-socket traversal,
// so it never gets socket-LB'd — the day kube-proxy is removed a default-network
// VM loses ClusterIP access. cozyplane's from_pod already has the per-packet DNAT
// (svc_forward + the svc_vips/svc_fwd/svc_rev maps, built for VPC ServiceVIPs);
// increment 3 un-gates it for net 0. This reconciler is the net-0 feed: it
// projects Kubernetes Services + EndpointSlices into the agent-pinned svc_vips
// map at net 0, the default-network ClusterIP table.
//
// Ownership is partitioned by net: the agent's SyncServiceVIPs owns net != 0
// (VPC ServiceVIPs) and does not prune net-0 keys; this owns net 0. One map, one
// DNAT path, no double-write. It watches Services/EndpointSlices directly rather
// than reading Cilium's StateDB tables — a self-contained boundary with no
// coupling to Cilium's internal LB schema.

// svc_vips key/value, replicating the pinned map's layout from bpf/overlay.c
// (the commit-the-struct-shape contract, as with the socket-LB map adoption).
// Ports are network order, addresses the 16-byte NAT64 form (64:ff9b::a.b.c.d
// for v4), exactly as the agent writes them.

const svcMaxBackends = 16
const svcFAffinity uint32 = 1

type svcKey struct {
	Net   uint32
	Vip   [16]byte
	Proto uint8
	Pad   uint8
	Port  uint16 // network order
}

type svcBackend struct {
	IP   [16]byte
	Port uint16 // network order
	Pad  uint16
}

type svcVal struct {
	N     uint32
	Flags uint32
	Be    [svcMaxBackends]svcBackend
}

func htons(x uint16) uint16 { return (x << 8) | (x >> 8) }

// addr128 is the 16-byte map form: RFC 6052 NAT64 (64:ff9b::a.b.c.d) for v4, the
// address itself for v6 — matching datapath.addr128 (internals.md invariant 2).
func addr128(ip net.IP) ([16]byte, bool) {
	var a [16]byte
	if v4 := ip.To4(); v4 != nil {
		a[1], a[2], a[3] = 0x64, 0xff, 0x9b
		copy(a[12:], v4)
		return a, true
	}
	if v6 := ip.To16(); v6 != nil {
		copy(a[:], v6)
		return a, true
	}
	return a, false
}

func protoNum(p corev1.Protocol) (uint8, bool) {
	switch p {
	case corev1.ProtocolTCP:
		return 6, true
	case corev1.ProtocolUDP:
		return 17, true
	default:
		return 0, false // SCTP and the rest are out of scope
	}
}

// runServiceVIPs reconciles Services + EndpointSlices into the pinned svc_vips
// map at net 0 until ctx is done. Runs alongside the LB hive; the two never
// write the same keys (this owns net 0, socket-LB uses Cilium's own maps).
func runServiceVIPs(ctx context.Context, pinDir string, logger *slog.Logger) error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kube client: %w", err)
	}

	// The agent creates and pins svc_vips; wait for the pin so a kpr that starts
	// first doesn't fail — the agent (the CNI) is always coming up alongside.
	pin := filepath.Join(pinDir, "svc_vips")
	var vips *ebpf.Map
	for {
		vips, err = ebpf.LoadPinnedMap(pin, nil)
		if err == nil {
			break
		}
		logger.Info("waiting for agent svc_vips pin", "path", pin, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	defer vips.Close()

	factory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := factory.Core().V1().Services()
	epsInformer := factory.Discovery().V1().EndpointSlices()

	var pending bool
	resync := func() {
		if err := reconcileServiceVIPs(vips, svcInformer.Lister(), epsInformer.Lister()); err != nil {
			logger.Error("reconcile svc_vips", "err", err)
			pending = true
			return
		}
		pending = false
	}
	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = svcInformer.Informer().AddEventHandler(onAny)
	_, _ = epsInformer.Informer().AddEventHandler(onAny)

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), svcInformer.Informer().HasSynced, epsInformer.Informer().HasSynced) {
		return fmt.Errorf("informer cache failed to sync")
	}
	resync()
	logger.Info("net-0 ClusterIP svc_vips reconciler running", "pin", pin)

	// A retry tick catches a transient map-write failure without waiting for the
	// next Service/EndpointSlice event.
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if pending {
				resync()
			}
		}
	}
}

// reconcileServiceVIPs makes the net-0 entries of svc_vips exactly the current
// Service/EndpointSlice state (full-state diff, pruning stale net-0 keys).
func reconcileServiceVIPs(vips *ebpf.Map, svcLister corelisters.ServiceLister, epsLister discoverylisters.EndpointSliceLister) error {
	services, err := svcLister.List(labels.Everything())
	if err != nil {
		return err
	}
	slices, err := epsLister.List(labels.Everything())
	if err != nil {
		return err
	}

	// Index EndpointSlices by their owning Service (namespace/name).
	byService := map[string][]*discoveryv1.EndpointSlice{}
	for _, es := range slices {
		svc := es.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue
		}
		key := es.Namespace + "/" + svc
		byService[key] = append(byService[key], es)
	}

	want := map[svcKey]svcVal{}
	for _, s := range services {
		if s.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		clusterIPs := s.Spec.ClusterIPs
		if len(clusterIPs) == 0 && s.Spec.ClusterIP != "" {
			clusterIPs = []string{s.Spec.ClusterIP}
		}
		affinity := s.Spec.SessionAffinity == corev1.ServiceAffinityClientIP
		ess := byService[s.Namespace+"/"+s.Name]

		for _, sp := range s.Spec.Ports {
			proto, ok := protoNum(sp.Protocol)
			if !ok {
				continue
			}
			for _, cipStr := range clusterIPs {
				cip := net.ParseIP(cipStr)
				if cip == nil || cipStr == corev1.ClusterIPNone {
					continue
				}
				vip, ok := addr128(cip)
				if !ok {
					continue
				}
				be := collectBackends(ess, sp, cip)
				if len(be) == 0 {
					continue // no ready endpoints: leave it unresolved (svc_forward SVC_MISS)
				}
				key := svcKey{Net: 0, Vip: vip, Proto: proto, Port: htons(uint16(sp.Port))}
				var val svcVal
				val.N = uint32(len(be))
				copy(val.Be[:], be)
				if affinity {
					val.Flags = svcFAffinity
				}
				want[key] = val
			}
		}
	}

	// Write desired, then prune stale net-0 keys. Only net 0 is ours.
	for k, v := range want {
		if err := vips.Put(&k, &v); err != nil {
			return fmt.Errorf("put svc_vips %v: %w", k, err)
		}
	}
	var key svcKey
	var val svcVal
	var stale []svcKey
	it := vips.Iterate()
	for it.Next(&key, &val) {
		if key.Net != 0 {
			continue // VPC ServiceVIPs — the agent's territory
		}
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate svc_vips: %w", err)
	}
	for _, k := range stale {
		if err := vips.Delete(&k); err != nil {
			return fmt.Errorf("delete svc_vips %v: %w", k, err)
		}
	}
	return nil
}

// collectBackends resolves the ready backend {IP, targetPort} pairs for one
// service port and ClusterIP family, from the service's EndpointSlices.
func collectBackends(ess []*discoveryv1.EndpointSlice, sp corev1.ServicePort, cip net.IP) []svcBackend {
	wantV4 := cip.To4() != nil
	var out []svcBackend
	for _, es := range ess {
		if (es.AddressType == discoveryv1.AddressTypeIPv4) != wantV4 {
			continue // match the ClusterIP's family
		}
		// The endpoint port for this service port (matched by name; a single
		// unnamed port has an empty name on both sides).
		var tport int32 = -1
		for _, ep := range es.Ports {
			name := ""
			if ep.Name != nil {
				name = *ep.Name
			}
			if name == sp.Name && ep.Port != nil {
				tport = *ep.Port
				break
			}
		}
		if tport < 0 {
			continue
		}
		for _, e := range es.Endpoints {
			if e.Conditions.Ready != nil && !*e.Conditions.Ready {
				continue
			}
			for _, addrStr := range e.Addresses {
				ip := net.ParseIP(addrStr)
				if ip == nil {
					continue
				}
				a, ok := addr128(ip)
				if !ok {
					continue
				}
				out = append(out, svcBackend{IP: a, Port: htons(uint16(tport))})
				if len(out) >= svcMaxBackends {
					return out
				}
			}
		}
	}
	return out
}
