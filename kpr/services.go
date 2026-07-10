// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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
//
// The reconcile is event-scoped: a workqueue keyed by service (an EndpointSlice
// event enqueues its owning service), each item recomputed alone, and an
// in-memory owned-keys index diffed against the previous state so a steady-state
// event costs O(that service's endpoints) — never a full-cluster rebuild or a
// full-map scan. The single full pass happens once at startup, to seed the index
// and sweep net-0 keys a previous kpr incarnation left behind (the pinned map
// outlives the process; a service deleted while kpr was down generates no event).

// svc_vips key/value, replicating the pinned map's layout from bpf/overlay.c
// (the commit-the-struct-shape contract, as with the socket-LB map adoption).
// Ports are network order, addresses the 16-byte NAT64 form (64:ff9b::a.b.c.d
// for v4), exactly as the agent writes them.

const svcMaxBackends = 16
const svcFAffinity uint32 = 1
const svcFSrcRanges uint32 = 2

// lbSrcKey replicates bpf/overlay.c's lb_src LPM key: loadBalancerSourceRanges
// admission, the frontend fully specified ahead of the client prefix.
// Prefixlen = 128 (LB IP) + client prefix bits; v4 addresses are the NAT64
// form, so a v4 /24 contributes 96+24 client bits.
type lbSrcKey struct {
	Prefixlen uint32
	Vip       [16]byte
	Client    [16]byte
}

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

// svcVal holds only fixed-size arrays, so it is comparable — the diff below
// relies on == to skip rewriting unchanged entries.
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

type vipReconciler struct {
	vips      *ebpf.Map
	svcLister corelisters.ServiceLister
	epsLister discoverylisters.EndpointSliceLister
	queue     workqueue.TypedRateLimitingInterface[string]
	logger    *slog.Logger
	// nodeName scopes the LB-ingress rows to this node's ready backends
	// (etp: Local as a per-node filter). Empty disables LB rows.
	nodeName string

	// owned indexes the net-0 keys this process wrote, per service ("ns/name" →
	// key → last-written value). It is what makes pruning scan-free: a service's
	// reconcile diffs desired against owned[svc] and never iterates the map.
	// Touched only by seed() and then the single worker goroutine — no lock.
	owned map[string]map[svcKey]svcVal

	// lbsrc is the pinned lb_src LPM (loadBalancerSourceRanges), ownedSrc its
	// per-service index — the same diff discipline as owned/vips.
	lbsrc    *ebpf.Map
	ownedSrc map[string]map[lbSrcKey]uint8

	// nodeAddrs are THIS node's InternalIP/ExternalIP addresses (both
	// families), the frontends for NodePort rows. Fetched once at startup —
	// node addresses effectively never change; a kpr restart re-reads them.
	nodeAddrs []net.IP
}

// runServiceVIPs reconciles Services + EndpointSlices into the pinned svc_vips
// map at net 0 until ctx is done. Runs alongside the LB hive; the two never
// write the same keys (this owns net 0, socket-LB uses Cilium's own maps).
// nodeName (the node this kpr instance runs on) scopes LB-ingress rows.
func runServiceVIPs(ctx context.Context, pinDir, nodeName string, logger *slog.Logger) error {
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

	// The lb_src LPM (loadBalancerSourceRanges) is pinned by the same agent
	// load; by the time svc_vips exists this does too.
	var lbsrc *ebpf.Map
	for {
		lbsrc, err = ebpf.LoadPinnedMap(filepath.Join(pinDir, "lb_src"), nil)
		if err == nil {
			break
		}
		logger.Info("waiting for agent lb_src pin", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	defer lbsrc.Close()

	// This node's addresses are the NodePort frontends. Fetched once —
	// node addresses effectively never change; a restart re-reads.
	var nodeAddrs []net.IP
	if nodeName != "" {
		node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get own node %s: %w", nodeName, err)
		}
		for _, a := range node.Status.Addresses {
			if a.Type != corev1.NodeInternalIP && a.Type != corev1.NodeExternalIP {
				continue
			}
			if ip := net.ParseIP(a.Address); ip != nil {
				nodeAddrs = append(nodeAddrs, ip)
			}
		}
	}

	factory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := factory.Core().V1().Services()
	epsInformer := factory.Discovery().V1().EndpointSlices()

	r := &vipReconciler{
		vips:      vips,
		svcLister: svcInformer.Lister(),
		epsLister: epsInformer.Lister(),
		queue: workqueue.NewTypedRateLimitingQueue(
			workqueue.DefaultTypedControllerRateLimiter[string]()),
		logger:    logger,
		nodeName:  nodeName,
		owned:     map[string]map[svcKey]svcVal{},
		lbsrc:     lbsrc,
		ownedSrc:  map[string]map[lbSrcKey]uint8{},
		nodeAddrs: nodeAddrs,
	}

	_, _ = svcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.enqueueService,
		UpdateFunc: func(_, obj any) { r.enqueueService(obj) },
		DeleteFunc: r.enqueueService,
	})
	_, _ = epsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.enqueueSliceOwner,
		UpdateFunc: func(_, obj any) { r.enqueueSliceOwner(obj) },
		DeleteFunc: r.enqueueSliceOwner,
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), svcInformer.Informer().HasSynced, epsInformer.Informer().HasSynced) {
		return fmt.Errorf("informer cache failed to sync")
	}

	// One-time full pass before the worker starts: seed the owned index and
	// sweep leftovers. Events that raced in during it sit in the queue and are
	// simply re-reconciled (idempotent).
	if err := r.seed(); err != nil {
		return fmt.Errorf("seed svc_vips: %w", err)
	}
	logger.Info("net-0 ClusterIP svc_vips reconciler running", "pin", pin, "services", len(r.owned))

	go func() {
		<-ctx.Done()
		r.queue.ShutDown()
	}()
	r.runWorker()
	return nil
}

// enqueueService queues a Service object (or its deletion tombstone) by key.
func (r *vipReconciler) enqueueService(obj any) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	r.queue.Add(key)
}

// enqueueSliceOwner queues the Service that owns an EndpointSlice event.
func (r *vipReconciler) enqueueSliceOwner(obj any) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return
	}
	svc := es.Labels[discoveryv1.LabelServiceName]
	if svc == "" {
		return
	}
	r.queue.Add(es.Namespace + "/" + svc)
}

// runWorker drains the queue until shutdown. A single worker: map writes are
// cheap, and one writer keeps the owned index lock-free.
func (r *vipReconciler) runWorker() {
	for {
		key, shutdown := r.queue.Get()
		if shutdown {
			return
		}
		err := r.reconcileService(key)
		r.queue.Done(key)
		if err != nil {
			r.logger.Error("reconcile service", "service", key, "err", err)
			r.queue.AddRateLimited(key)
			continue
		}
		r.queue.Forget(key)
	}
}

// reconcileService recomputes one service's desired net-0 entries and applies
// the delta against what this process last wrote for it.
func (r *vipReconciler) reconcileService(key string) error {
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	svc, err := r.svcLister.Services(ns).Get(name)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	desired, desiredSrc, err := r.computeService(svc)
	if err != nil {
		return err
	}
	return r.apply(key, desired, desiredSrc)
}

// apply writes desired-minus-owned and deletes owned-minus-desired, then
// records desired as owned — for the svc_vips rows and the lb_src LPM alike.
// Unchanged entries (value-equal) are not rewritten.
func (r *vipReconciler) apply(key string, desired map[svcKey]svcVal, desiredSrc map[lbSrcKey]uint8) error {
	prev := r.owned[key]
	for k, v := range desired {
		if pv, ok := prev[k]; ok && pv == v {
			continue
		}
		if err := r.vips.Put(&k, &v); err != nil {
			return fmt.Errorf("put svc_vips %v: %w", k, err)
		}
	}
	for k := range prev {
		if _, ok := desired[k]; ok {
			continue
		}
		if err := r.vips.Delete(&k); err != nil && !isMapKeyNotExist(err) {
			return fmt.Errorf("delete svc_vips %v: %w", k, err)
		}
	}
	if len(desired) == 0 {
		delete(r.owned, key)
	} else {
		r.owned[key] = desired
	}

	prevSrc := r.ownedSrc[key]
	for k, v := range desiredSrc {
		if pv, ok := prevSrc[k]; ok && pv == v {
			continue
		}
		if err := r.lbsrc.Put(&k, &v); err != nil {
			return fmt.Errorf("put lb_src %v: %w", k, err)
		}
	}
	for k := range prevSrc {
		if _, ok := desiredSrc[k]; ok {
			continue
		}
		if err := r.lbsrc.Delete(&k); err != nil && !isMapKeyNotExist(err) {
			return fmt.Errorf("delete lb_src %v: %w", k, err)
		}
	}
	if len(desiredSrc) == 0 {
		delete(r.ownedSrc, key)
	} else {
		r.ownedSrc[key] = desiredSrc
	}
	return nil
}

func isMapKeyNotExist(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

// computeService builds the desired net-0 svc_vips entries for one service.
// A nil svc (deleted), ExternalName, headless, or backend-less service yields
// an empty set — apply() then prunes whatever was owned.
func (r *vipReconciler) computeService(svc *corev1.Service) (map[svcKey]svcVal, map[lbSrcKey]uint8, error) {
	if svc == nil || svc.Spec.Type == corev1.ServiceTypeExternalName {
		return nil, nil, nil
	}
	sel := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: svc.Name})
	slices, err := r.epsLister.EndpointSlices(svc.Namespace).List(sel)
	if err != nil {
		return nil, nil, err
	}
	rows, srcs := computeRows(svc, slices, r.nodeName, r.nodeAddrs)
	return rows, srcs, nil
}

type bucketKey struct {
	v4       bool
	portName string
}

// computeRows derives the map rows from a Service and its EndpointSlices:
// ClusterIP rows (cluster-wide ready backends — the per-packet fallback for
// clients socket-LB can't rewrite) and, for a LoadBalancer Service, LB-ingress
// rows keyed by the Service's status ingress IPs whose backend set is THIS
// node's ready endpoints only (docs/lb-ingress.md).
//
// Single pass over the EndpointSlices: ready endpoints are bucketed by
// {address family, port name}, cluster-wide and node-local in parallel, then
// each (servicePort × address) picks its bucket — no per-port re-walk.
func computeRows(svc *corev1.Service, slices []*discoveryv1.EndpointSlice, nodeName string, nodeAddrs []net.IP) (map[svcKey]svcVal, map[lbSrcKey]uint8) {
	buckets := map[bucketKey][]svcBackend{}
	local := map[bucketKey][]svcBackend{}
	add := func(m map[bucketKey][]svcBackend, bk bucketKey, be svcBackend) {
		if len(m[bk]) < svcMaxBackends {
			m[bk] = append(m[bk], be)
		}
	}
	for _, es := range slices {
		var v4 bool
		switch es.AddressType {
		case discoveryv1.AddressTypeIPv4:
			v4 = true
		case discoveryv1.AddressTypeIPv6:
			v4 = false
		default:
			continue // FQDN slices carry no addresses we can NAT to
		}
		for _, ep := range es.Ports {
			if ep.Port == nil {
				continue
			}
			pname := ""
			if ep.Name != nil {
				pname = *ep.Name
			}
			bk := bucketKey{v4: v4, portName: pname}
			tport := htons(uint16(*ep.Port))
			for _, e := range es.Endpoints {
				if e.Conditions.Ready != nil && !*e.Conditions.Ready {
					continue
				}
				isLocal := nodeName != "" && e.NodeName != nil && *e.NodeName == nodeName
				for _, addrStr := range e.Addresses {
					ip := net.ParseIP(addrStr)
					if ip == nil {
						continue
					}
					a, ok := addr128(ip)
					if !ok {
						continue
					}
					add(buckets, bk, svcBackend{IP: a, Port: tport})
					if isLocal {
						add(local, bk, svcBackend{IP: a, Port: tport})
					}
				}
			}
		}
	}

	affinity := svc.Spec.SessionAffinity == corev1.ServiceAffinityClientIP
	mkVal := func(be []svcBackend) svcVal {
		var v svcVal
		v.N = uint32(len(be))
		copy(v.Be[:], be)
		if affinity {
			v.Flags = svcFAffinity
		}
		return v
	}

	clusterIPs := svc.Spec.ClusterIPs
	if len(clusterIPs) == 0 && svc.Spec.ClusterIP != "" {
		clusterIPs = []string{svc.Spec.ClusterIP}
	}
	desired := map[svcKey]svcVal{}
	for _, sp := range svc.Spec.Ports {
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
			be := buckets[bucketKey{v4: cip.To4() != nil, portName: sp.Name}]
			if len(be) == 0 {
				continue // no ready endpoints: leave it unresolved (svc_forward SVC_MISS)
			}
			desired[svcKey{Net: 0, Vip: vip, Proto: proto, Port: htons(uint16(sp.Port))}] = mkVal(be)
		}
	}

	// LoadBalancer ingress rows (docs/lb-ingress.md): traffic for a status
	// ingress IP that reaches THIS node is DNAT'd at from_uplink to node-local
	// ready backends — externalTrafficPolicy: Local as a per-node table filter,
	// the client source preserved by the datapath. Only Local is served
	// (Cluster needs an ingress-point client SNAT — deferred); ipMode Proxy
	// means the LB terminates and proxies — no interception. Whoever wrote the
	// status (a CCM, MetalLB, a human) is the provider; cozyplane only reads.
	desiredSrc := map[lbSrcKey]uint8{}
	local2 := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer && local2 {
		// loadBalancerSourceRanges: parsed once; applied to every VIP-mode
		// ingress IP as lb_src LPM entries + the flag on the rows. LB rows
		// only, matching upstream (NodePort traffic is not range-filtered).
		type srcRange struct {
			a    [16]byte
			bits uint32
		}
		var ranges []srcRange
		for _, cidr := range svc.Spec.LoadBalancerSourceRanges {
			_, ipn, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				continue // invalid ranges are ignored, like kube-proxy
			}
			a, ok := addr128(ipn.IP)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			bits := uint32(ones)
			if ipn.IP.To4() != nil {
				bits += 96 // NAT64 form: the v4 bits sit behind the /96 prefix
			}
			ranges = append(ranges, srcRange{a: a, bits: bits})
		}
		var flags uint32
		if len(svc.Spec.LoadBalancerSourceRanges) > 0 {
			flags = svcFSrcRanges
		}
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ing.IP == "" || (ing.IPMode != nil && *ing.IPMode == corev1.LoadBalancerIPModeProxy) {
				continue
			}
			lbIP := net.ParseIP(ing.IP)
			if lbIP == nil {
				continue
			}
			lb128, ok := addr128(lbIP)
			if !ok {
				continue
			}
			wrote := false
			for _, sp := range svc.Spec.Ports {
				proto, ok := protoNum(sp.Protocol)
				if !ok {
					continue
				}
				be := local[bucketKey{v4: lbIP.To4() != nil, portName: sp.Name}]
				if len(be) == 0 {
					continue // no local ready backend: no row — Local's contract
				}
				v := mkVal(be)
				v.Flags |= flags
				desired[svcKey{Net: 0, Vip: lb128, Proto: proto, Port: htons(uint16(sp.Port))}] = v
				wrote = true
			}
			if wrote {
				for _, sr := range ranges {
					desiredSrc[lbSrcKey{Prefixlen: 128 + sr.bits, Vip: lb128, Client: sr.a}] = 1
				}
			}
		}
	}

	// External NodePort (docs/lb-ingress.md): the same rows with this node's
	// own addresses as the frontends — type NodePort and LoadBalancer alike,
	// Local only, no range filter, same datapath.
	if local2 && (svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer) {
		for _, sp := range svc.Spec.Ports {
			if sp.NodePort == 0 {
				continue
			}
			proto, ok := protoNum(sp.Protocol)
			if !ok {
				continue
			}
			for _, na := range nodeAddrs {
				na128, ok := addr128(na)
				if !ok {
					continue
				}
				be := local[bucketKey{v4: na.To4() != nil, portName: sp.Name}]
				if len(be) == 0 {
					continue
				}
				desired[svcKey{Net: 0, Vip: na128, Proto: proto, Port: htons(uint16(sp.NodePort))}] = mkVal(be)
			}
		}
	}
	return desired, desiredSrc
}

// seed runs once at startup, before the worker: computes every service, applies
// it (seeding the owned index), then sweeps net-0 keys in the pinned map that no
// current service owns — leftovers of a previous kpr incarnation (the map
// outlives the process, and a service deleted while kpr was down produces no
// event to prune it by).
func (r *vipReconciler) seed() error {
	services, err := r.svcLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, s := range services {
		key := s.Namespace + "/" + s.Name
		desired, desiredSrc, err := r.computeService(s)
		if err != nil {
			return err
		}
		if err := r.apply(key, desired, desiredSrc); err != nil {
			return err
		}
	}

	live := map[svcKey]bool{}
	for _, keys := range r.owned {
		for k := range keys {
			live[k] = true
		}
	}
	var key svcKey
	var val svcVal
	var stale []svcKey
	it := r.vips.Iterate()
	for it.Next(&key, &val) {
		if key.Net != 0 {
			continue // VPC ServiceVIPs — the agent's territory
		}
		if !live[key] {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate svc_vips: %w", err)
	}
	for _, k := range stale {
		if err := r.vips.Delete(&k); err != nil && !isMapKeyNotExist(err) {
			return fmt.Errorf("sweep svc_vips %v: %w", k, err)
		}
	}
	if len(stale) > 0 {
		r.logger.Info("swept stale net-0 svc_vips entries", "count", len(stale))
	}

	// The same leftover sweep for the lb_src LPM (it is exclusively ours).
	liveSrc := map[lbSrcKey]bool{}
	for _, keys := range r.ownedSrc {
		for k := range keys {
			liveSrc[k] = true
		}
	}
	var skey lbSrcKey
	var sval uint8
	var staleSrc []lbSrcKey
	sit := r.lbsrc.Iterate()
	for sit.Next(&skey, &sval) {
		if !liveSrc[skey] {
			staleSrc = append(staleSrc, skey)
		}
	}
	if err := sit.Err(); err != nil {
		return fmt.Errorf("iterate lb_src: %w", err)
	}
	for _, k := range staleSrc {
		if err := r.lbsrc.Delete(&k); err != nil && !isMapKeyNotExist(err) {
			return fmt.Errorf("sweep lb_src %v: %w", k, err)
		}
	}
	if len(staleSrc) > 0 {
		r.logger.Info("swept stale lb_src entries", "count", len(staleSrc))
	}
	return nil
}
