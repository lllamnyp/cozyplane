package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/lllamnyp/cozyplane/pkg/netid"
	"log/slog"
	"net"
	"os"
	"reflect"
	"slices"
	"sync"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/pkg/boundaryidentity"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
)

// Compilation uses identities, never infers ownership from a peer CIDR.
func compileBoundaries(vpcs []*sdn.VPC, ports []*sdn.Port) ([]datapath.Boundary, []uint32, []datapath.PrimaryPort, error) {
	byRef := map[sdn.VPCRef]*sdn.VPC{}
	var known []uint32
	for _, v := range vpcs {
		vni := v.Status.VNI
		if vni != 0 && !netid.ValidVNI(vni) {
			return nil, nil, nil, fmt.Errorf("invalid VPC VNI")
		}
		if netid.ValidVNI(vni) {
			byRef[sdn.VPCRef{Namespace: v.Namespace, Name: v.Name}] = v
			known = append(known, netid.VNI(vni))
		}
	}
	out := []datapath.Boundary{}
	for _, v := range vpcs {
		vni := v.Status.VNI
		if !netid.ValidVNI(vni) || v.Spec.Boundary == nil {
			continue
		}
		if v.Spec.Boundary.Revision < 1 {
			return nil, nil, nil, fmt.Errorf("invalid boundary revision")
		}
		policyIdentity, _ := json.Marshal(struct {
			UID    string
			CIDRs  []string
			Policy *sdn.VPCBoundary
		}{string(v.UID), v.Spec.CIDRs, v.Spec.Boundary})
		identity := sha256.Sum256(policyIdentity)
		id := binary.LittleEndian.Uint64(identity[:8])
		if id == 0 {
			id = 1
		}
		b := datapath.Boundary{Net: netid.VNI(vni), Identity: id, Revision: uint64(v.Spec.Boundary.Revision), Internet: v.Spec.Boundary.Internet}
		for _, c := range v.Spec.CIDRs {
			_, cidr, err := net.ParseCIDR(c)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("invalid VPC CIDR")
			}
			b.CIDRs = append(b.CIDRs, cidr)
		}
		for _, r := range v.Spec.Boundary.Peers {
			peer := byRef[r.PeerRef]
			if peer == nil {
				return nil, nil, nil, fmt.Errorf("boundary peer not realized")
			}
			peerVNI := peer.Status.VNI
			if !netid.ValidVNI(peerVNI) {
				return nil, nil, nil, fmt.Errorf("boundary peer not realized")
			}
			if peer == v || sdn.CIDRsOverlap(v.Spec.CIDRs, peer.Spec.CIDRs) {
				return nil, nil, nil, fmt.Errorf("invalid boundary peer address space")
			}
			if r.Direction != "ingress" && r.Direction != "egress" {
				return nil, nil, nil, fmt.Errorf("invalid boundary direction")
			}
			base := datapath.BoundaryRule{Peer: netid.VNI(peerVNI), Ingress: r.Direction == "ingress"}
			switch r.Protocol {
			case "TCP", "UDP":
				if len(r.Ports) == 0 || len(r.Ports) > 32 || r.ICMPType != nil || r.ICMPCode != nil {
					return nil, nil, nil, fmt.Errorf("invalid boundary ports")
				}
				base.Protocol = 6
				if r.Protocol == "UDP" {
					base.Protocol = 17
				}
				for _, p := range r.Ports {
					if p < 1 || p > 65535 {
						return nil, nil, nil, fmt.Errorf("invalid boundary port")
					}
					base.Port = uint16(p)
					b.Rules = append(b.Rules, base)
				}
			case "ICMP":
				if len(r.Ports) > 0 || r.ICMPType == nil || r.ICMPCode == nil {
					return nil, nil, nil, fmt.Errorf("invalid boundary ICMP")
				}
				icmpType, icmpCode := *r.ICMPType, *r.ICMPCode
				if icmpType < 0 || icmpType > 255 || icmpCode < 0 || icmpCode > 255 {
					return nil, nil, nil, fmt.Errorf("invalid boundary ICMP")
				}
				base.Port = uint16(icmpType)<<8 | uint16(icmpCode)
				base.Protocol = 1
				b.Rules = append(b.Rules, base)
				base.Protocol = 58
				b.Rules = append(b.Rules, base)
			default:
				return nil, nil, nil, fmt.Errorf("unsupported boundary protocol")
			}
		}
		out = append(out, b)
	}
	prim := []datapath.PrimaryPort{}
	for _, p := range ports {
		v := byRef[p.Spec.VPCRef]
		if v == nil || !p.Spec.Primary || p.DeletionTimestamp != nil {
			continue
		}
		vni := v.Status.VNI
		if !netid.ValidVNI(vni) {
			return nil, nil, nil, fmt.Errorf("primary VPC not realized")
		}
		ip := net.ParseIP(p.Spec.IP)
		if ip == nil {
			return nil, nil, nil, fmt.Errorf("invalid primary Port address")
		}
		prim = append(prim, datapath.PrimaryPort{Net: netid.VNI(vni), IP: ip})
	}
	return out, known, prim, nil
}

func desiredPeerNetworks(links []peerLink) []datapath.PeerNet {
	var networks []datapath.PeerNet
	for _, l := range links {
		for _, cidr := range l.cidrsB {
			networks = append(networks, datapath.PeerNet{Scope: l.a, CIDR: cidr, Net: l.b})
		}
		for _, cidr := range l.cidrsA {
			networks = append(networks, datapath.PeerNet{Scope: l.b, CIDR: cidr, Net: l.a})
		}
	}
	return networks
}

var peerSyncMu sync.Mutex

// Policy and transport acknowledgements use the same transport writer.
func syncPeerTransport(mgr *datapath.Manager, links []peerLink) error {
	peerSyncMu.Lock()
	defer peerSyncMu.Unlock()
	want := map[[2]uint32]bool{}
	networks := desiredPeerNetworks(links)
	for _, l := range links {
		want[[2]uint32{l.a, l.b}] = true
	}
	if len(want) > 2048 {
		return fmt.Errorf("peering map capacity exceeded")
	}
	current, err := mgr.Peers()
	if err != nil {
		return err
	}
	for p := range current {
		if !want[p] {
			if err := mgr.DelPeer(p[0], p[1]); err != nil {
				return err
			}
		}
	}
	for p := range want {
		if !current[p] {
			if err := mgr.SetPeer(p[0], p[1]); err != nil {
				return err
			}
		}
	}
	return mgr.SyncPeerNetworks(networks)
}

func boundaryTransportComplete(v *sdn.VPC, byRef map[sdn.VPCRef]*sdn.VPC, links []peerLink) bool {
	vni := v.Status.VNI
	if !netid.ValidVNI(vni) {
		return false
	}
	for _, r := range v.Spec.Boundary.Peers {
		p := byRef[r.PeerRef]
		if p == nil {
			return false
		}
		peerVNI := p.Status.VNI
		if !netid.ValidVNI(peerVNI) {
			return false
		}
		a, b := netid.VNI(vni), netid.VNI(peerVNI)
		if a > b {
			a, b = b, a
		}
		if !slices.ContainsFunc(links, func(l peerLink) bool { return l.a == a && l.b == b }) {
			return false
		}
	}
	return true
}

func watchBoundaries(ctx context.Context, factory sdninformers.SharedInformerFactory, client sdnclient.Interface, mgr *datapath.Manager, node string, log *slog.Logger) {
	vs := factory.Sdn().V1alpha1().VPCs()
	ps := factory.Sdn().V1alpha1().Ports()
	peers := factory.Sdn().V1alpha1().VPCPeerings()
	uid := os.Getenv("POD_UID")
	resync := func(ctx context.Context) {
		if !vs.Informer().HasSynced() || !ps.Informer().HasSynced() || !peers.Informer().HasSynced() {
			return
		}
		all, err := vs.Lister().List(labels.Everything())
		if err != nil {
			return
		}
		ports, err := ps.Lister().List(labels.Everything())
		if err != nil {
			return
		}
		halves, err := peers.Lister().List(labels.Everything())
		if err != nil {
			return
		}
		desired, known, primary, err := compileBoundaries(all, ports)
		if err != nil {
			log.Error("boundary compile failed", "err", err)
			return
		}
		if err := mgr.SyncBoundaries(desired, known, primary); err != nil {
			log.Error("boundary map sync failed", "err", err)
			return
		}
		refs := map[sdn.VPCRef]*sdn.VPC{}
		for _, v := range all {
			refs[sdn.VPCRef{Namespace: v.Namespace, Name: v.Name}] = v
		}
		links := desiredPeerLinks(halves, func(ns, name string) *sdn.VPC { return refs[sdn.VPCRef{Namespace: ns, Name: name}] })
		if err := syncPeerTransport(mgr, links); err != nil {
			log.Error("boundary transport sync failed", "err", err)
			return
		}
		if uid == "" {
			return
		} // No agent-instance identity means no trusted acknowledgement.
		for _, v := range all {
			if v.Spec.Boundary == nil || !netid.ValidVNI(v.Status.VNI) {
				continue
			}
			identities := []boundaryidentity.PrimaryPort{}
			for _, port := range ports {
				if port.Spec.Primary && port.Spec.VPCRef == (sdn.VPCRef{Namespace: v.Namespace, Name: v.Name}) {
					identities = append(identities, boundaryidentity.PrimaryPort{UID: string(port.UID), IP: port.Spec.IP})
				}
			}
			ack := sdn.VPCBoundaryNode{Node: node, AgentUID: uid, Revision: v.Spec.Boundary.Revision, ObservedGeneration: v.Generation, PrimaryPortsDigest: boundaryidentity.Digest(identities), TransportReady: boundaryTransportComplete(v, refs, links)}
			if slices.Contains(v.Status.BoundaryNodes, ack) {
				continue
			}
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				latest, err := client.SdnV1alpha1().VPCs(v.Namespace).Get(ctx, v.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if latest.UID != v.UID || latest.Generation != v.Generation || !reflect.DeepEqual(latest.Spec, v.Spec) {
					return fmt.Errorf("boundary changed before acknowledgement")
				}
				if slices.Contains(latest.Status.BoundaryNodes, ack) {
					return nil
				}
				latest.Status.BoundaryNodes = slices.DeleteFunc(latest.Status.BoundaryNodes, func(a sdn.VPCBoundaryNode) bool { return a.Node == node })
				latest.Status.BoundaryNodes = append(latest.Status.BoundaryNodes, ack)
				_, err = client.SdnV1alpha1().VPCs(v.Namespace).UpdateStatus(ctx, latest, metav1.UpdateOptions{})
				return err
			}); err != nil {
				log.Error("boundary acknowledgement failed", "err", err)
			}
		}
	}
	notifications := make(boundarySyncNotifications, 1)
	events := cache.ResourceEventHandlerFuncs{AddFunc: func(any) { notifications.notify() }, UpdateFunc: func(_, _ any) { notifications.notify() }, DeleteFunc: func(any) { notifications.notify() }}
	_, _ = vs.Informer().AddEventHandler(events)
	_, _ = ps.Informer().AddEventHandler(events)
	_, _ = peers.Informer().AddEventHandler(events)
	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), vs.Informer().HasSynced, ps.Informer().HasSynced, peers.Informer().HasSynced) {
			return
		}
		notifications.notify()
		runBoundarySyncWorker(ctx, notifications, resync)
	}()
}
