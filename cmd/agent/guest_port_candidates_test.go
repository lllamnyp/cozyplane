package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnlisters "github.com/lllamnyp/cozyplane/pkg/generated/sdn/listers/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

type observedGuestPortLister struct {
	sdnlisters.PortLister
	lists, gets, rows int
}

func (l *observedGuestPortLister) List(selector labels.Selector) ([]*sdnv1.Port, error) {
	objects, err := l.PortLister.List(selector)
	l.lists++
	l.rows += len(objects)
	return objects, err
}

func (l *observedGuestPortLister) Get(name string) (*sdnv1.Port, error) {
	obj, err := l.PortLister.Get(name)
	l.gets++
	if obj != nil {
		l.rows++
	}
	return obj, err
}

func guestPortCandidateFixture(t testing.TB) (*observedGuestPortLister, []datapath.LocalPortVeth) {
	t.Helper()
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for i := range 10000 {
		ip := net.IPv4(10, 100, byte(i/250), byte(i%250+1)).String()
		port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(101, ip), UID: types.UID(fmt.Sprintf("other-%05d", i))}, Spec: sdnv1.PortSpec{IP: ip, Node: "remote"}}
		if err := store.Add(port); err != nil {
			t.Fatal(err)
		}
	}
	wanted := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, "192.0.2.10"), UID: "wanted", Labels: map[string]string{sdnv1.LabelVMName: "guest"}}, Spec: sdnv1.PortSpec{IP: "192.0.2.10", Node: "source"}}
	if err := store.Add(wanted); err != nil {
		t.Fatal(err)
	}
	other := wanted.DeepCopy()
	other.Name, other.UID = sdn.PortName(101, wanted.Spec.IP), "another-vpc"
	if err := store.Add(other); err != nil {
		t.Fatal(err)
	}
	return &observedGuestPortLister{PortLister: sdnlisters.NewPortLister(store)}, []datapath.LocalPortVeth{{Net: 100, RawNet: 100, PortUID: "wanted", IPs: []net.IP{net.ParseIP(wanted.Spec.IP)}}}
}

func TestGuestPortCandidatesReadOnlyLocalClaim(t *testing.T) {
	lister, inventory := guestPortCandidateFixture(t)
	ports, err := guestPortCandidates(lister, inventory)
	if err != nil || len(ports) != 1 || ports[0].UID != "wanted" {
		t.Fatal("guest candidates include unrelated cluster claims", len(ports), err)
	}
	if lister.lists != 0 || lister.gets != 1 || lister.rows != 1 {
		t.Fatal("guest candidate lookup materialized cluster Ports", lister.lists, lister.gets, lister.rows)
	}
}

func TestGuestPortCandidatesGenerationAndScope(t *testing.T) {
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		t.Run(address, func(t *testing.T) {
			store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			current := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, address), UID: "current"}, Spec: sdnv1.PortSpec{IP: address}}
			other := current.DeepCopy()
			other.Name, other.UID = sdn.PortName(101, address), "other-vpc"
			for _, p := range []*sdnv1.Port{current, other} {
				if err := store.Add(p); err != nil {
					t.Fatal(err)
				}
			}
			lister := &observedGuestPortLister{PortLister: sdnlisters.NewPortLister(store)}
			old := datapath.LocalPortVeth{Net: 100, RawNet: 100, PortUID: "old", IPs: []net.IP{net.ParseIP(address)}}
			live := old
			live.PortUID = "current"
			ports, err := guestPortCandidates(lister, []datapath.LocalPortVeth{old, live, live})
			if err != nil || len(ports) != 1 || ports[0].UID != current.UID || lister.lists != 0 || lister.gets != 2 {
				t.Fatal("old alias hid replacement or crossed VNI", ports, err, lister.gets)
			}
			legacy := live
			legacy.PortUID = ""
			ports, err = guestPortCandidates(lister, []datapath.LocalPortVeth{legacy})
			if err != nil || len(ports) != 1 {
				t.Fatal("legacy candidate lost before ownership proof", ports, err)
			}
			bad := current.DeepCopy()
			bad.Spec.IP = "192.0.2.99"
			if err := store.Update(bad); err != nil {
				t.Fatal(err)
			}
			ports, err = guestPortCandidates(lister, []datapath.LocalPortVeth{live})
			if err != nil || len(ports) != 0 {
				t.Fatal("mismatched claim address accepted", ports, err)
			}
			if err := store.Delete(bad); err != nil {
				t.Fatal(err)
			}
			ports, err = guestPortCandidates(lister, []datapath.LocalPortVeth{live})
			if err != nil || len(ports) != 0 {
				t.Fatal("missing claim borrowed another VNI", ports, err)
			}
		})
	}
}

func TestGuestPortCandidatesSkipInactiveInventory(t *testing.T) {
	ports, err := guestPortCandidates(nil, []datapath.LocalPortVeth{
		{},
		{Net: 100, RawNet: datapath.QuarantineNet, IPs: []net.IP{net.ParseIP("192.0.2.10")}},
		{Net: 100, RawNet: 100 | datapath.PortGatewayFlag, IPs: []net.IP{net.ParseIP("192.0.2.10")}},
		{Net: 100, RawNet: 100, IPs: []net.IP{nil}},
	})
	if err != nil || len(ports) != 0 {
		t.Fatal("inactive endpoint queried claims", ports, err)
	}
}

func BenchmarkGuestCandidatesAmong10000Ports(b *testing.B) {
	lister, inventory := guestPortCandidateFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ports, err := guestPortCandidates(lister, inventory)
		if err != nil || len(ports) == 0 {
			b.Fatal("candidate lookup failed", err)
		}
	}
}
