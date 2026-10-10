package main

import (
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"testing"
)

func TestOrphanEndpointUsesUIDDespiteAddressReuse(t *testing.T) {
	ip := net.ParseIP("10.0.0.2")
	ports := []*sdnv1.Port{{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", UID: "replacement"}, Spec: sdnv1.PortSpec{IP: ip.String()}}}
	veths := []datapath.LocalPortVeth{{Net: 101, IPs: []net.IP{ip}, PortUID: "old", Ifindex: 1}, {Net: 101, IPs: []net.IP{ip}, PortUID: "replacement", Ifindex: 2}, {Net: 101, IPs: []net.IP{ip}, Ifindex: 3}, {Net: 0, IPs: []net.IP{ip}, PortUID: "fabric", Ifindex: 4}, {Net: 101, RawNet: datapath.QuarantineNet, PortUID: "already-cut", Ifindex: 5}}
	got := orphanPortVeths(ports, veths)
	if len(got) != 1 || got[0].Ifindex != 1 {
		t.Fatal("orphan selection adopted address identity or touched legacy/fabric", got)
	}
}
