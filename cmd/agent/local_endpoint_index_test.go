package main

import (
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"testing"
)

func TestLocalEndpointIndexSeparatesOwnersAndOverlappingNetworks(t *testing.T) {
	ip := net.ParseIP("10.0.0.2")
	index := indexLocalPortVeths([]datapath.LocalPortVeth{{Net: 101, IPs: []net.IP{ip}, Ifindex: 1, PortUID: "owner"}, {Net: 101, IPs: []net.IP{ip}, Ifindex: 2, PortUID: "replacement"}, {Net: 101, IPs: []net.IP{ip}, Ifindex: 3}, {Net: 202, IPs: []net.IP{ip}, Ifindex: 4}, {RawNet: datapath.QuarantineNet, PortUID: "owner", Ifindex: 5}})
	port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", UID: "owner"}, Spec: sdnv1.PortSpec{IP: ip.String()}}
	got := index.forPort(port)
	if len(got) != 3 || got[0].Ifindex != 1 || got[1].Ifindex != 5 || got[2].Ifindex != 3 {
		t.Fatal("index mixed tenants/owners or lost quarantine/legacy endpoint", got)
	}
	port.UID = "remote"
	port.Name = "v300.10-0-0-2"
	if got := index.forPort(port); len(got) != 0 {
		t.Fatal("remote-only Port produced local candidates", got)
	}
}
