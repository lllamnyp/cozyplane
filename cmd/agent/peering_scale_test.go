package main

import (
	"fmt"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func BenchmarkUnmatchedPeerings(b *testing.B) {
	ps := make([]*sdn.VPCPeering, 10000)
	for i := range ps {
		ps[i] = &sdn.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: fmt.Sprint(i)}, Spec: sdn.VPCPeeringSpec{VPCRef: sdn.LocalVPCRef{Name: fmt.Sprint("a-", i)}, PeerRef: sdn.VPCRef{Namespace: "tenant-b", Name: fmt.Sprint("b-", i)}}}
	}
	lookup := func(namespace, name string) *sdn.VPC {
		n := int32(101)
		cidr := "10.1.0.0/24"
		if namespace == "tenant-b" {
			n = 102
			cidr = "10.2.0.0/24"
		}
		return &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: []string{cidr}}, Status: sdn.VPCStatus{VNI: n}}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(desiredPeerLinks(ps, lookup)) != 0 {
			b.Fatal("unilateral peering admitted")
		}
	}
}
