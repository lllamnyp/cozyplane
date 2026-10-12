package main

import (
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func BenchmarkVPCBoundaryProjection(b *testing.B) {
	for _, count := range []int{1024, 4096} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			gateways := make([]*sdn.VPCGateway, count)
			vpcs := make([]*sdn.VPC, count)
			for i := range count {
				name := fmt.Sprintf("net-%d", i)
				vpcs[i] = &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: name}, Status: sdn.VPCStatus{VNI: int32(i + 1)}}
				gateways[i] = &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: name},
					Spec:   sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: name}, Ingress: sdn.VPCGatewayIngress{LoadBalancer: true}, NAT: sdn.VPCGatewayNAT{Enabled: true}},
					Status: sdn.VPCGatewayStatus{NATAddress: fmt.Sprintf("198.18.%d.%d", i>>8, i&255)}}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if len(desiredVPCIngress(gateways, vpcs)) != count || len(desiredVPCNAT(gateways, vpcs)) != count {
					b.Fatal("incomplete boundary projection")
				}
			}
		})
	}
}

func TestVPCBoundaryProjectionPreservesOldestGatewayAndNamespace(t *testing.T) {
	old := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "a", CreationTimestamp: metav1.NewTime(time.Unix(1, 0))},
		Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}}
	newer := old.DeepCopy()
	newer.Name = "b"
	newer.Spec.Ingress.LoadBalancer = true
	newer.Spec.NAT.Enabled = true
	newer.Status.NATAddress = "203.0.113.1"
	other := newer.DeepCopy()
	other.Namespace = "tenant-b"
	other.Status.NATAddress = "203.0.113.2"
	unrelated := newer.DeepCopy()
	unrelated.Name = "unrelated"
	unrelated.Spec.VPCRef.Name = "another-net"
	vpcs := []*sdn.VPC{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdn.VPCStatus{VNI: 101}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-b", Name: "net"}, Status: sdn.VPCStatus{VNI: 102}},
	}
	gateways := []*sdn.VPCGateway{other, newer, unrelated, old}
	if got := desiredVPCIngress(gateways, vpcs); got[101] || !got[102] || len(got) != 1 {
		t.Fatal("newer/unrelated/cross-namespace gateway widened ingress", got)
	}
	if got := desiredVPCNAT(gateways, vpcs); got[101].V4 != "" || got[102].V4 != "203.0.113.2" || len(got) != 1 {
		t.Fatal("newer/unrelated/cross-namespace gateway widened NAT", got)
	}
	old.DeletionTimestamp = new(metav1.NewTime(time.Unix(2, 0)))
	if got := desiredVPCIngress(gateways, vpcs); !got[101] || !got[102] {
		t.Fatal("terminating oldest gateway blocked replacement", got)
	}
	if got := desiredVPCNAT(gateways, vpcs); got[101].V4 != "203.0.113.1" || got[102].V4 != "203.0.113.2" {
		t.Fatal("terminating oldest gateway retained NAT ownership", got)
	}
}
