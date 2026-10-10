package sdn

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFloatingTargetRequiresCurrentVPCClaim(t *testing.T) {
	for _, mutation := range []string{"current", "old-vni", "terminating-port", "terminating-vpc", "missing-vpc"} {
		t.Run(mutation, func(t *testing.T) {
			vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/24")
			port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2"}, Spec: sdnv1alpha1.PortSpec{IP: "10.0.0.2", Node: "node-a", VPCRef: sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}}}
			switch mutation {
			case "old-vni":
				vpc.Status.VNI = 102
			case "terminating-port":
				now := metav1.Now()
				port.DeletionTimestamp = &now
				port.Finalizers = []string{"example.invalid/cleanup"}
			case "terminating-vpc":
				now := metav1.Now()
				vpc.DeletionTimestamp = &now
				vpc.Finalizers = []string{"example.invalid/cleanup"}
			}
			objs := []client.Object{port}
			if mutation != "missing-vpc" {
				objs = append(objs, vpc)
			}
			r := &FloatingIPReconciler{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(objs...).Build()}
			got := r.targetLiveNode(t.Context(), floatingIP(vpc.Namespace, "public", vpc.Name, port.Spec.IP))
			if (mutation == "current" && got != port.Spec.Node) || (mutation != "current" && got != "") {
				t.Fatalf("target node %q for %s", got, mutation)
			}
		})
	}
}

func TestFloatingConflictComparesEquivalentIPv6Targets(t *testing.T) {
	older := floatingIP("tenant-a", "a-winner", "net", "fd00::5")
	newer := floatingIP("tenant-a", "z-loser", "net", "fd00:0:0:0:0:0:0:5")
	r := &FloatingIPReconciler{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdnv1alpha1.FloatingIP{}, floatingTargetIndex, floatingTargetIndexKeys).WithObjects(older, newer).Build()}
	if got := r.conflictingFIP(t.Context(), newer); got != older.Name {
		t.Fatalf("equivalent IPv6 target escaped conflict: %q", got)
	}
}
