package main

import (
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDesiredFloatingInvalidWinnerDoesNotPromoteStaleLoser(t *testing.T) {
	port := vpcPort("v101.10-0-0-5", "tenant-a", "net", "10.0.0.5", "node-a")
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}
	winner := floatingIPObj("tenant-a", "a-winner", "net", port.Spec.IP, "203.0.113.10")
	loser := floatingIPObj("tenant-a", "z-loser", "net", port.Spec.IP, "203.0.113.11")
	winner.Spec.AddressClaimName = strings.Repeat("x", 128<<10)
	for _, inputs := range [][]*sdnv1alpha1.FloatingIP{{winner, loser}, {loser, winner}} {
		if got := desiredFloating(inputs, []*sdnv1alpha1.Port{port}, []*sdnv1alpha1.VPC{vpc}); len(got) != 0 {
			t.Fatal("invalid winner or stale loser projected", got)
		}
	}
	winner.Spec.AddressClaimName = "claim"
	got := desiredFloating([]*sdnv1alpha1.FloatingIP{loser, winner}, []*sdnv1alpha1.Port{port}, []*sdnv1alpha1.VPC{vpc})
	if len(got) != 1 || got[winner.Status.Address].vni != 101 {
		t.Fatal("valid winner recovery missing", got)
	}
}
