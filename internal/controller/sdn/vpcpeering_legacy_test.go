package sdn

import (
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestVPCPeeringInvalidLegacyRemainsPending(t *testing.T) {
	for _, bad := range [][]string{{"invalid"}, {strings.Repeat("x", 1<<20)}, make([]string, sdn.MaxVPCCIDRs+1)} {
		a := nsVPCWithVNI("tenant-a", "net", 101)
		a.Spec.CIDRs = bad
		b := nsVPCWithVNI("tenant-b", "net", 102)
		b.Spec.CIDRs = []string{"10.2.0.0/24"}
		client := peeringClient(t, a, b, peeringHalf(a.Namespace, "to-b", "net", b.Namespace, "net"), peeringHalf(b.Namespace, "to-a", "net", a.Namespace, "net"))
		got := reconcilePeering(t, client, a.Namespace, "to-b")
		if got.Status.Phase != sdn.VPCPeeringPhasePending {
			t.Fatal("invalid legacy VPC peering reported Ready", got.Status)
		}
	}
}
