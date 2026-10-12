package main

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCNIReportsOversizedForwardingGrant(t *testing.T) {
	grant := &sdnv1alpha1.VPCBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "consumer"},
		Spec: sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "owner", Name: "net"}, AllowForwarding: true,
			ForwardingCIDRs: make([]string, sdnv1alpha1.MaxForwardingPrefixes+1)},
	}
	for i := range grant.Spec.ForwardingCIDRs {
		grant.Spec.ForwardingCIDRs[i] = "10.0.0.0/24"
	}
	client := sdnfake.NewSimpleClientset(grant)
	allow, cidrs, err := requireVPCBinding(t.Context(), client, "consumer", "owner", "net")
	if err == nil || allow || cidrs != nil {
		t.Fatalf("oversized grant published: allow=%v prefixes=%d err=%v", allow, len(cidrs), err)
	}
}
