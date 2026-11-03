package main

import (
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCNIRejectsUnusableCIDRsBeforePinnedPortRebind(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	state := &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}
	vpc := newVPC("tenant", "net", 101, "10.0.0.0/24")
	labels := `{"kubevirt.io/created-by":"instance"}`
	_, _, original, _, err := attachPort(t.Context(), client, res(vpc, vpc.Namespace), state, vpc.Namespace, "old", "old-uid", "vm", labels)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"10.0.0.0/24", "invalid"}, {strings.Repeat("x", 1<<20)}, make([]string, sdn.MaxVPCCIDRs+1)} {
		vpc.Spec.CIDRs = bad
		// Keep the resolved address from the original pool: validateAttachmentVPC
		// must check the actual full VPC spec before any existing identity rebind.
		r := res(newVPC("tenant", "net", 101, "10.0.0.0/24"), vpc.Namespace)
		r.vpc = vpc
		if _, _, _, _, err := attachPort(t.Context(), client, r, state, vpc.Namespace, "current", "current-uid", "vm", labels); err == nil {
			t.Fatal("unusable CIDRs accepted")
		} else if len(err.Error()) > 300 {
			t.Fatal("rejection echoed oversized input")
		}
		got, err := client.SdnV1alpha1().Ports().Get(t.Context(), original.Name, metav1.GetOptions{})
		if err != nil || got.Spec.PodName != original.Spec.PodName || got.Spec.IP != original.Spec.IP || got.Spec.MAC != original.Spec.MAC {
			t.Fatal("rejected input changed pinned identity", got, err)
		}
	}
}
