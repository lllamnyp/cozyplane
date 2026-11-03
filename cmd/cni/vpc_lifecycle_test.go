package main

import (
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPortAttachRejectsTerminatingVPCWithoutChangingPinnedIdentity(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-claim", true: "pinned-rebind"}[persistent], func(t *testing.T) {
			c := sdnfake.NewSimpleClientset()
			state := &datapath.AgentState{NodeName: "node-a", NodeIP: "192.0.2.1"}
			vpc := newVPC("tenant-a", "net", 101, "10.0.0.0/24")
			vm, labels := "", ""
			var original *sdn.Port
			if persistent {
				vm, labels = "vm", `{"kubevirt.io/created-by":"instance-current"}`
			}
			if persistent {
				_, _, claim, _, err := attachPort(t.Context(), c, res(vpc, vpc.Namespace), state, vpc.Namespace, "old-launcher", "pod-old", vm, labels)
				if err != nil {
					t.Fatal(err)
				}
				original = claim.DeepCopy()
			}
			now := metav1.Now()
			vpc.DeletionTimestamp = &now
			if _, _, _, _, err := attachPort(t.Context(), c, res(vpc, vpc.Namespace), state, vpc.Namespace, "new-launcher", "pod-new", vm, labels); err == nil {
				t.Error("attachment accepted a terminating VPC")
			}
			ports, err := c.SdnV1alpha1().Ports().List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if persistent {
				want = 1
			}
			if len(ports.Items) != want {
				t.Fatalf("rejected attach changed claim count=%d want=%d", len(ports.Items), want)
			}
			if persistent && (ports.Items[0].Spec.PodName != "old-launcher" || ports.Items[0].Labels[labelPodUID] != "pod-old") {
				t.Fatal("rejected attach rebound pinned identity", ports.Items[0].Spec.PodName)
			}
			if persistent && (ports.Items[0].Spec.IP != original.Spec.IP || ports.Items[0].Spec.MAC != original.Spec.MAC) {
				t.Fatal("rejected attach changed pinned IP/MAC")
			}
			vpc.DeletionTimestamp = nil
			if ip, mac, _, bound, err := attachPort(t.Context(), c, res(vpc, vpc.Namespace), state, vpc.Namespace, "new-launcher", "pod-new", vm, labels); err != nil || (persistent && (!bound || ip.String() != original.Spec.IP || mac.String() != original.Spec.MAC)) {
				t.Fatal("valid VPC did not recover attachment", ip, mac, bound, err)
			}
		})
	}
}

func TestAttachmentVPCResolutionRejectsUnusableLifecycle(t *testing.T) {
	for _, scenario := range []string{"terminating", "zero-vni", "negative-vni", "live", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			vpc := newVPC("tenant-a", "net", 101, "10.0.0.0/24")
			switch scenario {
			case "terminating":
				now := metav1.Now()
				vpc.DeletionTimestamp = &now
			case "zero-vni":
				vpc.Status.VNI = 0
			case "negative-vni":
				vpc.Status.VNI = -1
			}
			c := sdnfake.NewSimpleClientset(vpc)
			name := vpc.Name
			if scenario == "missing" {
				name = "absent"
			}
			got, err := lookupAttachmentVPC(t.Context(), c, vpc.Namespace, name)
			if scenario == "live" {
				if err != nil || got.Status.VNI != 101 {
					t.Fatal("live VPC resolution failed", got, err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unusable VPC resolution accepted", got, err)
			}
			for _, action := range c.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("resolution mutated API state", action.GetVerb())
				}
			}
		})
	}
}
