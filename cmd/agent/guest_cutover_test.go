package main

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGuestAnnouncementCannotMoveReplacedPort(t *testing.T) {
	expected := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", UID: "old-uid", ResourceVersion: "10", Labels: map[string]string{sdnv1alpha1.LabelVMName: "vm"}}, Spec: sdnv1alpha1.PortSpec{IP: "10.0.0.2", MAC: "02:00:00:00:00:01", Node: "source"}}
	for _, change := range []string{"replacement", "termination", "binding", "valid"} {
		t.Run(change, func(t *testing.T) {
			current := expected.DeepCopy()
			switch change {
			case "replacement":
				current.UID = "new-uid"
			case "termination":
				current.DeletionTimestamp = new(metav1.Now())
			case "binding":
				current.ResourceVersion = "11"
				current.Spec.Node = "other-target"
			}
			client := sdnfake.NewSimpleClientset(current)
			moved, err := claimPortOnGuestAnnouncement(t.Context(), client, expected, "target", "192.0.2.2")
			if err != nil || moved != (change == "valid") {
				t.Fatal("unexpected cutover", moved, err)
			}
			got, err := client.SdnV1alpha1().Ports().Get(t.Context(), expected.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if change == "valid" {
				if got.Spec.Node != "target" || got.Spec.NodeIP != "192.0.2.2" || got.Spec.IP != expected.Spec.IP || got.Spec.MAC != expected.Spec.MAC {
					t.Fatal("legitimate cutover failed", got)
				}
			} else {
				if got.Spec.Node != current.Spec.Node || got.UID != current.UID {
					t.Fatal("stale listener moved current Port", got)
				}
				for _, action := range client.Actions() {
					if action.GetVerb() == "patch" {
						t.Fatal("stale listener attempted cutover")
					}
				}
			}
		})
	}
}

func TestGuestCutoverPublishesTargetSandboxWithPlacement(t *testing.T) {
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", UID: "port-owner", ResourceVersion: "1", Labels: map[string]string{sdnv1alpha1.LabelVMName: "guest", sdnv1alpha1.LabelPodUID: "source-pod"}, Annotations: map[string]string{sdnv1alpha1.AnnotationContainerID: "source-sandbox", sdnv1alpha1.AnnotationCNIIfName: "eth0"}}, Spec: sdnv1alpha1.PortSpec{Node: "source", PodName: "source", PodNamespace: "tenant", IP: "10.0.0.2", MAC: "02:00:00:00:00:01"}}
	client := sdnfake.NewSimpleClientset(port)
	binding := guestSandboxBinding{namespace: "tenant", name: "target", uid: "target-pod", containerID: "target-sandbox", ifName: "eth0", podLabels: `{"role":"guest"}`}
	if moved, err := claimPortOnGuestAnnouncement(t.Context(), client, port, "target-node", "192.0.2.2", binding); err != nil || !moved {
		t.Fatal(moved, err)
	}
	got, err := client.SdnV1alpha1().Ports().Get(t.Context(), port.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Node != "target-node" || got.Spec.PodName != "target" || got.Labels[sdnv1alpha1.LabelPodUID] != "target-pod" || got.Annotations[sdnv1alpha1.AnnotationContainerID] != "target-sandbox" || got.Spec.IP != port.Spec.IP || got.Spec.MAC != port.Spec.MAC {
		t.Fatal("cutover retained source identity or changed pinned identity", got)
	}
}
