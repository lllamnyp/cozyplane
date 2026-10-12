package main

import (
	"errors"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// The default object tracker ignores deletion preconditions. Model the API's
// conditional delete so the test observes whether the current object survives.
func conditionalPortClient(port *sdnv1alpha1.Port) *sdnfake.Clientset {
	client := sdnfake.NewSimpleClientset(port)
	resource := sdnv1alpha1.SchemeGroupVersion.WithResource("ports")
	client.PrependReactor("delete", "ports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deletion := action.(k8stesting.DeleteAction)
		object, err := client.Tracker().Get(resource, "", deletion.GetName())
		if err != nil {
			return true, nil, err
		}
		current := object.(*sdnv1alpha1.Port)
		pre := deletion.GetDeleteOptions().Preconditions
		if pre != nil && ((pre.UID != nil && *pre.UID != current.UID) ||
			(pre.ResourceVersion != nil && *pre.ResourceVersion != current.ResourceVersion)) {
			return true, nil, apierrors.NewConflict(sdnv1alpha1.Resource("ports"), current.Name, errors.New("claim changed"))
		}
		return true, nil, client.Tracker().Delete(resource, "", current.Name)
	})
	return client
}

func TestRollbackPortPreservesReboundClaim(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "ordinary"
		if persistent {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			observed := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{
				Name: "claim", UID: "same-uid", ResourceVersion: "10",
				Annotations: map[string]string{sdnv1alpha1.AnnotationContainerID: "old-sandbox"},
			}}
			if persistent {
				observed.Labels = map[string]string{labelVMName: "vm"}
			}
			current := observed.DeepCopy()
			current.ResourceVersion = "11"
			current.Annotations[sdnv1alpha1.AnnotationContainerID] = "current-sandbox"
			current.Spec.Node = "current-node"
			client := conditionalPortClient(current)
			if err := deleteClaimedPort(t.Context(), client, observed); !apierrors.IsConflict(err) {
				t.Errorf("changed claim deletion must conflict, got %v", err)
			}
			got, err := client.SdnV1alpha1().Ports().Get(t.Context(), current.Name, metav1.GetOptions{})
			if err != nil || got.ResourceVersion != current.ResourceVersion || got.Spec.Node != current.Spec.Node {
				t.Fatalf("rollback lost rebound claim: %v, %v", got, err)
			}
		})
	}
}

func TestRollbackPortDeletesUnchangedClaimAndPreservesReplacement(t *testing.T) {
	observed := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "claim", UID: "original", ResourceVersion: "10"}}
	t.Run("unchanged", func(t *testing.T) {
		client := conditionalPortClient(observed.DeepCopy())
		if err := deleteClaimedPort(t.Context(), client, observed); err != nil {
			t.Fatal(err)
		}
		if _, err := client.SdnV1alpha1().Ports().Get(t.Context(), observed.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("unchanged claim not released: %v", err)
		}
	})
	t.Run("replacement", func(t *testing.T) {
		current := observed.DeepCopy()
		current.UID = "replacement"
		client := conditionalPortClient(current)
		if err := deleteClaimedPort(t.Context(), client, observed); !apierrors.IsConflict(err) {
			t.Fatal(err)
		}
		if _, err := client.SdnV1alpha1().Ports().Get(t.Context(), current.Name, metav1.GetOptions{}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRollbackPortTracksOwnSandboxPatch(t *testing.T) {
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "claim", UID: "original", ResourceVersion: "10"}}
	client := conditionalPortClient(port.DeepCopy())
	client.PrependReactor("patch", "ports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := port.DeepCopy()
		updated.ResourceVersion = "11"
		updated.Annotations = map[string]string{
			sdnv1alpha1.AnnotationContainerID: "sandbox",
			sdnv1alpha1.AnnotationCNIIfName:   "eth0",
			sdnv1alpha1.AnnotationCNIPrimary:  "true",
		}
		return true, updated, client.Tracker().Update(sdnv1alpha1.SchemeGroupVersion.WithResource("ports"), updated, "")
	})
	if err := recordPortSandbox(t.Context(), client, port, "sandbox", "eth0", true, "node"); err != nil {
		t.Fatal(err)
	}
	if err := deleteClaimedPort(t.Context(), client, port); err != nil {
		t.Fatalf("own successful patch prevented cleanup: %v", err)
	}
	if _, err := client.SdnV1alpha1().Ports().Get(t.Context(), port.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("claim not released: %v", err)
	}
}
