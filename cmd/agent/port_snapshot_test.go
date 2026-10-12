package main

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestPortSnapshotUsesReplacementAndLatestPlacement(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	old := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "port", UID: "old", ResourceVersion: "1"}, Spec: sdnv1alpha1.PortSpec{Node: "source", IP: "10.0.0.10"}}
	current := old.DeepCopy()
	current.UID = "replacement"
	current.ResourceVersion = "2"
	current.Spec.Node = "target"
	if err := store.Add(current); err != nil {
		t.Fatal(err)
	}
	got, found, err := currentPortSnapshot(store, old)
	if err != nil || !found || got.UID != current.UID || got.Spec.Node != "target" {
		t.Fatalf("obsolete event won: got=%+v found=%v err=%v", got, found, err)
	}
	olderMove := current.DeepCopy()
	current = current.DeepCopy()
	current.Spec.Node = "other"
	current.ResourceVersion = "3"
	if err := store.Update(current); err != nil {
		t.Fatal(err)
	}
	got, found, err = currentPortSnapshot(store, olderMove)
	if err != nil || !found || got.Spec.Node != "other" {
		t.Fatalf("older move replaced current placement: %v %v %v", got, found, err)
	}
	if err := store.Delete(current); err != nil {
		t.Fatal(err)
	}
	_, found, err = currentPortSnapshot(store, current)
	if err != nil || found {
		t.Fatal("deleted Port still actionable", found, err)
	}
}
