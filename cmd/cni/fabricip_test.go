package main

import (
	"context"
	"fmt"
	"hash/fnv"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"net"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
)

func TestFabricSandboxRetryAndStaleDEL(t *testing.T) {
	client := localfake.NewSimpleClientset()
	oldID, newID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	allocate := func(container string) *fabricAllocation {
		t.Helper()
		allocation, err := claimFabricIPs(t.Context(), client, []string{"10.244.0.0/24", "fd00::/120"}, "node-a", "tenant", "pod", "pod-uid", container, "eth0")
		if err != nil {
			t.Fatal(err)
		}
		return allocation
	}
	old := allocate(oldID)
	live := allocate(newID)
	retry := allocate(newID)
	if len(retry.Created) != 0 || len(retry.Addresses) != 2 {
		t.Fatal("ADD retry allocated additional claims")
	}
	bridges := map[string]bool{}
	for i := range live.Addresses {
		if !retry.Addresses[i].Equal(live.Addresses[i]) || old.Addresses[i].Equal(live.Addresses[i]) {
			t.Fatal("sandbox address reuse incorrect")
		}
		bridges[old.Addresses[i].String()], bridges[live.Addresses[i].String()] = true, true
	}
	legacy := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Labels: map[string]string{labelFabricPodUID: "pod-uid"}}, Spec: localv1alpha1.FabricIPSpec{Address: "10.244.0.250", PodUID: "pod-uid"}}
	if _, err := client.LocalV1alpha1().FabricIPs().Create(t.Context(), legacy, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	bridges[legacy.Spec.Address] = true
	if err := releaseFabricIPs(t.Context(), client, "pod-uid", oldID, "eth0", func(address string) error { delete(bridges, address); return nil }); err != nil {
		t.Fatal(err)
	}
	for i := range live.Addresses {
		if !bridges[live.Addresses[i].String()] || bridges[old.Addresses[i].String()] {
			t.Fatal("stale DEL removed the live bridge or retained old bridge")
		}
		if _, err := client.LocalV1alpha1().FabricIPs().Get(t.Context(), localv1alpha1.FabricIPName(live.Addresses[i].String()), metav1.GetOptions{}); err != nil {
			t.Fatal("live claim lost", err)
		}
	}
	if !bridges[legacy.Spec.Address] {
		t.Fatal("legacy bridge removed without sandbox proof")
	}
	list, err := client.LocalV1alpha1().FabricIPs().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 3 {
		t.Fatalf("expected live dual-stack claims and legacy, got %v err=%v", list, err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete-collection" {
			t.Fatal("bulk deletion used")
		}
	}
}

func TestFabricAllocatorSkipsReservedCandidate(t *testing.T) {
	// Find a UID whose first candidate is the platform hairpin inside a wider
	// pool, rather than the pool's own reserved network+1 address.
	uid := ""
	for i := range 50000 {
		value := fmt.Sprintf("sandbox-%d", i)
		h := fnv.New64a()
		_, _ = h.Write([]byte(value))
		if 2+h.Sum64()%1022 == 513 { // 169.254.40.0 + 513 = 169.254.42.1
			uid = value
			break
		}
	}
	if uid == "" {
		t.Fatal("could not build reserved-candidate fixture")
	}
	client := localfake.NewSimpleClientset()
	allocation, err := claimFabricIPs(t.Context(), client, []string{"169.254.40.0/22"}, "node", "tenant", "pod", uid, "sandbox", "eth0")
	if err != nil || len(allocation.Addresses) != 1 || allocation.Addresses[0].String() != "169.254.42.2" {
		t.Fatalf("did not skip reserved candidate without restarting the pool: %v %v", allocation, err)
	}
}

func TestFabricRollbackDoesNotReleaseReusedClaims(t *testing.T) {
	client := localfake.NewSimpleClientset()
	args := []string{"node-a", "tenant", "pod", "uid", "sandbox", "eth0"}
	allocation, err := claimFabricIPs(t.Context(), client, []string{"10.244.0.0/24"}, args[0], args[1], args[2], args[3], args[4], args[5])
	if err != nil {
		t.Fatal(err)
	}
	_, err = claimFabricIPs(t.Context(), client, []string{"10.244.0.0/24", "invalid"}, args[0], args[1], args[2], args[3], args[4], args[5])
	if err == nil {
		t.Fatal("invalid pool accepted")
	}
	if _, err := client.LocalV1alpha1().FabricIPs().Get(t.Context(), localv1alpha1.FabricIPName(allocation.Addresses[0].String()), metav1.GetOptions{}); err != nil {
		t.Fatal("retry failure released earlier allocation", err)
	}
}

func TestFabricConcurrentRetryReusesCreateWinner(t *testing.T) {
	client := localfake.NewSimpleClientset()
	client.PrependReactor("create", "fabricips", func(action k8stesting.Action) (bool, runtime.Object, error) {
		claim := action.(k8stesting.CreateAction).GetObject().(*localv1alpha1.FabricIP)
		if err := client.Tracker().Create(localv1alpha1.SchemeGroupVersion.WithResource("fabricips"), claim, ""); err != nil {
			t.Fatal(err)
		}
		// Simulate another retry winning between List and Create.
		return true, nil, apierrors.NewAlreadyExists(localv1alpha1.Resource("fabricips"), claim.Name)
	})
	allocation, err := claimFabricIPs(context.Background(), client, []string{"10.244.0.0/24"}, "node", "tenant", "pod", "uid", "sandbox", "eth0")
	if err != nil || len(allocation.Created) != 0 || len(allocation.Addresses) != 1 {
		t.Fatalf("concurrent retry failed: %v %v", allocation, err)
	}
	list, err := client.LocalV1alpha1().FabricIPs().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 || net.ParseIP(list.Items[0].Spec.Address) == nil {
		t.Fatalf("duplicate or invalid claims: %v %v", list, err)
	}
}

func TestFabricDELWithoutPodUIDIsInterfaceScoped(t *testing.T) {
	client := localfake.NewSimpleClientset()
	for _, ifName := range []string{"eth0", "eth1"} {
		if _, err := claimFabricIPs(t.Context(), client, []string{"10.244.0.0/24"}, "node", "tenant", "pod", "uid", "sandbox", ifName); err != nil {
			t.Fatal(err)
		}
	}
	if err := releaseFabricIPs(t.Context(), client, "", "sandbox", "eth0", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	list, err := client.LocalV1alpha1().FabricIPs().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 || list.Items[0].Spec.IfName != "eth1" {
		t.Fatal("DEL removed other interface", list, err)
	}
}

func TestFabricReleaseSkipsReplacedClaimBeforeBridgeCleanup(t *testing.T) {
	current := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "claim", UID: "current", ResourceVersion: "2"}, Spec: localv1alpha1.FabricIPSpec{Address: "10.244.0.2", ContainerID: "current", IfName: "eth0"}}
	old := current.DeepCopy()
	old.UID = "old"
	old.ResourceVersion = "1"
	old.Spec.ContainerID = "old"
	client := localfake.NewSimpleClientset(current)
	cleaned := false
	if err := releaseFabricClaims(t.Context(), client, []localv1alpha1.FabricIP{*old}, func(string) error { cleaned = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if cleaned {
		t.Fatal("obsolete claim deleted current bridge")
	}
	got, err := client.LocalV1alpha1().FabricIPs().Get(t.Context(), current.Name, metav1.GetOptions{})
	if err != nil || got.UID != current.UID {
		t.Fatal("replacement claim lost", got, err)
	}
}
