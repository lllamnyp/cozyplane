package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLegacyOwnershipBoundsStalledPodRead(t *testing.T) {
	core, entered, _ := blockedGuestCoreAPI(t)
	ctx, cancel := context.WithCancel(t.Context())
	port, claim, veth := legacyOwnershipFixture()
	returned := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pod, err := launcherClaimPod(ctx, core, claim, port, veth, "local")
		if pod != nil {
			t.Error("stalled read returned an ownership proof")
		}
		returned <- err
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("ownership read did not drain on shutdown")
		}
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real Pod request did not start")
	}
	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("stalled ownership read did not expire", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("ownership read remained blocked on the healthy agent context")
	}
	if ctx.Err() != nil {
		t.Fatal("ownership timeout canceled the whole agent", ctx.Err())
	}
}

func legacyOwnershipFixture() (*sdnv1.Port, *localv1.FabricIP, datapath.LocalPortVeth) {
	port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
		sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner",
	}}, Spec: sdnv1.PortSpec{PodNamespace: "tenant"}}
	claim := &localv1.FabricIP{Spec: localv1.FabricIPSpec{Node: "local", PodNamespace: "tenant", PodName: "launcher", PodUID: "pod-owner", ContainerID: "sandbox", IfName: "eth0"}}
	veth := datapath.LocalPortVeth{ContainerID: "sandbox", IfName: "eth0"}
	return port, claim, veth
}

func TestLegacyOwnershipHonorsShorterParentDeadline(t *testing.T) {
	core, entered, _ := blockedGuestCoreAPI(t)
	port, claim, veth := legacyOwnershipFixture()
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	pod, err := launcherClaimPod(ctx, core, claim, port, veth, "local")
	if pod != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatal("ownership read extended its parent deadline", pod, err, time.Since(start))
	}
	select {
	case <-entered:
	default:
		t.Fatal("short-deadline test did not reach real HTTP")
	}
}

func TestLegacyOwnershipCancellationReleasesResources(t *testing.T) {
	countFD := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	beforeFD, beforeGo := countFD(), runtime.NumGoroutine()
	core, entered, stop := blockedGuestCoreAPI(t)
	port, claim, veth := legacyOwnershipFixture()
	root, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()
	for range 25 {
		child, cancel := context.WithCancel(root)
		returned := make(chan error, 1)
		go func() {
			_, err := launcherClaimPod(child, core, claim, port, veth, "local")
			returned <- err
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("ownership HTTP request did not start")
		}
		cancel()
		select {
		case err := <-returned:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("child cancellation was not preserved", err)
			}
		case <-time.After(time.Second):
			t.Fatal("ownership request did not drain after cancellation")
		}
		if root.Err() != nil {
			t.Fatal("ownership child canceled the parent")
		}
	}
	stop()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > beforeGo+2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if after := countFD(); after != beforeFD {
		t.Fatal("ownership cancellations leaked descriptors", beforeFD, after)
	}
	if after := runtime.NumGoroutine(); after > beforeGo+2 {
		t.Fatal("ownership cancellations retained goroutines", beforeGo, after)
	}
}
