package datapath

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"testing"
)

// The required kernel lane fails rather than silently skipping verification.
// It loads into a disposable container's private BPF handles, with no pins or
// attachments to user interfaces and no mutation of a Kubernetes cluster.
func TestBoundaryKernelVerifier(t *testing.T) {
	if os.Getenv("COZYPLANE_REQUIRE_BPF") != "1" {
		t.Skip("requires isolated privileged Linux BPF validation")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	var objs overlayObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("kernel verifier: %+v", verifier)
		}
		t.Fatalf("kernel verifier: %+v", err)
	}
	defer objs.Close()
	if err := objs.LbProg.Put(uint32(4), objs.CozyplaneFromPodContinue); err != nil {
		t.Fatal(err)
	}
	if err := objs.LbProg.Put(uint32(5), objs.CozyplaneToPodContinue); err != nil {
		t.Fatal(err)
	}
}
