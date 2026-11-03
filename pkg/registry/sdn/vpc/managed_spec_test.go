package vpc

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestManagedVPCNetworkSpecRequiresBoundaryAuthority(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*sdn.VPC)
	}{
		{"cidrs", func(v *sdn.VPC) { v.Spec.CIDRs = []string{"10.21.0.0/24"} }},
		{"mtu", func(v *sdn.VPC) { v.Spec.MTU = 1400 }},
	} {
		for _, allowed := range []bool{false, true} {
			t.Run(change.name+map[bool]string{false: "/denied", true: "/allowed"}[allowed], func(t *testing.T) {
				a := &boundaryAuthorizer{allow: allowed}
				s := boundaryStrategy(a)
				old := boundaryVPC()
				old.Generation = 7
				updated := old.DeepCopy()
				change.apply(updated)
				s.PrepareForUpdate(boundaryRequest(), updated, old)
				if updated.Generation != 8 {
					t.Fatalf("generation = %d, want 8", updated.Generation)
				}
				errs := s.ValidateUpdate(boundaryRequest(), updated, old)
				if (len(errs) == 0) != allowed {
					t.Fatalf("allowed=%v errors=%v", allowed, errs)
				}
				assertBoundaryAuthorization(t, a, old)
			})
		}
	}
}

func TestVPCStatusCannotForgeGeneration(t *testing.T) {
	old := boundaryVPC()
	old.Generation = 7
	updated := old.DeepCopy()
	updated.Generation = 999
	updated.Spec.CIDRs = []string{"10.21.0.0/24"}
	updated.Status.VNI = 100
	NewStatusStrategy(boundaryStrategy(nil)).PrepareForUpdate(context.Background(), updated, old)
	if updated.Generation != 7 || updated.Spec.CIDRs[0] != old.Spec.CIDRs[0] || updated.Status.VNI != 100 {
		t.Fatalf("status crossed spec/generation: %+v", updated)
	}
}

func TestManagedVPCMetadataKeepsGenerationWithoutBoundaryCheck(t *testing.T) {
	a := &boundaryAuthorizer{}
	s := boundaryStrategy(a)
	old := boundaryVPC()
	old.Generation = 7
	updated := old.DeepCopy()
	updated.Labels = map[string]string{"purpose": "test"}
	updated.Generation = 999
	s.PrepareForUpdate(boundaryRequest(), updated, old)
	if errs := s.ValidateUpdate(boundaryRequest(), updated, old); len(errs) != 0 {
		t.Fatal(errs)
	}
	if a.calls != 0 || updated.Generation != 7 {
		t.Fatalf("calls=%d generation=%d", a.calls, updated.Generation)
	}
}
