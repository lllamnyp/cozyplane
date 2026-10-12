package vpc

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestVPCCIDRAdmissionRejectsMalformedAndOversizedInputs(t *testing.T) {
	for _, prefixes := range [][]string{{"invalid"}, {strings.Repeat("x", 1<<20)}, make([]string, 1025)} {
		vpc := &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: prefixes}}
		errors := NewStrategy(nil).Validate(t.Context(), vpc)
		if len(errors) == 0 {
			t.Fatal("unusable VPC accepted")
		}
		if len(errors.ToAggregate().Error()) > 300 {
			t.Fatal("rejection echoed input payload")
		}
	}
}

func TestVPCCIDRAdmissionPreservesLegacyCleanup(t *testing.T) {
	strategy := NewStrategy(nil)
	old := &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: []string{"invalid"}}}
	metadata := old.DeepCopy()
	metadata.Finalizers = []string{"cleanup"}
	if errs := strategy.ValidateUpdate(t.Context(), metadata, old); len(errs) != 0 {
		t.Fatal("legacy metadata update trapped", errs)
	}
	changed := old.DeepCopy()
	changed.Spec.CIDRs = []string{"still-invalid"}
	if errs := strategy.ValidateUpdate(t.Context(), changed, old); len(errs) == 0 {
		t.Fatal("changed invalid CIDRs admitted")
	}
	changed.Spec.CIDRs = []string{"10.0.0.0/24", "2001:db8::/64", "::ffff:10.1.0.0/120"}
	if errs := strategy.ValidateUpdate(t.Context(), changed, old); len(errs) != 0 {
		t.Fatal("legacy correction rejected", errs)
	}
	if errs := strategy.Validate(t.Context(), &sdn.VPC{}); len(errs) == 0 {
		t.Fatal("unusable empty network admitted")
	}
	boundary := make([]string, sdnv1alpha1.MaxVPCCIDRs)
	for i := range boundary {
		boundary[i] = "10.0.0.0/24"
	}
	if errs := strategy.Validate(t.Context(), &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: boundary}}); len(errs) != 0 {
		t.Fatal("valid boundary rejected", errs)
	}
}
