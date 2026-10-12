package v1alpha1

import (
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func grantBinding(prefixes int) *VPCBinding {
	binding := &VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer"}, Spec: VPCBindingSpec{
		VPCRef: VPCRef{Namespace: "owner", Name: "net"}, AllowForwarding: true,
	}}
	if prefixes != 0 {
		binding.Spec.ForwardingCIDRs = make([]string, prefixes)
		for i := range binding.Spec.ForwardingCIDRs {
			binding.Spec.ForwardingCIDRs[i] = "10.0.0.0/24"
		}
	}
	return binding
}

func TestBindingGrantUnionFailsClosedAboveWorkBudget(t *testing.T) {
	attached, forwarding, cidrs := BindingGrants([]*VPCBinding{grantBinding(2048), grantBinding(2049)}, "consumer", "owner", "net")
	if !attached || forwarding || cidrs != nil {
		t.Fatalf("oversized union authorized forwarding: attached=%v forwarding=%v prefixes=%d", attached, forwarding, len(cidrs))
	}
}

func TestBindingGrantBudgetPreservesGrantSemantics(t *testing.T) {
	for _, test := range []struct {
		name                 string
		bindings             []*VPCBinding
		attached, forwarding bool
		prefixes             int
		wantErr              bool
	}{
		{"no grant", nil, false, false, 0, false},
		{"exact budget", []*VPCBinding{grantBinding(MaxForwardingPrefixes)}, true, true, MaxForwardingPrefixes, false},
		{"single oversized", []*VPCBinding{grantBinding(MaxForwardingPrefixes + 1)}, true, false, 0, true},
		{"blanket before oversized", []*VPCBinding{grantBinding(0), grantBinding(MaxForwardingPrefixes + 1)}, true, true, 0, false},
		{"blanket after oversized", []*VPCBinding{grantBinding(MaxForwardingPrefixes + 1), grantBinding(0)}, true, true, 0, false},
		{"scoped union retains duplicates", []*VPCBinding{grantBinding(2), grantBinding(3)}, true, true, 5, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			attached, forwarding, cidrs, err := BindingGrantsWithBudget(test.bindings, "consumer", "owner", "net")
			if attached != test.attached || forwarding != test.forwarding || len(cidrs) != test.prefixes || (err != nil) != test.wantErr {
				t.Fatalf("attached=%v forwarding=%v prefixes=%d err=%v", attached, forwarding, len(cidrs), err)
			}
		})
	}
	for _, change := range []string{"foreign namespace", "different VPC", "terminating"} {
		t.Run(change, func(t *testing.T) {
			blanket := grantBinding(0)
			switch change {
			case "foreign namespace":
				blanket.Namespace = "foreign"
			case "different VPC":
				blanket.Spec.VPCRef.Name = "other"
			case "terminating":
				now := metav1.Now()
				blanket.DeletionTimestamp = &now
			}
			attached, forwarding, cidrs, err := BindingGrantsWithBudget([]*VPCBinding{nil, grantBinding(MaxForwardingPrefixes + 1), blanket}, "consumer", "owner", "net")
			if !attached || forwarding || cidrs != nil || err == nil {
				t.Fatal("unrelated blanket bypassed budget")
			}
		})
	}
}

func TestMalformedForwardingPrefixesFailClosedWithBoundedErrors(t *testing.T) {
	for _, text := range []string{"not-a-cidr", "192.0.2.999/24", "fd00::/129", strings.Repeat("x", 1<<20)} {
		binding := grantBinding(1)
		binding.Spec.ForwardingCIDRs[0] = text
		attached, forwarding, cidrs, err := BindingGrantsWithBudget([]*VPCBinding{binding}, "consumer", "owner", "net")
		if !attached || forwarding || cidrs != nil || err == nil || len(err.Error()) > 128 {
			t.Fatalf("malformed prefix emitted a grant or unbounded error: forwarding=%v prefixes=%d err=%v", forwarding, len(cidrs), err)
		}
	}
	for _, text := range []string{"0.0.0.0/0", "10.0.0.7/24", "::/0", "fd00:abcd:1234::5/64", "::ffff:192.0.2.0/120"} {
		if err := ValidateForwardingPrefixes([]string{text}); err != nil {
			t.Fatal("valid forwarding prefix rejected", text, err)
		}
	}
}

func BenchmarkBindingGrantsBlanketWithLargeScopes(b *testing.B) {
	large, blanket := grantBinding(16384), grantBinding(0)
	for _, test := range []struct {
		name     string
		bindings []*VPCBinding
	}{{"blanket-first", []*VPCBinding{blanket, large}}, {"blanket-last", []*VPCBinding{large, blanket}}} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				attached, forwarding, cidrs := BindingGrants(test.bindings, "consumer", "owner", "net")
				if !attached || !forwarding || cidrs != nil {
					b.Fatal("unrestricted grant semantics changed")
				}
			}
		})
	}
}

func TestStreamedBindingGrantsMatchSnapshotResolution(t *testing.T) {
	blanket := grantBinding(0)
	bad := grantBinding(1)
	bad.Spec.ForwardingCIDRs[0] = "invalid"
	deleted := grantBinding(0)
	now := metav1.Now()
	deleted.DeletionTimestamp = &now
	foreign := grantBinding(0)
	foreign.Namespace = "other"
	for _, bindings := range [][]*VPCBinding{
		{nil}, {grantBinding(4)}, {grantBinding(2048), grantBinding(2049)},
		{bad, blanket}, {blanket, bad}, {bad}, {bad, deleted, foreign},
	} {
		grant := NewBindingGrantAccumulator("consumer", "owner", "net")
		for _, binding := range bindings {
			grant.Add(binding)
		}
		a, f, c, err := grant.Result()
		wa, wf, wc, we := BindingGrantsWithBudget(bindings, "consumer", "owner", "net")
		if a != wa || f != wf || !slices.Equal(c, wc) || (err == nil) != (we == nil) {
			t.Fatal("stream/snapshot diverged", a, f, c, err, wa, wf, wc, we)
		}
	}
}
