package securitygroup

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func diagnosticStatus(t testing.TB, errs field.ErrorList) []byte {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("invalid policy admitted")
	}
	status := apierrors.NewInvalid(schema.GroupKind{Group: sdn.GroupName, Kind: "SecurityGroup"}, "policy", errs).Status()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func diagnosticPolicy() *sdn.SecurityGroup {
	sg := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, Ingress: make([]sdn.SecurityGroupRule, 4096)}}
	for i := range sg.Spec.Ingress {
		sg.Spec.Ingress[i].From.CIDR = "invalid-prefix"
	}
	return sg
}

func TestSecurityGroupDiagnosticsBoundActualAPIStatus(t *testing.T) {
	strategy := NewStrategy(nil, nil)
	canary := "input-canary-" + strings.Repeat("a", 1<<20)
	base := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}}}
	objects := []*sdn.SecurityGroup{diagnosticPolicy(), base.DeepCopy(), base.DeepCopy(), base.DeepCopy()}
	objects[1].Spec.Ingress = []sdn.SecurityGroupRule{{From: sdn.SecurityGroupPeer{CIDR: canary}}}
	objects[2].Spec.Egress = []sdn.SecurityGroupEgressRule{{To: sdn.SecurityGroupPeer{Group: "peer"}, Ports: []sdn.SecurityGroupPort{{Protocol: canary}}}}
	objects[3].Spec.PodSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "role", Operator: metav1.LabelSelectorOperator(canary)}}
	for i, obj := range objects {
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, base)} {
			raw := diagnosticStatus(t, errs)
			if len(errs) > 2 || len(raw) > 1024 || strings.Contains(string(raw), "input-canary") {
				t.Errorf("case %d: %d causes/%d-byte APIStatus", i, len(errs), len(raw))
			}
		}
	}
}

func BenchmarkSecurityGroupDiagnostics(b *testing.B) {
	strategy := NewStrategy(nil, nil)
	sg := diagnosticPolicy()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = diagnosticStatus(b, strategy.Validate(b.Context(), sg))
	}
}

func TestSecurityGroupDiagnosticRecoveryAndImmutableVPC(t *testing.T) {
	strategy := NewStrategy(nil, nil)
	peerVPC := &sdn.VPCRef{Namespace: "tenant-b", Name: "vpc-b"}
	obj := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "app"}}, Ingress: []sdn.SecurityGroupRule{
		{From: sdn.SecurityGroupPeer{CIDR: "192.0.2.7/24"}, Ports: []sdn.SecurityGroupPort{{Protocol: "TCP", Port: 0}}},
		{From: sdn.SecurityGroupPeer{Group: "peer", VPC: peerVPC}, Ports: []sdn.SecurityGroupPort{{Protocol: "UDP", Port: 65535}}},
	}, Egress: make([]sdn.SecurityGroupEgressRule, 4096)}}
	for i := range obj.Spec.Egress {
		obj.Spec.Egress[i].To.CIDR = "::ffff:192.0.2.7/120"
	}
	obj.Spec.Egress[0].To.CIDR = "2001:db8::7/64"
	old := obj.DeepCopy()
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, old)} {
		if len(errs) != 0 {
			t.Fatalf("valid dual-family/group/port rules rejected: %v", errs)
		}
	}
	obj.Spec.Egress[4095].To.CIDR = strings.Repeat("a", 65)
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, old)} {
		if len(errs) != 1 || errs[0].Field != "spec.egress[4095].to.cidr" || len(diagnosticStatus(t, errs)) > 1024 {
			t.Fatal("late bad CIDR was admitted or diagnostics lost its index", errs)
		}
	}
	obj.Spec.Egress = old.DeepCopy().Spec.Egress
	obj.Spec.Ingress[1].From.VPC.Name = ""
	if errs := strategy.Validate(t.Context(), obj); len(errs) != 1 || errs[0].Field != "spec.ingress[1].from.vpc" {
		t.Fatal("incomplete peer anchor admitted", errs)
	}
	obj.Spec.Ingress = old.DeepCopy().Spec.Ingress
	if errs := strategy.ValidateUpdate(t.Context(), obj, old); len(errs) != 0 {
		t.Fatal("valid recovery rejected", errs)
	}
	obj.Spec.VPCRef.Name = "other"
	if errs := strategy.ValidateUpdate(t.Context(), obj, old); len(errs) != 1 || errs[0].Type != field.ErrorTypeForbidden {
		t.Fatal("VPC anchor mutation admitted", errs)
	}
}
