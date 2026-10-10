package securitygroup

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestSecurityGroupRejectsUnusableReferences(t *testing.T) {
	strategy := NewStrategy(nil, nil)
	base := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "net"}, Ingress: []sdn.SecurityGroupRule{{From: sdn.SecurityGroupPeer{Group: "peer", VPC: &sdn.VPCRef{Namespace: "tenant-b", Name: "net"}}}}, Egress: []sdn.SecurityGroupEgressRule{{To: sdn.SecurityGroupPeer{Group: "peer"}}}}}
	for _, value := range []string{strings.Repeat("x", 128<<10), "bad/name"} {
		for _, test := range []struct {
			name string
			edit func(*sdn.SecurityGroup)
		}{
			{"local VPC", func(g *sdn.SecurityGroup) { g.Spec.VPCRef.Name = value }},
			{"ingress group", func(g *sdn.SecurityGroup) { g.Spec.Ingress[0].From.Group = value }},
			{"egress group", func(g *sdn.SecurityGroup) { g.Spec.Egress[0].To.Group = value }},
			{"peer VPC", func(g *sdn.SecurityGroup) { g.Spec.Ingress[0].From.VPC.Name = value }},
			{"peer namespace", func(g *sdn.SecurityGroup) { g.Spec.Ingress[0].From.VPC.Namespace = value }},
		} {
			t.Run(test.name+"/"+value[:min(8, len(value))], func(t *testing.T) {
				obj := base.DeepCopy()
				test.edit(obj)
				old := obj.DeepCopy()
				old.Spec.PodSelector.MatchLabels = map[string]string{"role": "previous"}
				for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, old)} {
					if len(errs) != 1 || len(diagnosticStatus(t, errs)) > 1024 {
						t.Fatal("unusable reference admitted or unbounded diagnostic", errs)
					}
				}
				if errs := strategy.ValidateUpdate(t.Context(), obj, obj.DeepCopy()); len(errs) != 0 {
					t.Fatal("unchanged legacy reference blocked metadata cleanup", errs)
				}
			})
		}
	}
}

func TestSecurityGroupReferenceBoundaries(t *testing.T) {
	strategy := NewStrategy(nil, nil)
	name := strings.Repeat("a.", 126) + "a"
	obj := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: name}, Ingress: []sdn.SecurityGroupRule{{From: sdn.SecurityGroupPeer{Group: name, VPC: &sdn.VPCRef{Namespace: strings.Repeat("a", 63), Name: name}}}}}}
	if errs := strategy.Validate(t.Context(), obj); len(errs) != 0 {
		t.Fatal("valid maximum reference rejected", errs)
	}
	for _, edit := range []func(*sdn.SecurityGroup){
		func(g *sdn.SecurityGroup) { g.Spec.VPCRef.Name += "a" },
		func(g *sdn.SecurityGroup) { g.Spec.Ingress[0].From.Group += "a" },
		func(g *sdn.SecurityGroup) { g.Spec.Ingress[0].From.VPC.Name += "a" },
		func(g *sdn.SecurityGroup) { g.Spec.Ingress[0].From.VPC.Namespace += "a" },
	} {
		next := obj.DeepCopy()
		edit(next)
		if errs := strategy.Validate(t.Context(), next); len(errs) != 1 || len(diagnosticStatus(t, errs)) > 1024 {
			t.Fatal("reference boundary admitted or diagnostic grew", errs)
		}
	}
}
