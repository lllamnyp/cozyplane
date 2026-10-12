package securitygroup

import (
	"github.com/lllamnyp/cozyplane/api/sdn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestSecurityGroupAdmissionRejectsWildcardPortOverflow(t *testing.T) {
	strategy := NewStrategy(nil, nil)
	base := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, Ingress: []sdn.SecurityGroupRule{{From: sdn.SecurityGroupPeer{Group: "client"}}}, Egress: []sdn.SecurityGroupEgressRule{{To: sdn.SecurityGroupPeer{Group: "server"}}}}}
	for _, test := range []struct {
		protocol string
		port     int32
		valid    bool
	}{{"TCP", 0, true}, {"UDP", 65535, true}, {"TCP", 65536, false}, {"UDP", -1, false}, {"TCP", 2147483647, false}, {"SCTP", 80, false}} {
		obj := base.DeepCopy()
		obj.Spec.Ingress[0].Ports = []sdn.SecurityGroupPort{{Protocol: test.protocol, Port: test.port}}
		obj.Spec.Egress[0].Ports = obj.Spec.Ingress[0].Ports
		if accepted := len(strategy.Validate(t.Context(), obj)) == 0; accepted != test.valid {
			t.Fatal("unexpected create admission", test, accepted)
		}
		if accepted := len(strategy.ValidateUpdate(t.Context(), obj, base)) == 0; accepted != test.valid {
			t.Fatal("unexpected update admission", test, accepted)
		}
	}
	obj := base.DeepCopy()
	obj.Spec.PodSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "role", Operator: "invalid", Values: []string{"app"}}}
	if len(strategy.Validate(t.Context(), obj)) == 0 || len(strategy.ValidateUpdate(t.Context(), obj, base)) == 0 {
		t.Fatal("invalid selector admitted; it would silently select no protected endpoints")
	}
}
