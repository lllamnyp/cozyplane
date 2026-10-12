package hostfirewall

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func diagnosticStatus(t testing.TB, errs field.ErrorList) []byte {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("invalid firewall admitted")
	}
	status := apierrors.NewInvalid(schema.GroupKind{Group: sdn.GroupName, Kind: "HostFirewall"}, "firewall", errs).Status()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHostFirewallDiagnosticsBoundActualAPIStatus(t *testing.T) {
	strategy := NewStrategy(nil)
	canary := "input-canary-" + strings.Repeat("a", 1<<20)
	base := &sdn.HostFirewall{}
	objects := []*sdn.HostFirewall{base.DeepCopy(), base.DeepCopy(), base.DeepCopy(), base.DeepCopy()}
	objects[0].Spec.Ingress = make([]sdn.HostFirewallRule, 4096)
	for i := range objects[0].Spec.Ingress {
		objects[0].Spec.Ingress[i].From = []sdn.HostFirewallPeer{{CIDR: "invalid-prefix"}}
	}
	objects[1].Spec.Egress = []sdn.HostFirewallEgressRule{{To: []sdn.HostFirewallPeer{{CIDR: canary}}}}
	objects[2].Spec.Ingress = []sdn.HostFirewallRule{{From: []sdn.HostFirewallPeer{{CIDR: "192.0.2.0/24", Except: []string{canary}}}}}
	objects[3].Spec.Egress = []sdn.HostFirewallEgressRule{{Ports: []sdn.HostFirewallPort{{Protocol: canary}}}}
	for i, obj := range objects {
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, base)} {
			raw := diagnosticStatus(t, errs)
			if len(errs) != 1 || len(raw) > 1024 || strings.Contains(string(raw), "input-canary") {
				t.Errorf("case %d: %d causes/%d-byte APIStatus", i, len(errs), len(raw))
			}
		}
	}
}

func TestHostFirewallDiagnosticRecoveryRangesAndExceptions(t *testing.T) {
	strategy := NewStrategy(nil)
	obj := &sdn.HostFirewall{Spec: sdn.HostFirewallSpec{Ingress: []sdn.HostFirewallRule{
		{},
		{From: []sdn.HostFirewallPeer{{CIDR: "192.0.2.7/24", Except: []string{"192.0.2.8/32"}}}, Ports: []sdn.HostFirewallPort{{Protocol: "TCP", Port: 1000, EndPort: 1063}}},
	}, Egress: []sdn.HostFirewallEgressRule{{To: []sdn.HostFirewallPeer{{CIDR: "2001:db8::7/64", Except: []string{"2001:db8::8/128"}}, {CIDR: "::ffff:192.0.2.7/120"}}, Ports: []sdn.HostFirewallPort{{Protocol: "UDP", Port: 0}, {Protocol: "TCP", Port: 65535}}}}}}
	old := obj.DeepCopy()
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, old)} {
		if len(errs) != 0 {
			t.Fatal("valid defaults, exceptions or ranges rejected", errs)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.HostFirewall)
		field  string
	}{
		{"late exception", func(hf *sdn.HostFirewall) {
			hf.Spec.Egress[0].To[0].Except = append(hf.Spec.Egress[0].To[0].Except, "invalid-prefix")
		}, "spec.egress[0].to[0].except[1]"},
		{"range 65", func(hf *sdn.HostFirewall) { hf.Spec.Ingress[1].Ports[0].EndPort = 1064 }, "spec.ingress[1].ports[0].endPort"},
		{"zero range", func(hf *sdn.HostFirewall) { hf.Spec.Egress[0].Ports[0].EndPort = 1 }, "spec.egress[0].ports[0].endPort"},
		{"descending", func(hf *sdn.HostFirewall) { hf.Spec.Ingress[1].Ports[0].EndPort = 999 }, "spec.ingress[1].ports[0].endPort"},
		{"port overflow", func(hf *sdn.HostFirewall) { hf.Spec.Egress[0].Ports[1].Port = 65536 }, "spec.egress[0].ports[1].port"},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := old.DeepCopy()
			test.mutate(bad)
			for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), bad), strategy.ValidateUpdate(t.Context(), bad, old)} {
				if len(errs) != 1 || errs[0].Field != test.field || len(diagnosticStatus(t, errs)) > 1024 {
					t.Fatal("invalid input admitted or wrong diagnostic", errs)
				}
			}
			if errs := strategy.ValidateUpdate(t.Context(), old.DeepCopy(), bad); len(errs) != 0 {
				t.Fatal("valid recovery rejected", errs)
			}
		})
	}
}
