/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vpc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

func boundaryVPC() *sdn.VPC {
	v := vpcWith([]string{"10.20.0.0/24"}, 0)
	v.Spec.Boundary = &sdn.VPCBoundary{Revision: 1, Peers: []sdn.VPCBoundaryRule{{
		PeerRef:   sdn.VPCRef{Namespace: "team-b", Name: "peer"},
		Direction: "egress", Protocol: "TCP", Ports: []int32{443},
	}}}
	return v
}

func boundaryInt(n int32) *int32 { return &n }

func TestBoundaryValidatesDirectedExplicitRules(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*sdn.VPC)
		invalidField string
	}{
		{"TCP", func(*sdn.VPC) {}, ""},
		{"UDP ingress", func(v *sdn.VPC) {
			v.Spec.Boundary.Peers[0].Protocol = "UDP"
			v.Spec.Boundary.Peers[0].Direction = "ingress"
		}, ""},
		{"ICMP explicit zero", func(v *sdn.VPC) {
			r := &v.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(0)
			r.ICMPCode = boundaryInt(0)
		}, ""},
		{"empty deny all", func(v *sdn.VPC) { v.Spec.Boundary.Peers = nil }, ""},
		{"Internet only", func(v *sdn.VPC) { v.Spec.Boundary.Peers = nil; v.Spec.Boundary.Internet = true }, ""},
		{"zero revision", func(v *sdn.VPC) { v.Spec.Boundary.Revision = 0 }, "spec.boundary.revision"},
		{"negative revision", func(v *sdn.VPC) { v.Spec.Boundary.Revision = -1 }, "spec.boundary.revision"},
		{"missing namespace", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].PeerRef.Namespace = "" }, "spec.boundary.peers[0].peerRef"},
		{"missing peer", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].PeerRef.Name = "" }, "spec.boundary.peers[0].peerRef"},
		{"self peer", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].PeerRef = sdn.VPCRef{Namespace: v.Namespace, Name: v.Name} }, "spec.boundary.peers[0].peerRef"},
		{"bad direction", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].Direction = "both" }, "spec.boundary.peers[0].direction"},
		{"wildcard protocol", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].Protocol = "ALL" }, "spec.boundary.peers[0].protocol"},
		{"TCP no ports", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].Ports = nil }, "spec.boundary.peers[0]"},
		{"port zero", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].Ports = []int32{0} }, "spec.boundary.peers[0].ports[0]"},
		{"port overflow", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].Ports = []int32{65536} }, "spec.boundary.peers[0].ports[0]"},
		{"duplicate port", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].Ports = []int32{443, 443} }, "spec.boundary.peers[0].ports[1]"},
		{"TCP ICMP fields", func(v *sdn.VPC) { v.Spec.Boundary.Peers[0].ICMPType = boundaryInt(8) }, "spec.boundary.peers[0]"},
		{"ICMP missing type", func(v *sdn.VPC) {
			r := &v.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPCode = boundaryInt(0)
		}, "spec.boundary.peers[0]"},
		{"ICMP missing code", func(v *sdn.VPC) {
			r := &v.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(8)
		}, "spec.boundary.peers[0]"},
		{"ICMP type overflow", func(v *sdn.VPC) {
			r := &v.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(256)
			r.ICMPCode = boundaryInt(0)
		}, "spec.boundary.peers[0]"},
		{"ICMP negative code", func(v *sdn.VPC) {
			r := &v.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(8)
			r.ICMPCode = boundaryInt(-1)
		}, "spec.boundary.peers[0]"},
		{"ICMP ports", func(v *sdn.VPC) {
			r := &v.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.ICMPType = boundaryInt(8)
			r.ICMPCode = boundaryInt(0)
		}, "spec.boundary.peers[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := boundaryVPC()
			tc.mutate(v)
			errs := newStrategyForTest(t).Validate(context.Background(), v)
			if tc.invalidField == "" {
				if len(errs) != 0 {
					t.Fatalf("valid boundary rejected: %v", errs)
				}
				return
			}
			for _, err := range errs {
				if err.Field == tc.invalidField {
					return
				}
			}
			t.Fatalf("missing rejection on %s: %v", tc.invalidField, errs)
		})
	}
}

func TestBoundaryCapacityRejectsWholeDesiredPolicy(t *testing.T) {
	for _, tc := range []struct {
		name         string
		peers, ports int
		invalid      bool
	}{
		{"port maximum", 1, 32, false}, {"port overflow", 1, 33, true},
		{"peer maximum", 256, 1, false}, {"peer overflow", 257, 1, true},
		{"map maximum", 128, 32, false}, {"map overflow", 129, 32, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := boundaryVPC()
			rule := v.Spec.Boundary.Peers[0]
			rule.Ports = make([]int32, tc.ports)
			for i := range rule.Ports {
				rule.Ports[i] = int32(i + 1)
			}
			v.Spec.Boundary.Peers = make([]sdn.VPCBoundaryRule, tc.peers)
			for i := range v.Spec.Boundary.Peers {
				v.Spec.Boundary.Peers[i] = rule
			}
			errs := newStrategyForTest(t).Validate(context.Background(), v)
			if (len(errs) != 0) != tc.invalid {
				t.Fatalf("invalid=%v, errors=%v", tc.invalid, errs)
			}
			if len(v.Spec.Boundary.Peers) != tc.peers {
				t.Fatal("validation truncated desired policy")
			}
		})
	}
}

type boundaryAuthorizer struct {
	allow bool
	calls int
	last  authorizer.Attributes
}

func (a *boundaryAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	a.calls++
	a.last = attrs
	if a.allow {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "denied", nil
}

func boundaryRequest() context.Context {
	return request.WithUser(context.Background(), &user.DefaultInfo{Name: "operator-test"})
}

func boundaryStrategy(auth authorizer.Authorizer) vpcStrategy {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return NewStrategy(scheme, auth)
}

func assertBoundaryAuthorization(t *testing.T, auth *boundaryAuthorizer, v *sdn.VPC) {
	t.Helper()
	if auth.calls != 1 || auth.last == nil {
		t.Fatalf("authorization calls=%d, want one", auth.calls)
	}
	a := auth.last
	if a.GetVerb() != "manage-boundary" || a.GetResource() != "vpcs" || a.GetAPIGroup() != sdn.GroupName || a.GetNamespace() != v.Namespace || a.GetName() != v.Name || !a.IsResourceRequest() || a.GetUser().GetName() != "operator-test" {
		t.Fatal("boundary authorization targeted the wrong principal, verb or VPC")
	}
}

func TestBoundaryCreateRequiresOperatorVerbOnItsOwnVPC(t *testing.T) {
	for _, allow := range []bool{false, true} {
		a := &boundaryAuthorizer{allow: allow}
		v := boundaryVPC()
		errs := boundaryStrategy(a).Validate(boundaryRequest(), v)
		if (len(errs) == 0) != allow {
			t.Fatalf("allow=%v errors=%v", allow, errs)
		}
		assertBoundaryAuthorization(t, a, v)
	}
	a := &boundaryAuthorizer{}
	legacy := boundaryVPC()
	legacy.Spec.Boundary = nil
	if errs := boundaryStrategy(a).Validate(boundaryRequest(), legacy); len(errs) != 0 || a.calls != 0 {
		t.Fatal("legacy create unexpectedly required boundary authority")
	}
	if errs := boundaryStrategy(&boundaryAuthorizer{allow: true}).Validate(context.Background(), boundaryVPC()); len(errs) == 0 {
		t.Fatal("boundary create accepted a missing request principal")
	}
}

func TestBoundaryUpdateProtectsAddChangeAndRemoval(t *testing.T) {
	for _, operation := range []string{"add", "replace", "remove"} {
		for _, allow := range []bool{false, true} {
			t.Run(operation+map[bool]string{true: " allowed", false: " denied"}[allow], func(t *testing.T) {
				old, desired := boundaryVPC(), boundaryVPC()
				switch operation {
				case "add":
					old.Spec.Boundary = nil
				case "replace":
					desired.Spec.Boundary.Revision = 2
					desired.Spec.Boundary.Internet = true
				case "remove":
					desired.Spec.Boundary = nil
				}
				a := &boundaryAuthorizer{allow: allow}
				errs := boundaryStrategy(a).ValidateUpdate(boundaryRequest(), desired, old)
				if (len(errs) == 0) != allow {
					t.Fatalf("allow=%v errors=%v", allow, errs)
				}
				assertBoundaryAuthorization(t, a, desired)
			})
		}
	}
	old, desired := boundaryVPC(), boundaryVPC()
	desired.Labels = map[string]string{"purpose": "test"}
	a := &boundaryAuthorizer{}
	if errs := boundaryStrategy(a).ValidateUpdate(boundaryRequest(), desired, old); len(errs) != 0 || a.calls != 0 {
		t.Fatal("unchanged boundary required operator authority")
	}
	for _, revision := range []int64{0, 1} {
		desired := boundaryVPC()
		desired.Spec.Boundary.Internet = true
		desired.Spec.Boundary.Revision = revision
		errs := boundaryStrategy(&boundaryAuthorizer{allow: true}).ValidateUpdate(boundaryRequest(), desired, old)
		found := false
		for _, err := range errs {
			if err.Field == "spec.boundary.revision" && err.Type == field.ErrorTypeInvalid {
				found = true
			}
		}
		if !found {
			t.Fatal("changed boundary accepted a non-increasing revision")
		}
	}
}

func TestBoundaryDeletionChecksCurrentObjectAndPreservesValidation(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, allow := range []bool{false, true} {
			v := boundaryVPC()
			if !managed {
				v.Spec.Boundary = nil
			}
			a := &boundaryAuthorizer{allow: allow}
			r := &BoundaryREST{auth: a}
			called := false
			sentinel := errors.New("delete validation rejected")
			check := r.deletionCheck(func(_ context.Context, obj runtime.Object) error {
				called = true
				if obj != v {
					t.Fatal("delete validator saw another object")
				}
				return sentinel
			})
			err := check(boundaryRequest(), v)
			if managed && !allow {
				if !apierrors.IsForbidden(err) || called {
					t.Fatal("managed deletion bypassed authorization")
				}
			} else if !errors.Is(err, sentinel) || !called {
				t.Fatal("delete authorization discarded the caller validation")
			}
			if managed {
				assertBoundaryAuthorization(t, a, v)
			} else if a.calls != 0 {
				t.Fatal("legacy deletion required boundary authority")
			}
		}
	}
	// A callback captured before a policy was added must inspect the object
	// supplied by storage at deletion time, rather than the earlier state.
	v := boundaryVPC()
	v.Spec.Boundary = nil
	r := &BoundaryREST{auth: &boundaryAuthorizer{}}
	check := r.deletionCheck(nil)
	v.Spec.Boundary = &sdn.VPCBoundary{Revision: 1}
	if err := check(boundaryRequest(), v); !apierrors.IsForbidden(err) {
		t.Fatal("policy added before storage delete escaped authorization")
	}
	if err := (&BoundaryREST{auth: &boundaryAuthorizer{allow: true}}).deletionCheck(nil)(boundaryRequest(), v); err != nil {
		t.Fatal(err)
	}
}

func TestBoundaryStatusUpdateCannotReplaceOperatorPolicy(t *testing.T) {
	old, desired := boundaryVPC(), boundaryVPC()
	desired.Spec.Boundary = nil
	desired.Status.BoundaryNodes = []sdn.VPCBoundaryNode{{Node: "node-test", AgentUID: "agent-test", Revision: 1}}
	a := &boundaryAuthorizer{}
	s := NewStatusStrategy(boundaryStrategy(a))
	s.PrepareForUpdate(boundaryRequest(), desired, old)
	if desired.Spec.Boundary == nil || desired.Spec.Boundary.Revision != 1 {
		t.Fatal("status endpoint replaced operator boundary")
	}
	if len(desired.Status.BoundaryNodes) != 1 || desired.Status.BoundaryNodes[0].AgentUID != "agent-test" {
		t.Fatal("status endpoint discarded agent acknowledgement")
	}
	if errs := s.ValidateUpdate(boundaryRequest(), desired, old); len(errs) != 0 || a.calls != 0 {
		t.Fatal("status observation unexpectedly required operator boundary authority")
	}
}

func TestBoundaryGeneratedCopiesAndConversionsPreserveDesiredAndObservedState(t *testing.T) {
	original := boundaryVPC()
	original.Spec.Boundary.Peers = append(original.Spec.Boundary.Peers, sdn.VPCBoundaryRule{
		PeerRef: sdn.VPCRef{Namespace: "team-b", Name: "peer"}, Direction: "ingress", Protocol: "ICMP",
		ICMPType: boundaryInt(8), ICMPCode: boundaryInt(0),
	})
	original.Status.BoundaryNodes = []sdn.VPCBoundaryNode{{Node: "node-test", AgentUID: "agent-test", Revision: 1, TransportReady: true}}
	copy := original.DeepCopy()
	copy.Spec.Boundary.Peers[0].Ports[0] = 8443
	*copy.Spec.Boundary.Peers[1].ICMPType = 0
	copy.Status.BoundaryNodes[0].Revision = 2
	copy.Status.BoundaryNodes[0].TransportReady = false
	if original.Spec.Boundary.Peers[0].Ports[0] != 443 || *original.Spec.Boundary.Peers[1].ICMPType != 8 || original.Status.BoundaryNodes[0].Revision != 1 || !original.Status.BoundaryNodes[0].TransportReady {
		t.Fatal("generated deepcopy shares boundary state with its original")
	}
	scheme := runtime.NewScheme()
	install.Install(scheme)
	versioned := &sdnv1alpha1.VPC{}
	if err := scheme.Convert(original, versioned, nil); err != nil {
		t.Fatal(err)
	}
	roundTrip := &sdn.VPC{}
	if err := scheme.Convert(versioned, roundTrip, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, roundTrip) {
		t.Fatal("API conversion discarded boundary policy or acknowledgements")
	}
	port := &sdn.Port{Spec: sdn.PortSpec{Primary: true}}
	versionedPort := &sdnv1alpha1.Port{}
	if err := scheme.Convert(port, versionedPort, nil); err != nil {
		t.Fatal(err)
	}
	if !versionedPort.Spec.Primary {
		t.Fatal("API conversion discarded primary NIC designation")
	}
}
