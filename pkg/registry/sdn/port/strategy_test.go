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

package port

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mkPort(name, ip string) *sdn.Port {
	return &sdn.Port{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sdn.PortSpec{
			VPCRef: sdn.VPCRef{Namespace: "team-a", Name: "vpc-a"},
			IP:     ip,
		},
	}
}

func TestPortValidate(t *testing.T) {
	s := portStrategy{}
	cases := []struct {
		desc string
		port *sdn.Port
		ok   bool
	}{
		{"v4 claim", mkPort("v5.10-0-0-2", "10.0.0.2"), true},
		{"v6 claim", mkPort("v5.fd00-a--2", "fd00:a::2"), true},
		{"name/spec mismatch", mkPort("v5.10-0-0-2", "10.0.0.3"), false},
		{"wrong kind prefix", mkPort("sv5.10-0-0-2", "10.0.0.2"), false},
		{"no claim shape", mkPort("web", "10.0.0.2"), false},
		{"VNI zero", mkPort("v0.10-0-0-2", "10.0.0.2"), false},
		{"VNI leading zero", mkPort("v05.10-0-0-2", "10.0.0.2"), false},
		{"not an IP", mkPort("v5.bogus", "bogus"), false},
		{"non-canonical v6", mkPort("v5.fd00-0a--2", "fd00:0a::2"), false},
		{"v4-mapped spelling", mkPort("v5.--ffff-10-0-0-2", "::ffff:10.0.0.2"), false},
	}
	for _, c := range cases {
		errs := s.Validate(context.Background(), c.port)
		if (len(errs) == 0) != c.ok {
			t.Errorf("%s: Validate = %v, want ok=%v", c.desc, errs, c.ok)
		}
	}
}

func TestPortValidateUpdate(t *testing.T) {
	s := portStrategy{}
	old := mkPort("v5.10-0-0-2", "10.0.0.2")

	moved := old.DeepCopy()
	moved.Spec.Node = "node-b" // migration cutover: allowed
	if errs := s.ValidateUpdate(context.Background(), moved, old); len(errs) != 0 {
		t.Errorf("node re-point rejected: %v", errs)
	}

	reIP := old.DeepCopy()
	reIP.Spec.IP = "10.0.0.3"
	if errs := s.ValidateUpdate(context.Background(), reIP, old); len(errs) == 0 {
		t.Error("spec.ip change accepted, want forbidden")
	}

	reVPC := old.DeepCopy()
	reVPC.Spec.VPCRef.Name = "vpc-b"
	if errs := s.ValidateUpdate(context.Background(), reVPC, old); len(errs) == 0 {
		t.Error("spec.vpcRef change accepted, want forbidden")
	}
}
