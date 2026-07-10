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

package servicevip

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mkVIP(name, ip string) *sdn.ServiceVIP {
	return &sdn.ServiceVIP{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sdn.ServiceVIPSpec{
			VPCRef: sdn.VPCRef{Namespace: "team-a", Name: "vpc-a"},
			IP:     ip,
		},
	}
}

func TestServiceVIPValidate(t *testing.T) {
	s := serviceVIPStrategy{}
	cases := []struct {
		desc string
		vip  *sdn.ServiceVIP
		ok   bool
	}{
		{"v4 claim", mkVIP("sv5.10-0-0-254", "10.0.0.254"), true},
		{"v6 claim", mkVIP("sv5.fd00-a--fffe", "fd00:a::fffe"), true},
		{"name/spec mismatch", mkVIP("sv5.10-0-0-254", "10.0.0.253"), false},
		{"wrong kind prefix", mkVIP("v5.10-0-0-254", "10.0.0.254"), false},
		{"no claim shape", mkVIP("web", "10.0.0.254"), false},
		{"VNI zero", mkVIP("sv0.10-0-0-254", "10.0.0.254"), false},
		{"not an IP", mkVIP("sv5.bogus", "bogus"), false},
	}
	for _, c := range cases {
		errs := s.Validate(context.Background(), c.vip)
		if (len(errs) == 0) != c.ok {
			t.Errorf("%s: Validate = %v, want ok=%v", c.desc, errs, c.ok)
		}
	}
}

func TestServiceVIPValidateUpdate(t *testing.T) {
	s := serviceVIPStrategy{}
	old := mkVIP("sv5.10-0-0-254", "10.0.0.254")

	rePorts := old.DeepCopy()
	rePorts.Spec.Ports = []sdn.VIPPort{{Name: "http", Protocol: "TCP", Port: 80}}
	rePorts.Spec.SessionAffinity = "ClientIP"
	if errs := s.ValidateUpdate(context.Background(), rePorts, old); len(errs) != 0 {
		t.Errorf("ports/affinity refresh rejected: %v", errs)
	}

	reIP := old.DeepCopy()
	reIP.Spec.IP = "10.0.0.253"
	if errs := s.ValidateUpdate(context.Background(), reIP, old); len(errs) == 0 {
		t.Error("spec.ip change accepted, want forbidden")
	}

	reVPC := old.DeepCopy()
	reVPC.Spec.VPCRef.Name = "vpc-b"
	if errs := s.ValidateUpdate(context.Background(), reVPC, old); len(errs) == 0 {
		t.Error("spec.vpcRef change accepted, want forbidden")
	}
}
