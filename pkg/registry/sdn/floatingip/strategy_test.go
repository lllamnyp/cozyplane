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

package floatingip

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
)

func newStrategyForTest(t *testing.T) floatingIPStrategy {
	t.Helper()
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return NewStrategy(scheme)
}

func fipWith(vpc, target string) *sdn.FloatingIP {
	return &sdn.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{Name: "f", Namespace: "team-a"},
		Spec: sdn.FloatingIPSpec{
			VPCRef: sdn.LocalVPCRef{Name: vpc},
			Target: target,
		},
	}
}

func TestValidateFloatingIPSpec(t *testing.T) {
	s := newStrategyForTest(t)
	cases := []struct {
		name    string
		obj     *sdn.FloatingIP
		wantErr bool
	}{
		{"v4 target", fipWith("tenant-a", "10.10.0.5"), false},
		{"v6 target", fipWith("tenant-a", "fd00:a::5"), false},

		// Each of these used to be accepted and then fail silently: the
		// controller's endpoint-slice builder parses the target and, on error,
		// simply writes no endpoint — leaving the object Pending forever with
		// nothing saying why.
		{"missing vpc", fipWith("", "10.10.0.5"), true},
		{"missing target", fipWith("tenant-a", ""), true},
		{"target is not an address", fipWith("tenant-a", "the-web-vm"), true},
		{"target is a CIDR", fipWith("tenant-a", "10.10.0.0/24"), true},
		// Replay normalizes valid IP spelling before matching canonical Port claims.
		{"normalized v6", fipWith("tenant-a", "fd00:0a::0005"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := s.Validate(context.Background(), c.obj)
			if c.wantErr && len(errs) == 0 {
				t.Fatal("want rejected, got accepted")
			}
			if !c.wantErr && len(errs) != 0 {
				t.Fatalf("want accepted, got %v", errs)
			}
		})
	}
}

func TestValidateUpdateRatchets(t *testing.T) {
	s := newStrategyForTest(t)
	legacy := fipWith("tenant-a", "the-web-vm") // stored before validation existed

	unchanged := legacy.DeepCopy()
	unchanged.Spec.LoadBalancerClass = "metallb"
	if errs := s.ValidateUpdate(context.Background(), unchanged, legacy); len(errs) == 0 {
		t.Fatal("changing legacy spec requires a usable target")
	}

	repaired := legacy.DeepCopy()
	repaired.Spec.Target = "10.10.0.5"
	if errs := s.ValidateUpdate(context.Background(), repaired, legacy); len(errs) != 0 {
		t.Fatalf("repairing the target should be allowed, got %v", errs)
	}

	worse := legacy.DeepCopy()
	worse.Spec.Target = "also-not-an-address"
	if errs := s.ValidateUpdate(context.Background(), worse, legacy); len(errs) == 0 {
		t.Fatal("changing the target to garbage should be rejected")
	}
}
