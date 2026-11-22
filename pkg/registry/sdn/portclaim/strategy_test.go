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

package portclaim

import (
	"context"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func newStrategyForTest(t *testing.T) portClaimStrategy {
	t.Helper()
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return NewStrategy(scheme)
}

func claimWith(mac, ip string) *sdn.PortClaim {
	return &sdn.PortClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "team-a"},
		Spec:       sdn.PortClaimSpec{VPCRef: sdn.VPCRef{Name: "vpc"}, MAC: mac, IP: ip},
	}
}

func TestPrepareForCreate(t *testing.T) {
	s := newStrategyForTest(t)
	pc := claimWith("", "")
	pc.Status.IP = "10.0.0.9"
	s.PrepareForCreate(context.Background(), pc)
	if pc.Status.IP != "" {
		t.Errorf("status not cleared: %+v", pc.Status)
	}
	if pc.Spec.VPCRef.Namespace != "team-a" {
		t.Errorf("vpcRef.namespace = %q, want the claim's namespace", pc.Spec.VPCRef.Namespace)
	}
	if !slices.Contains(pc.Finalizers, sdnv1alpha1.FinalizerPortClaim) {
		t.Errorf("finalizers = %v, want %s", pc.Finalizers, sdnv1alpha1.FinalizerPortClaim)
	}
	s.PrepareForCreate(context.Background(), pc)
	if len(pc.Finalizers) != 1 {
		t.Errorf("finalizer duplicated: %v", pc.Finalizers)
	}
}

func TestValidate(t *testing.T) {
	s := newStrategyForTest(t)
	cases := []struct {
		name    string
		obj     *sdn.PortClaim
		wantErr bool
	}{
		{"no request", claimWith("", ""), false},
		{"mac and v4", claimWith("02:00:00:00:00:01", "10.0.0.9"), false},
		{"v6", claimWith("", "fd00::9"), false},
		{"upper-case mac", claimWith("02:AA:00:00:00:01", ""), true},
		{"multicast mac", claimWith("03:00:00:00:00:01", ""), true},
		{"zero mac", claimWith("00:00:00:00:00:00", ""), true},
		{"eui-64", claimWith("02:00:00:00:00:00:00:01", ""), true},
		{"non-canonical ip", claimWith("", "fd00:0::9"), true},
		{"not an ip", claimWith("", "vm1"), true},
		{"no vpc", &sdn.PortClaim{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "a"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := s.Validate(context.Background(), tc.obj)
			if (len(errs) > 0) != tc.wantErr {
				t.Errorf("errs = %v, wantErr %v", errs, tc.wantErr)
			}
		})
	}
}

func TestSpecImmutable(t *testing.T) {
	s := newStrategyForTest(t)
	old := claimWith("02:00:00:00:00:01", "")
	changed := claimWith("02:00:00:00:00:02", "")
	if errs := s.ValidateUpdate(context.Background(), changed, old); len(errs) == 0 {
		t.Error("spec change accepted")
	}
	if errs := s.ValidateUpdate(context.Background(), claimWith("02:00:00:00:00:01", ""), old); len(errs) != 0 {
		t.Errorf("unchanged spec refused: %v", errs)
	}
}

func TestPinnedStatusImmutable(t *testing.T) {
	ss := NewStatusStrategy(newStrategyForTest(t))
	old := claimWith("", "")
	pinned := claimWith("", "")
	pinned.Status = sdn.PortClaimStatus{IP: "10.0.0.9", MAC: "02:00:00:00:00:01"}
	if errs := ss.ValidateUpdate(context.Background(), pinned, old); len(errs) != 0 {
		t.Errorf("first pin refused: %v", errs)
	}
	moved := claimWith("", "")
	moved.Status = sdn.PortClaimStatus{IP: "10.0.0.10", MAC: "02:00:00:00:00:02"}
	if errs := ss.ValidateUpdate(context.Background(), moved, pinned); len(errs) != 2 {
		t.Errorf("errs = %v, want ip and mac refused", errs)
	}
}
