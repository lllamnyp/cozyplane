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

package sdn

import (
	"context"
	"math"
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVPCRepairsReservedVNI(t *testing.T) {
	for _, vni := range []int32{-1, 99, 1 << 22, 1 << 23, math.MaxInt32} {
		vpc := vpcWithVNI("test", vni)
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&sdnv1alpha1.VPC{}).WithObjects(vpc).Build()
		r := &VPCReconciler{Client: c}
		key := types.NamespacedName{Namespace: vpc.Namespace, Name: vpc.Name}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(context.Background(), key, vpc); err != nil {
			t.Fatal(err)
		}
		if vpc.Status.VNI != 100 {
			t.Fatalf("reserved VNI %d kept as %d", vni, vpc.Status.VNI)
		}
	}
}

func TestSecurityGroupRepairsReservedID(t *testing.T) {
	for _, id := range []int32{-1, 63, 64, 65537, math.MaxInt32} {
		group := sg("test", "group", "vpc", time.Unix(0, 0))
		group.Status.ID = id
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&sdnv1alpha1.SecurityGroup{}).WithObjects(group).Build()
		r := &SecurityGroupReconciler{Client: c}
		got := reconcileSG(t, r, group.Namespace, group.Name)
		if got.Status.ID != 1 {
			t.Fatalf("reserved ID %d kept as %d", id, got.Status.ID)
		}
	}
}

func TestPendingOrInvalidSelectedGroupRetainsPolicy(t *testing.T) {
	for _, id := range []int32{0, -1, 63, 64, 65537} {
		group := sg("test", "group", "vpc", time.Unix(0, 0))
		group.Status.ID = id
		port := &sdnv1alpha1.Port{Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "test", Name: "vpc"}}, Status: sdnv1alpha1.PortStatus{Groups: []int32{1}}}
		port.Name = "v100.10-0-0-2"
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&sdnv1alpha1.Port{}).WithIndex(&sdnv1alpha1.SecurityGroup{}, membershipVPCIndex, membershipVPCKeys).WithObjects(group, port).Build()
		r := &PortMembershipReconciler{Client: c, SentinelReady: func(context.Context) (bool, error) { return true, nil }}
		key := types.NamespacedName{Name: port.Name}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(context.Background(), key, port); err != nil {
			t.Fatal(err)
		}
		if len(port.Status.Groups) != 1 || port.Status.Groups[0] != 0 {
			t.Errorf("selected group %d became legacy allow: %v", id, port.Status.Groups)
		}
	}
}
