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

package main

import (
	"context"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
)

func newClaim(name string, mac, ip string) *sdnv1alpha1.PortClaim {
	return &sdnv1alpha1.PortClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a", UID: types.UID("claim-" + name)},
		Spec: sdnv1alpha1.PortClaimSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "tenant-a"},
			MAC:    mac,
			IP:     ip,
		},
	}
}

// withPods makes getPod answer from pods, NotFound otherwise.
func withPods(t *testing.T, pods ...*corev1.Pod) {
	t.Helper()
	orig := getPod
	t.Cleanup(func() { getPod = orig })
	getPod = func(_ context.Context, ns, name string) (*corev1.Pod, error) {
		for _, p := range pods {
			if p.Namespace == ns && p.Name == name {
				return p, nil
			}
		}
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, name)
	}
}

func runningPod(name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: name, UID: types.UID(uid)},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestClaimedPortFirstBind(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}
	claim := newClaim("vm1", "", "")

	ip, mac, port, bound, err := attachPort(t.Context(), client, vpc, "team-a", state, "team-a", "launcher-a", "uid-a", claim, "", "")
	if err != nil {
		t.Fatalf("attachPort: %v", err)
	}
	if bound {
		t.Error("first bind reported a pre-existing Port")
	}
	if ip.String() != "10.10.0.2" || port.Spec.MAC != mac.String() || len(mac) != 6 {
		t.Errorf("ip %s mac %s port.mac %q", ip, mac, port.Spec.MAC)
	}
	for k, want := range map[string]string{
		sdnv1alpha1.LabelClaimNamespace: "team-a",
		sdnv1alpha1.LabelClaimName:      "vm1",
		sdnv1alpha1.LabelClaimUID:       "claim-vm1",
	} {
		if port.Labels[k] != want {
			t.Errorf("label %q = %q, want %q", k, port.Labels[k], want)
		}
	}
}

func TestClaimedPortSurvivesPodRecreation(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	claim := newClaim("vm1", "", "")

	ip1, mac1, _, _, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}, "team-a", "launcher-a", "uid-a", claim, "", "")
	if err != nil {
		t.Fatalf("first attachPort: %v", err)
	}

	// The first pod is gone (VMI deleted); a new pod lands on another node.
	withPods(t)
	ip2, mac2, port, bound, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node2", NodeIP: "192.0.2.2"}, "team-a", "launcher-b", "uid-b", claim, "", "")
	if err != nil {
		t.Fatalf("second attachPort: %v", err)
	}
	if !bound || !ip2.Equal(ip1) || mac2.String() != mac1.String() {
		t.Fatalf("second bind = %s/%s bound=%v, want %s/%s bound", ip2, mac2, bound, ip1, mac1)
	}
	if port.Spec.Node != "node2" || port.Spec.NodeIP != "192.0.2.2" {
		t.Errorf("Port not taken over: node %q/%q", port.Spec.Node, port.Spec.NodeIP)
	}
	if port.Labels[sdnv1alpha1.LabelPodUID] != "uid-b" || port.Spec.PodName != "launcher-b" {
		t.Errorf("pod identity not rebound: %v %q", port.Labels, port.Spec.PodName)
	}
}

func TestClaimedPortDetachedIsTakenOver(t *testing.T) {
	claim := newClaim("vm1", "", "")
	detached := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v100.10-10-0-7", Labels: map[string]string{
			sdnv1alpha1.LabelVPCNamespace: "team-a", sdnv1alpha1.LabelVPC: "tenant-a",
			sdnv1alpha1.LabelClaimUID: "claim-vm1",
		}},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "tenant-a"},
			IP:     "10.10.0.7", MAC: "02:00:00:00:00:07",
		},
	}
	client := sdnfake.NewSimpleClientset(detached)
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")

	ip, _, port, bound, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node3", NodeIP: "192.0.2.3"}, "team-a", "launcher-c", "uid-c", claim, "", "")
	if err != nil || !bound || ip.String() != "10.10.0.7" {
		t.Fatalf("attachPort = %s bound=%v err=%v", ip, bound, err)
	}
	if port.Spec.Node != "node3" {
		t.Errorf("node = %q, want node3", port.Spec.Node)
	}
}

func TestClaimedPortLiveHolderStagesTarget(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	claim := newClaim("vm1", "", "")
	if _, _, _, _, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}, "team-a", "source", "uid-src", claim, "", ""); err != nil {
		t.Fatalf("source attachPort: %v", err)
	}

	// The source is still running: the target binds but must not take the Port.
	withPods(t, runningPod("source", "uid-src"))
	_, _, port, bound, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node2", NodeIP: "192.0.2.2"}, "team-a", "target", "uid-tgt", claim, "", "")
	if err != nil || !bound {
		t.Fatalf("target attachPort bound=%v err=%v", bound, err)
	}
	if port.Spec.Node != "node1" {
		t.Errorf("node = %q, want node1 (staged until cutover)", port.Spec.Node)
	}
}

func TestClaimedPortRecreatedFromStatus(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	claim := newClaim("vm1", "", "")
	claim.Status = sdnv1alpha1.PortClaimStatus{IP: "10.10.0.9", MAC: "02:00:00:00:00:09"}

	ip, mac, _, bound, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}, "team-a", "launcher", "uid", claim, "", "")
	if err != nil || bound {
		t.Fatalf("attachPort bound=%v err=%v", bound, err)
	}
	if ip.String() != "10.10.0.9" || mac.String() != "02:00:00:00:00:09" {
		t.Errorf("recreated as %s/%s, want the pinned 10.10.0.9/02:00:00:00:00:09", ip, mac)
	}
}

func TestClaimedPortRequests(t *testing.T) {
	other := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v100.10-10-0-5", Labels: map[string]string{
			sdnv1alpha1.LabelVPCNamespace: "team-a", sdnv1alpha1.LabelVPC: "tenant-a",
		}},
		Spec: sdnv1alpha1.PortSpec{IP: "10.10.0.5", MAC: "02:00:00:00:00:05"},
	}
	cases := []struct {
		name, mac, ip string
		wantErr       bool
	}{
		{"requested mac and ip", "02:00:00:00:00:42", "10.10.0.42", false},
		{"ip held by another port", "", "10.10.0.5", true},
		{"mac used by another port", "02:00:00:00:00:05", "", true},
		{"ip outside cidr", "", "10.11.0.5", true},
		{"reserved gateway ip", "", "10.10.0.1", true},
		{"wrong family", "", "fd00::5", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := sdnfake.NewSimpleClientset(other.DeepCopy())
			vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
			ip, mac, _, _, err := attachPort(t.Context(), client, vpc, "team-a",
				&datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}, "team-a", "p", "uid", newClaim("vm1", tc.mac, tc.ip), "", "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && (ip.String() != tc.ip || mac.String() != tc.mac) {
				t.Errorf("got %s/%s, want %s/%s", ip, mac, tc.ip, tc.mac)
			}
		})
	}
}

func TestClaimedPortInOtherVPCRefused(t *testing.T) {
	p := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v200.10-20-0-2", Labels: map[string]string{sdnv1alpha1.LabelClaimUID: "claim-vm1"}},
		Spec:       sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "other"}, IP: "10.20.0.2", MAC: "02:00:00:00:00:02"},
	}
	client := sdnfake.NewSimpleClientset(p)
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	if _, _, _, _, err := attachPort(t.Context(), client, vpc, "team-a",
		&datapath.AgentState{NodeName: "node1"}, "team-a", "p", "uid", newClaim("vm1", "", ""), "", ""); err == nil {
		t.Fatal("bound a claim's Port from another VPC")
	}
}

func TestGetPortClaimIsNamespaceLocal(t *testing.T) {
	claim := newClaim("vm1", "", "")
	gone := newClaim("gone", "", "")
	now := metav1.Now()
	gone.DeletionTimestamp = &now
	gone.Finalizers = []string{sdnv1alpha1.FinalizerPortClaim}
	client := sdnfake.NewSimpleClientset(claim, gone)
	if _, err := getPortClaim(t.Context(), client, "team-b", "vm1"); err == nil {
		t.Error("a pod in team-b resolved team-a's PortClaim")
	}
	if _, err := getPortClaim(t.Context(), client, "team-a", "gone"); err == nil {
		t.Error("a terminating PortClaim was bound")
	}
	if _, err := getPortClaim(t.Context(), client, "team-a", "vm1"); err != nil {
		t.Errorf("own PortClaim: %v", err)
	}
}

func TestBytesLess(t *testing.T) {
	if !bytesLess(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")) || bytesLess(net.ParseIP("fd00::2"), net.ParseIP("fd00::2")) {
		t.Error("bytesLess ordering")
	}
}
