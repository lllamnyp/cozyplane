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
	"io"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
)

func healLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// claimMap is a fabricIPGetter over a plain map — the informer store's contract
// without the informer.
type claimMap map[string]*localv1alpha1.FabricIP

func (c claimMap) Get(name string) (*localv1alpha1.FabricIP, error) {
	if f, ok := c[name]; ok {
		return f, nil
	}
	return nil, apierrors.NewNotFound(
		schema.GroupResource{Group: localv1alpha1.GroupName, Resource: "fabricips"}, name)
}

func podOn(node, ns, name, uid string, ips ...string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, ip := range ips {
		p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: ip})
	}
	if len(ips) > 0 {
		p.Status.PodIP = ips[0]
	}
	return p
}

// The regression: a running pod whose claim went missing is unreachable from
// every other node, and nothing used to put the claim back.
func TestHealRecreatesMissingClaim(t *testing.T) {
	pod := podOn("node0", "kube-system", "capi-operator", "uid-1", "10.244.0.7")
	kc := k8sfake.NewSimpleClientset(pod)
	lc := localfake.NewSimpleClientset()

	if err := periodicFixtureHealOnce(context.Background(), kc, lc, claimMap{}, "node0", healLogger()); err != nil {
		t.Fatalf("heal: %v", err)
	}

	got, err := lc.LocalV1alpha1().FabricIPs().Get(
		context.Background(), localv1alpha1.FabricIPName("10.244.0.7"), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("claim was not re-created: %v", err)
	}
	if got.Spec.Address != "10.244.0.7" || got.Spec.Node != "node0" ||
		got.Spec.PodNamespace != "kube-system" || got.Spec.PodName != "capi-operator" ||
		got.Spec.PodUID != "uid-1" {
		t.Errorf("spec does not identify the pod: %+v", got.Spec)
	}
	// The labels the CNI writes, so selector-based lookups find this claim too.
	for k, want := range map[string]string{
		localv1alpha1.LabelFabricPodUID:       "uid-1",
		localv1alpha1.LabelFabricPodNamespace: "kube-system",
		localv1alpha1.LabelFabricNode:         "node0",
	} {
		if got.Labels[k] != want {
			t.Errorf("label %s = %q, want %q", k, got.Labels[k], want)
		}
	}
	if fabricMissing.Load() != 1 {
		t.Errorf("fabric_ips_missing = %d, want 1", fabricMissing.Load())
	}
}

// Dual-stack: a pod holds one claim per family, so both must be healed.
func TestHealRecreatesBothFamilies(t *testing.T) {
	pod := podOn("node0", "ns", "p", "uid-2", "10.244.0.8", "fd00:10:244::8")
	kc := k8sfake.NewSimpleClientset(pod)
	lc := localfake.NewSimpleClientset()

	if err := periodicFixtureHealOnce(context.Background(), kc, lc, claimMap{}, "node0", healLogger()); err != nil {
		t.Fatalf("heal: %v", err)
	}
	for _, ip := range []string{"10.244.0.8", "fd00:10:244::8"} {
		if _, err := lc.LocalV1alpha1().FabricIPs().Get(
			context.Background(), localv1alpha1.FabricIPName(ip), metav1.GetOptions{}); err != nil {
			t.Errorf("claim for %s missing: %v", ip, err)
		}
	}
}

// A claim already held by the same pod is left alone — the heal must be a no-op
// in the overwhelmingly common case.
func TestHealLeavesOwnClaimAlone(t *testing.T) {
	pod := podOn("node0", "ns", "p", "uid-3", "10.244.0.9")
	kc := k8sfake.NewSimpleClientset(pod)
	lc := localfake.NewSimpleClientset()
	claims := claimMap{localv1alpha1.FabricIPName("10.244.0.9"): {
		ObjectMeta: metav1.ObjectMeta{Name: localv1alpha1.FabricIPName("10.244.0.9")},
		Spec:       localv1alpha1.FabricIPSpec{Address: "10.244.0.9", PodUID: "uid-3"},
	}}

	if err := periodicFixtureHealOnce(context.Background(), kc, lc, claims, "node0", healLogger()); err != nil {
		t.Fatalf("heal: %v", err)
	}
	list, _ := lc.LocalV1alpha1().FabricIPs().List(context.Background(), metav1.ListOptions{})
	if len(list.Items) != 1 {
		t.Errorf("claim count changed: %d", len(list.Items))
	}
	if fabricMissing.Load() != 0 || fabricConflict.Load() != 0 {
		t.Errorf("missing=%d conflicted=%d, want 0/0", fabricMissing.Load(), fabricConflict.Load())
	}
}

// A claim held by a DIFFERENT pod is a real double allocation. Report it; do not
// delete or overwrite, which would strand whichever pod is the honest holder.
func TestHealReportsConflictWithoutTouchingIt(t *testing.T) {
	pod := podOn("node0", "ns", "newcomer", "uid-new", "10.244.0.10")
	kc := k8sfake.NewSimpleClientset(pod)
	lc := localfake.NewSimpleClientset()
	name := localv1alpha1.FabricIPName("10.244.0.10")
	claims := claimMap{name: {
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: localv1alpha1.FabricIPSpec{
			Address: "10.244.0.10", PodUID: "uid-incumbent",
			PodNamespace: "ns", PodName: "incumbent",
		},
	}}

	if err := periodicFixtureHealOnce(context.Background(), kc, lc, claims, "node0", healLogger()); err != nil {
		t.Fatalf("heal: %v", err)
	}
	if fabricConflict.Load() != 1 {
		t.Errorf("fabric_ips_conflicted = %d, want 1", fabricConflict.Load())
	}
	if list, _ := lc.LocalV1alpha1().FabricIPs().List(context.Background(), metav1.ListOptions{}); len(list.Items) != 1 {
		t.Errorf("claim count changed over a conflict: %d", len(list.Items))
	}
	if claims[name].Spec.PodUID != "uid-incumbent" {
		t.Error("the incumbent claim was mutated")
	}
}

// Only this node's pods, and only via the field selector — listing every pod in
// the cluster on every node every minute is not acceptable.
func TestHealListsOnlyItsOwnNode(t *testing.T) {
	kc := k8sfake.NewSimpleClientset(podOn("node0", "ns", "mine", "uid-a", "10.244.0.11"))
	lc := localfake.NewSimpleClientset()

	var seen string
	kc.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		seen = a.(k8stesting.ListAction).GetListRestrictions().Fields.String()
		return false, nil, nil
	})
	if err := periodicFixtureHealOnce(context.Background(), kc, lc, claimMap{}, "node0", healLogger()); err != nil {
		t.Fatalf("heal: %v", err)
	}
	if want := "spec.nodeName=node0,status.phase=Running"; seen != want {
		t.Errorf("list field selector = %q, want %q", seen, want)
	}
}

// Pods that must never get a claim.
func TestPodFabricAddrsSkips(t *testing.T) {
	hostNet := podOn("node0", "ns", "h", "u", "10.20.0.1")
	hostNet.Spec.HostNetwork = true
	if got := podFabricAddrs(hostNet); got != nil {
		t.Errorf("hostNetwork pod: got %v, want nil (it shares the node's address)", got)
	}

	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
		p := podOn("node0", "ns", "d", "u", "10.244.0.12")
		p.Status.Phase = phase
		if got := podFabricAddrs(p); got != nil {
			t.Errorf("%s pod: got %v, want nil (no sandbox to reach)", phase, got)
		}
	}

	unwired := podOn("node0", "ns", "u", "u")
	if got := podFabricAddrs(unwired); got != nil {
		t.Errorf("pod with no address: got %v, want nil", got)
	}

	// Older kubelets fill only the scalar field.
	scalar := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.13"},
	}
	if got := podFabricAddrs(scalar); len(got) != 1 || got[0] != "10.244.0.13" {
		t.Errorf("scalar-only podIP: got %v, want [10.244.0.13]", got)
	}
}

// These fixtures model the kernel-owned inventory independently of Pod status.
// Existing claims live in the API, which is authoritative during repair.
func periodicFixtureHealOnce(ctx context.Context, kc *k8sfake.Clientset, lc *localfake.Clientset, claims claimMap, node string, log *slog.Logger) error {
	for name, claim := range claims {
		copy := claim.DeepCopy()
		if copy.Spec.Node == "" {
			copy.Spec.Node = node
		}
		if _, err := lc.LocalV1alpha1().FabricIPs().Get(ctx, name, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			if _, err := lc.LocalV1alpha1().FabricIPs().Create(ctx, copy, metav1.CreateOptions{}); err != nil {
				return err
			}
		}
	}
	obj, err := kc.Tracker().List(corev1.SchemeGroupVersion.WithResource("pods"), corev1.SchemeGroupVersion.WithKind("Pod"), "")
	if err != nil {
		return err
	}
	var endpoints []datapath.LocalFabricIP
	for _, pod := range obj.(*corev1.PodList).Items {
		for _, ip := range podFabricAddrs(&pod) {
			endpoints = append(endpoints, datapath.LocalFabricIP{Address: ip, ContainerID: "sandbox", IfName: "eth0"})
		}
	}
	return healFabricIPsOnce(ctx, kc, lc, claims, node, log, func() ([]datapath.LocalFabricIP, error) { return endpoints, nil })
}
