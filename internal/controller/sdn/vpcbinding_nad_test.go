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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// nadScheme registers Multus's kind as unstructured, the way the reconciler
// handles it — the controller deliberately does not import the Multus API module
// for one object with one string field.
func nadScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := testScheme(t)
	s.AddKnownTypeWithName(nadGVK, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(nadGVK.GroupVersion().WithKind(nadGVK.Kind+"List"), &unstructured.UnstructuredList{})
	return s
}

func getNAD(t *testing.T, c client.Client, ns, name string) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(nadGVK)
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, u); err != nil {
		return nil
	}
	return u
}

func reconcileBinding(t *testing.T, c client.Client, s *runtime.Scheme, ns, name string) {
	t.Helper()
	r := &VPCBindingReconciler{Client: c, Scheme: s, emitNAD: true}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

// A KubeVirt VM cannot name a VPC: spec.networks admits only `pod` and `multus`.
// The binding is mirrored into the shim that gives it a name to use.
func TestBindingEmitsNAD(t *testing.T) {
	s := nadScheme(t)
	b := vpcBinding("team-a", "use-back", "team-a", "back", true)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(b).Build()
	reconcileBinding(t, c, s, "team-a", "use-back")

	nad := getNAD(t, c, "team-a", "back")
	if nad == nil {
		t.Fatal("no NetworkAttachmentDefinition was created for the binding")
	}
	cfg, found, err := unstructured.NestedString(nad.Object, "spec", "config")
	if err != nil || !found {
		t.Fatalf("spec.config missing: found=%v err=%v", found, err)
	}
	if !strings.Contains(cfg, `"type":"cozyplane"`) {
		t.Errorf("config %q does not delegate to cozyplane", cfg)
	}
	// The VPC must be fully qualified: Multus resolves the NAD in the pod's
	// namespace, which is not necessarily the VPC's owner.
	if !strings.Contains(cfg, `"vpc":"team-a/back"`) {
		t.Errorf("config %q does not name the VPC as <owner-ns>/<name>", cfg)
	}
	// Owned, so revoking the binding removes it by ordinary GC rather than by
	// another finalizer.
	owners := nad.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Name != "use-back" || owners[0].Kind != "VPCBinding" {
		t.Errorf("owner references = %+v, want the VPCBinding", owners)
	}
}

// A VPC consumed from another namespace gets a NAD THERE. That is the whole
// reason the shim is per-binding: Multus resolves networkName in the pod's
// namespace, and the binding is what authorizes that namespace.
func TestBindingEmitsNADInTheConsumerNamespace(t *testing.T) {
	s := nadScheme(t)
	b := vpcBinding("team-b", "use-a-back", "team-a", "back", true)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(b).Build()
	reconcileBinding(t, c, s, "team-b", "use-a-back")

	if getNAD(t, c, "team-b", "back") == nil {
		t.Error("no NAD in the consuming namespace, where the pod will look for it")
	}
	if getNAD(t, c, "team-a", "back") != nil {
		t.Error("a NAD appeared in the VPC's owner namespace, which nothing asked for")
	}
}

// Without Multus there is no kind to create and nothing for a VM to reference.
// The manager gates on RESTMapping; the reconciler must honour the flag.
func TestBindingEmitsNoNADWithoutMultus(t *testing.T) {
	s := nadScheme(t)
	b := vpcBinding("team-a", "use-back", "team-a", "back", true)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(b).Build()

	r := &VPCBindingReconciler{Client: c, Scheme: s} // emitNAD false
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "team-a", Name: "use-back"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if getNAD(t, c, "team-a", "back") != nil {
		t.Error("a NAD was created on a cluster that does not serve the kind")
	}
}

// Two bindings authorizing one VPC in one namespace describe one network. The
// second must converge on the same object, not fight the first.
func TestTwoBindingsForOneVPCConvergeOnOneNAD(t *testing.T) {
	s := nadScheme(t)
	b1 := vpcBinding("team-a", "use-back", "team-a", "back", true)
	b2 := vpcBinding("team-a", "use-back-too", "team-a", "back", true)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(b1, b2).Build()

	reconcileBinding(t, c, s, "team-a", "use-back")
	reconcileBinding(t, c, s, "team-a", "use-back-too")

	var list unstructured.UnstructuredList
	list.SetGroupVersionKind(nadGVK.GroupVersion().WithKind(nadGVK.Kind + "List"))
	if err := c.List(context.Background(), &list, client.InNamespace("team-a")); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("got %d NADs for one network, want 1", len(list.Items))
	}
}

// An operator's own NAD under this name is not ours to adopt: taking ownership
// would make revoking any binding delete an object cozyplane never created.
func TestBindingDoesNotAdoptAForeignNAD(t *testing.T) {
	s := nadScheme(t)
	b := vpcBinding("team-a", "use-back", "team-a", "back", true)

	foreign := &unstructured.Unstructured{}
	foreign.SetGroupVersionKind(nadGVK)
	foreign.SetName("back")
	foreign.SetNamespace("team-a")
	foreign.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "Deployment", Name: "someone-else", UID: "u1",
	}})

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(b, foreign).Build()
	reconcileBinding(t, c, s, "team-a", "use-back")

	nad := getNAD(t, c, "team-a", "back")
	if nad == nil {
		t.Fatal("the pre-existing NAD disappeared")
	}
	owners := nad.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Name != "someone-else" {
		t.Errorf("owner references = %+v, want the original owner untouched", owners)
	}
}
