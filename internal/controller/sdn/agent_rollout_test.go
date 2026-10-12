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
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const compatibleAgentImage = "example.invalid/cozyplane@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func rolloutPods() []client.Object {
	var objects []client.Object
	for i := 0; i < 3; i++ {
		controller := true
		objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("test-agent-%d", i), Namespace: "test-system", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "cozyplane-agent", UID: "test-ds-uid", Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: fmt.Sprintf("test-node-%d", i), Containers: []corev1.Container{{Name: "agent", Image: compatibleAgentImage}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}})
	}
	return objects
}

func TestPendingSGRequiresCompleteCompatibleRollout(t *testing.T) {
	scheme := runtime.NewScheme()
	if e := appsv1.AddToScheme(scheme); e != nil {
		t.Fatal(e)
	}
	if e := corev1.AddToScheme(scheme); e != nil {
		t.Fatal(e)
	}
	ready := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "cozyplane-agent", Namespace: "test-system", Generation: 2}, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: "test-compatible-image"}}}}}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, UpdatedNumberScheduled: 3, NumberReady: 3, NumberAvailable: 3, ObservedGeneration: 2}}
	for _, tc := range []struct {
		name   string
		change func(*appsv1.DaemonSet)
		want   bool
	}{
		{"complete", func(*appsv1.DaemonSet) {}, true},
		{"old binary", func(d *appsv1.DaemonSet) { d.Spec.Template.Spec.Containers[0].Image = "test-old-image" }, false},
		{"one old node", func(d *appsv1.DaemonSet) { d.Status.UpdatedNumberScheduled = 2 }, false},
		{"unready", func(d *appsv1.DaemonSet) { d.Status.NumberReady = 2 }, false},
		{"unavailable", func(d *appsv1.DaemonSet) { d.Status.NumberAvailable = 2 }, false},
		{"stale generation", func(d *appsv1.DaemonSet) { d.Status.ObservedGeneration = 1 }, false},
		{"empty", func(d *appsv1.DaemonSet) { d.Status.DesiredNumberScheduled = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := ready.DeepCopy()
			ds.UID = "test-ds-uid"
			ds.Spec.Template.Spec.Containers[0].Image = compatibleAgentImage
			tc.change(ds)
			objects := append(rolloutPods(), ds)
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			got, e := AgentRolloutReady(context.Background(), reader, "test-system", compatibleAgentImage)
			if e != nil || got != tc.want {
				t.Fatalf("ready %v, error %v", got, e)
			}
		})
	}
}

func TestPendingSGRejectsOldAgentOnRemovedNodeAndNegativeCache(t *testing.T) {
	scheme := runtime.NewScheme()
	appsv1.AddToScheme(scheme)
	corev1.AddToScheme(scheme)
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "cozyplane-agent", Namespace: "test-system", UID: "test-ds-uid", Generation: 2}, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: compatibleAgentImage}}}}}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, UpdatedNumberScheduled: 3, NumberReady: 3, NumberAvailable: 3, ObservedGeneration: 2}}
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{"removed node", func(p *corev1.Pod) { p.Spec.NodeName = "removed-node"; p.Spec.Containers[0].Image = "old-agent" }},
		{"terminating", func(p *corev1.Pod) {
			now := metav1.Now()
			p.DeletionTimestamp = &now
			p.Finalizers = []string{"test-finalizer"}
		}},
		{"duplicate", func(p *corev1.Pod) { p.Spec.NodeName = "test-node-0" }},
		{"not-ready", func(p *corev1.Pod) { p.Status.Conditions = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := rolloutPods()
			extra := objects[0].(*corev1.Pod).DeepCopy()
			extra.Name = "old-agent-survivor"
			tc.mutate(extra)
			objects = append(objects, extra, ds)
			base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			reader := &countingRolloutReader{Reader: base}
			gate := AgentRolloutGate(reader, "test-system", compatibleAgentImage)
			for i := 0; i < 2; i++ {
				if ready, e := gate(context.Background()); e != nil || ready {
					t.Fatalf("unsafe rollout accepted: %v %v", ready, e)
				}
			}
			if reader.gets != 1 || reader.lists != 1 {
				t.Fatalf("negative cache did not bound I/O: %d %d", reader.gets, reader.lists)
			}
		})
	}
	reader := &countingRolloutReader{Reader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(append(rolloutPods(), ds)...).Build()}
	gate := AgentRolloutGate(reader, "test-system", compatibleAgentImage)
	for i := 0; i < 2; i++ {
		if ready, e := gate(context.Background()); e != nil || !ready {
			t.Fatal(ready, e)
		}
	}
	if reader.gets != 2 || reader.lists != 2 {
		t.Fatal("positive grant was cached")
	}
}

type countingRolloutReader struct {
	client.Reader
	gets, lists int
}

func (r *countingRolloutReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.gets++
	return r.Reader.Get(ctx, key, obj, opts...)
}
func (r *countingRolloutReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.lists++
	return r.Reader.List(ctx, list, opts...)
}
