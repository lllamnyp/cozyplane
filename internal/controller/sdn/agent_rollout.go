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
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AgentRolloutReady gates new membership encoding until every scheduled agent
// runs the image shipped with this controller. A partial rollout is not enough.
func AgentRolloutReady(ctx context.Context, reader client.Reader, namespace, image string) (bool, error) {
	if namespace == "" || !strings.Contains(image, "@sha256:") {
		return false, fmt.Errorf("pending SG policy requires an explicit agent namespace and digest-pinned image")
	}
	var ds appsv1.DaemonSet
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "cozyplane-agent"}, &ds); err != nil {
		return false, err
	}
	found := false
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "agent" && c.Image == image {
			found = true
		}
	}
	status := ds.Status
	if !found || ds.UID == "" || status.NumberMisscheduled != 0 || status.DesiredNumberScheduled <= 0 || status.ObservedGeneration < ds.Generation || status.UpdatedNumberScheduled != status.DesiredNumberScheduled || status.NumberReady != status.DesiredNumberScheduled || status.NumberAvailable != status.DesiredNumberScheduled {
		return false, nil
	}
	var pods corev1.PodList
	if err := reader.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	nodes := map[string]bool{}
	for _, p := range pods.Items {
		owner := metav1.GetControllerOf(&p)
		if owner == nil || owner.UID != ds.UID {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if p.DeletionTimestamp != nil || p.Spec.NodeName == "" || nodes[p.Spec.NodeName] {
			return false, nil
		}
		compatible := false
		for _, c := range p.Spec.Containers {
			if c.Name == "agent" && c.Image == image {
				compatible = true
			}
		}
		ready := false
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if !compatible || !ready {
			return false, nil
		}
		nodes[p.Spec.NodeName] = true
	}
	return len(nodes) == int(status.DesiredNumberScheduled), nil
}

// Share a short negative cache across pending Ports. Positive results are
// always checked live; a rollback must not inherit a cached capability grant.
func AgentRolloutGate(reader client.Reader, namespace, image string) func(context.Context) (bool, error) {
	var mu sync.Mutex
	var retryAt time.Time
	var lastError error
	return func(ctx context.Context) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if time.Now().Before(retryAt) {
			return false, lastError
		}
		ready, err := AgentRolloutReady(ctx, reader, namespace, image)
		if !ready {
			retryAt = time.Now().Add(time.Second)
			lastError = err
		} else {
			retryAt = time.Time{}
		}
		return ready, err
	}
}
