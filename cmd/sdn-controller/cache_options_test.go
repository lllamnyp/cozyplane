package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Helm release Secrets (owner=helm) must stay out of the controller's cache:
// cached cluster-wide they OOM-killed it after a platform upgrade. Every other
// Secret, labelled or not, is still cached.
func TestControllerCacheLeavesHelmReleasesOut(t *testing.T) {
	var sel labels.Selector
	for obj, by := range controllerCacheOptions().ByObject {
		if _, ok := obj.(*corev1.Secret); ok {
			sel = by.Label
		}
	}
	if sel == nil {
		t.Fatal("no label selector on the Secret cache")
	}
	for _, tc := range []struct {
		labels labels.Set
		cached bool
	}{
		{labels.Set{"owner": "helm", "name": "cozyplane"}, false},
		{labels.Set{}, true},
		{labels.Set{"owner": "someone-else"}, true},
		{labels.Set{"sdn.cozystack.io/wireguard-client-state": "true"}, true},
	} {
		if got := sel.Matches(tc.labels); got != tc.cached {
			t.Errorf("labels %v: cached=%t, want %t", tc.labels, got, tc.cached)
		}
	}
}
