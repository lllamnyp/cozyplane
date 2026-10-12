package main

import (
	"net"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNodeEndpointChangesNotifyAfterPublication(t *testing.T) {
	index := newNodeIPIndex()
	updates := make(chan net.IP, 8)
	index.onChange(func() { updates <- index.get("node-a") })
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{
		Addresses:  []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1"}},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
	}}
	apply := func(operation func(), want string) {
		t.Helper()
		done := make(chan struct{})
		go func() { operation(); close(done) }()
		select {
		case got := <-updates:
			if !got.Equal(net.ParseIP(want)) {
				t.Fatalf("callback read stale endpoint %s want %s", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("endpoint update failed to notify or called reader under its lock")
		}
		<-done
	}
	apply(func() { index.set(node) }, "192.0.2.1")
	index.set(node.DeepCopy()) // unchanged endpoint, including a readiness heartbeat
	select {
	case <-updates:
		t.Fatal("unchanged endpoint triggered full reconciliation")
	default:
	}
	node.Status.Addresses[0].Address = "192.0.2.2"
	apply(func() { index.set(node) }, "192.0.2.2") // readiness stays True
	node.Status.Addresses = nil
	apply(func() { index.set(node) }, "")
	index.del(node.Name) // already withdrawn: no duplicate notification
	select {
	case <-updates:
		t.Fatal("absent endpoint deletion triggered reconciliation")
	default:
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.3"}}
	apply(func() { index.set(node) }, "192.0.2.3")
	apply(func() { index.del(node.Name) }, "")
}
