package main

import (
	"net"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNodeIPIndexConcurrentUpdatesAndRemoval(t *testing.T) {
	index := newNodeIPIndex()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1"}}}}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for j := 0; j < 1000; j++ {
				index.set(node)
				ip := index.get(node.Name)
				if len(ip) > 0 {
					ip[0] = 0
				}
				index.del(node.Name)
			}
		})
	}
	workers.Wait()
	index.set(node)
	if !index.get(node.Name).Equal(net.ParseIP("192.0.2.1")) {
		t.Fatal("caller modified cached IP")
	}
	index.set(&corev1.Node{ObjectMeta: node.ObjectMeta})
	if index.get(node.Name) != nil {
		t.Fatal("removed InternalIP remains cached")
	}
}

func TestRemovedNodeAddresses(t *testing.T) {
	old := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	removed := removedNodeAddresses(old, []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")})
	if len(removed) != 1 || !removed[0].Equal(old[0]) {
		t.Fatalf("wrong addresses revoked: %v", removed)
	}
}
