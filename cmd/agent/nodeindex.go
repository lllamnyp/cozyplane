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
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// nodePoolIndex is the agent's view of which nodes are Ready.
//
// It exists for one thing: a NAT port block is used only once every Ready node
// has acked its lease (docs/vpc-egress.md §4.3), so the agents need the Ready set.
//
// It used to carry, in addition, which ExternalPools each node could put a frame
// on — the electorate for announcing floating addresses. Cozyplane does not
// announce any more (tenet 3), so the electorate went with the election.
type nodePoolIndex struct {
	mu    sync.Mutex
	nodes map[string]bool // Ready nodes
	subs  []func()
}

func newNodePoolIndex() *nodePoolIndex {
	return &nodePoolIndex{nodes: map[string]bool{}}
}

// onChange registers a callback fired whenever the node set changes: a block's
// required acks change with it.
func (n *nodePoolIndex) onChange(f func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subs = append(n.subs, f)
}

// set records a node's readiness. A NotReady node is not waited for: its agent
// may not be running to ack.
func (n *nodePoolIndex) set(node *corev1.Node) {
	ready := nodeReady(node)
	n.mu.Lock()
	changed := n.nodes[node.Name] != ready
	if ready {
		n.nodes[node.Name] = true
	} else {
		delete(n.nodes, node.Name)
	}
	subs := append([]func(){}, n.subs...)
	n.mu.Unlock()

	// Notify outside the lock: a subscriber calls back in.
	if changed {
		for _, f := range subs {
			f()
		}
	}
}

func (n *nodePoolIndex) del(name string) {
	n.mu.Lock()
	_, had := n.nodes[name]
	delete(n.nodes, name)
	subs := append([]func(){}, n.subs...)
	n.mu.Unlock()
	if had {
		for _, f := range subs {
			f()
		}
	}
}

// sortedNames returns the Ready nodes, sorted.
func (n *nodePoolIndex) sortedNames() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.nodes))
	for name := range n.nodes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func nodeReady(node *corev1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
