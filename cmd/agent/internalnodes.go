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
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// internalNodeSink is the datapath side of internalNodes (datapath.Manager).
type internalNodeSink interface {
	SetInternalNode(net.IP) error
	DelInternalNode(net.IP) error
	SyncInternalNodes([]net.IP) error
}

// internalNodes keeps internal_nodes equal to the union of every node's npNodeAddresses.
type internalNodes struct {
	mu    sync.Mutex
	sink  internalNodeSink
	nodes map[string][]netip.Addr
	refs  map[netip.Addr]int
}

func newInternalNodes(sink internalNodeSink) *internalNodes {
	return &internalNodes{sink: sink, nodes: map[string][]netip.Addr{}, refs: map[netip.Addr]int{}}
}

// set records a node's current addresses.
func (t *internalNodes) set(node *corev1.Node) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.replace(node.Name, nodeAddrSet(node))
}

// del forgets a node.
func (t *internalNodes) del(name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.replace(name, nil)
}

// replace swaps a node's addresses, writing those whose claim count crosses zero.
func (t *internalNodes) replace(name string, want []netip.Addr) error {
	old := t.nodes[name]
	if len(want) == 0 {
		delete(t.nodes, name)
	} else {
		t.nodes[name] = want
	}
	var errs []error
	for _, a := range want {
		if slices.Contains(old, a) {
			continue
		}
		t.refs[a]++
		if t.refs[a] == 1 {
			errs = append(errs, t.sink.SetInternalNode(net.IP(a.AsSlice())))
		}
	}
	for _, a := range old {
		if slices.Contains(want, a) {
			continue
		}
		t.refs[a]--
		if t.refs[a] <= 0 {
			delete(t.refs, a)
			errs = append(errs, t.sink.DelInternalNode(net.IP(a.AsSlice())))
		}
	}
	return errors.Join(errs...)
}

// resync rewrites internal_nodes from the recorded nodes.
func (t *internalNodes) resync() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ips := make([]net.IP, 0, len(t.refs))
	for a := range t.refs {
		ips = append(ips, net.IP(a.AsSlice()))
	}
	return t.sink.SyncInternalNodes(ips)
}

// nodeAddrSet returns npNodeAddresses as distinct, unmapped netip.Addrs.
func nodeAddrSet(node *corev1.Node) []netip.Addr {
	var out []netip.Addr
	for _, ip := range npNodeAddresses(node) {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}
