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
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeInternalNodes stands in for the internal_nodes map.
type fakeInternalNodes struct {
	m       map[string]bool
	puts    []string
	dels    []string
	failPut string
}

func newFakeInternalNodes(seed ...string) *fakeInternalNodes {
	f := &fakeInternalNodes{m: map[string]bool{}}
	for _, s := range seed {
		f.m[s] = true
	}
	return f
}

func (f *fakeInternalNodes) SetInternalNode(ip net.IP) error {
	if ip.String() == f.failPut {
		return errors.New("map full")
	}
	f.puts = append(f.puts, ip.String())
	f.m[ip.String()] = true
	return nil
}

func (f *fakeInternalNodes) DelInternalNode(ip net.IP) error {
	f.dels = append(f.dels, ip.String())
	delete(f.m, ip.String())
	return nil
}

func (f *fakeInternalNodes) SyncInternalNodes(ips []net.IP) error {
	f.m = map[string]bool{}
	for _, ip := range ips {
		f.m[ip.String()] = true
	}
	return nil
}

func (f *fakeInternalNodes) entries() []string {
	var out []string
	for k := range f.m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func inNode(name, annotation string, addrs ...corev1.NodeAddress) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if annotation != "" {
		n.Annotations = map[string]string{nodeAddrsAnnotation: annotation}
	}
	n.Status.Addresses = addrs
	return n
}

func inInternal(a string) corev1.NodeAddress {
	return corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: a}
}

func inExternal(a string) corev1.NodeAddress {
	return corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: a}
}

func wantEntries(t *testing.T, f *fakeInternalNodes, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := f.entries(); !slices.Equal(got, want) {
		t.Fatalf("internal_nodes = %v, want %v", got, want)
	}
}

// TestInternalNodesAdd checks both families of InternalIP, ExternalIP and the annotation.
func TestInternalNodesAdd(t *testing.T) {
	f := newFakeInternalNodes()
	tr := newInternalNodes(f)
	err := tr.set(inNode("n1", "10.0.1.9, 2001:db8:1::9",
		inInternal("10.0.0.1"), inInternal("fd00::1"),
		inExternal("203.0.113.1"), inExternal("2001:db8::1"),
		corev1.NodeAddress{Type: corev1.NodeHostName, Address: "n1"}))
	if err != nil {
		t.Fatal(err)
	}
	wantEntries(t, f, "10.0.0.1", "fd00::1", "203.0.113.1", "2001:db8::1", "10.0.1.9", "2001:db8:1::9")
}

// TestInternalNodesUpdate checks an Update writes only what changed.
func TestInternalNodesUpdate(t *testing.T) {
	f := newFakeInternalNodes()
	tr := newInternalNodes(f)
	_ = tr.set(inNode("n1", "10.0.1.9", inInternal("10.0.0.1"), inExternal("203.0.113.1"), inExternal("2001:db8::1")))
	f.puts, f.dels = nil, nil

	if err := tr.set(inNode("n1", "10.0.1.10", inInternal("10.0.0.1"), inExternal("2001:db8::2"))); err != nil {
		t.Fatal(err)
	}
	wantEntries(t, f, "10.0.0.1", "10.0.1.10", "2001:db8::2")
	slices.Sort(f.puts)
	slices.Sort(f.dels)
	if !slices.Equal(f.puts, []string{"10.0.1.10", "2001:db8::2"}) {
		t.Errorf("puts = %v", f.puts)
	}
	if !slices.Equal(f.dels, []string{"10.0.1.9", "2001:db8::1", "203.0.113.1"}) {
		t.Errorf("dels = %v", f.dels)
	}
}

// TestInternalNodesDelete checks a Delete keeps an address another node claims.
func TestInternalNodesDelete(t *testing.T) {
	f := newFakeInternalNodes()
	tr := newInternalNodes(f)
	_ = tr.set(inNode("n1", "", inInternal("10.0.0.1"), inInternal("fd00::1"), inExternal("198.51.100.7")))
	_ = tr.set(inNode("n2", "198.51.100.7", inInternal("10.0.0.2"), inInternal("fd00::2")))

	if err := tr.del("n1"); err != nil {
		t.Fatal(err)
	}
	wantEntries(t, f, "198.51.100.7", "10.0.0.2", "fd00::2")
	if err := tr.del("n2"); err != nil {
		t.Fatal(err)
	}
	wantEntries(t, f)
	if err := tr.del("never-seen"); err != nil {
		t.Fatal(err)
	}
}

// TestInternalNodesMappedV4 checks a v4-mapped annotation address is the same entry as the InternalIP.
func TestInternalNodesMappedV4(t *testing.T) {
	f := newFakeInternalNodes()
	tr := newInternalNodes(f)
	_ = tr.set(inNode("n1", "::ffff:10.0.0.1", inInternal("10.0.0.1")))
	wantEntries(t, f, "10.0.0.1")
	if len(f.puts) != 1 {
		t.Errorf("puts = %v, want one", f.puts)
	}
	_ = tr.del("n1")
	wantEntries(t, f)
}

// TestInternalNodesIndependentOfStatic checks addresses a static range covers are still node entries.
func TestInternalNodesIndependentOfStatic(t *testing.T) {
	f := newFakeInternalNodes()
	tr := newInternalNodes(f)
	_ = tr.set(inNode("n1", "", inInternal("10.244.0.1"), inExternal("192.0.2.10")))
	wantEntries(t, f, "10.244.0.1", "192.0.2.10")
	_ = tr.del("n1")
	wantEntries(t, f)
}

// TestInternalNodesResync checks resync prunes stale entries and restores failed writes.
func TestInternalNodesResync(t *testing.T) {
	f := newFakeInternalNodes("10.0.0.99")
	f.failPut = "fd00::1"
	tr := newInternalNodes(f)
	if err := tr.set(inNode("n1", "", inInternal("10.0.0.1"), inInternal("fd00::1"))); err == nil {
		t.Fatal("want the failed write reported")
	}
	wantEntries(t, f, "10.0.0.1", "10.0.0.99")
	if err := tr.resync(); err != nil {
		t.Fatal(err)
	}
	wantEntries(t, f, "10.0.0.1", "fd00::1")
}
