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
	"fmt"
	"reflect"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

type recordingVPCNetworks struct{ ops []string }

type realizedVPCNetworks struct {
	entries     map[vpcNetworkKey]bool
	failCounter bool
}

func (w *realizedVPCNetworks) SetNetwork(s uint32, c string, n uint32) error {
	w.entries[vpcNetworkKey{s, c}] = true
	return nil
}
func (w *realizedVPCNetworks) DelNetwork(s uint32, c string) error {
	delete(w.entries, vpcNetworkKey{s, c})
	return nil
}
func (w *realizedVPCNetworks) EnsureVPCCounter(n uint32) error {
	if w.failCounter {
		w.failCounter = false
		return fmt.Errorf("test counter failure")
	}
	return nil
}

func TestNetworkPartialWriteSupersededByNewDesiredState(t *testing.T) {
	for _, target := range []int32{0, 100, 101, 102} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			a := vpcObj("test", "vpc", 100)
			a.Spec.CIDRs = []string{"10.0.0.0/24"}
			b := a.DeepCopy()
			b.Status.VNI = 101
			state := &vpcNetworkState{applied: map[string]*sdn.VPC{"test/vpc": a}}
			writer := &realizedVPCNetworks{entries: projectedVPCNetworks(a), failCounter: true}
			if e := state.sync(writer, "test/vpc", b); e == nil {
				t.Fatal("missing injected failure")
			}
			var next *sdn.VPC
			if target != 0 {
				next = a.DeepCopy()
				next.Status.VNI = target
			}
			if e := state.sync(writer, "test/vpc", next); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(writer.entries, projectedVPCNetworks(next)) {
				t.Fatalf("realized map %v want %v", writer.entries, projectedVPCNetworks(next))
			}
			if target == 0 && (len(state.applied) != 0 || len(state.dirty) != 0) {
				t.Fatal("deleted projection retained in memory")
			}
		})
	}
}

func (w *recordingVPCNetworks) SetNetwork(scope uint32, cidr string, network uint32) error {
	w.ops = append(w.ops, fmt.Sprintf("set:%d:%s:%d", scope, cidr, network))
	return nil
}
func (w *recordingVPCNetworks) DelNetwork(scope uint32, cidr string) error {
	w.ops = append(w.ops, fmt.Sprintf("del:%d:%s", scope, cidr))
	return nil
}
func (w *recordingVPCNetworks) EnsureVPCCounter(network uint32) error {
	w.ops = append(w.ops, fmt.Sprintf("counter:%d", network))
	return nil
}

func TestNetworkProjectionRemovesOldScopeWithoutStatusIO(t *testing.T) {
	old := vpcObj("test", "vpc", 100)
	old.Spec.CIDRs = []string{"10.0.0.0/24"}
	for _, tc := range []struct {
		vni  int32
		want []string
	}{{0, []string{"del:100:10.0.0.0/24"}}, {1 << 22, []string{"del:100:10.0.0.0/24"}}, {101, []string{"del:100:10.0.0.0/24", "set:101:10.0.0.0/24:101", "counter:101"}}, {100, nil}} {
		next := old.DeepCopy()
		next.Status.VNI = tc.vni
		next.Status.Phase = sdn.VPCPhaseReady
		w := &recordingVPCNetworks{}
		if err := syncVPCNetworks(w, old, next); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(w.ops, tc.want) {
			t.Errorf("VNI %d operations %v want %v", tc.vni, w.ops, tc.want)
		}
	}
}

type faultVPCNetworks struct {
	recordingVPCNetworks
	failAt, calls int
}

func (w *faultVPCNetworks) step() error {
	w.calls++
	if w.calls == w.failAt {
		return fmt.Errorf("test map write failure")
	}
	return nil
}
func (w *faultVPCNetworks) SetNetwork(s uint32, c string, n uint32) error {
	if e := w.step(); e != nil {
		return e
	}
	return w.recordingVPCNetworks.SetNetwork(s, c, n)
}
func (w *faultVPCNetworks) DelNetwork(s uint32, c string) error {
	if e := w.step(); e != nil {
		return e
	}
	return w.recordingVPCNetworks.DelNetwork(s, c)
}
func (w *faultVPCNetworks) EnsureVPCCounter(n uint32) error {
	if e := w.step(); e != nil {
		return e
	}
	return w.recordingVPCNetworks.EnsureVPCCounter(n)
}

func TestNetworkStateRetriesPartialFailuresAndDropsDeletedState(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		old := vpcObj("test", "vpc", 100)
		old.Spec.CIDRs = []string{"10.0.0.0/24"}
		next := old.DeepCopy()
		next.Status.VNI = 101
		state := &vpcNetworkState{applied: map[string]*sdn.VPC{"test/vpc": old}}
		w := &faultVPCNetworks{failAt: failAt}
		if e := state.sync(w, "test/vpc", next); e == nil {
			t.Fatalf("write %d did not fail", failAt)
		}
		if state.applied["test/vpc"].Status.VNI != 100 {
			t.Fatal("partial state was committed")
		}
		if e := state.sync(w, "test/vpc", next); e != nil {
			t.Fatal(e)
		}
		before := len(w.ops)
		if e := state.sync(w, "test/vpc", next.DeepCopy()); e != nil {
			t.Fatal(e)
		}
		if len(w.ops) != before {
			t.Fatal("identical ACK produced map I/O")
		}
		if e := state.sync(w, "test/vpc", nil); e != nil {
			t.Fatal(e)
		}
		if len(state.applied) != 0 {
			t.Fatal("deleted VPC retained in Go state")
		}
	}
}
