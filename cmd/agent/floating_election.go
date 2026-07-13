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
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/lllamnyp/cozyplane/datapath"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

// The electorate for floating-IP announcement (docs/floating-ha.md).
//
// A node may only announce an address whose pool link it can actually put a
// frame on — attracting an address a node cannot serve is a black hole, not a
// degradation. Only a node's own FIB knows whether it can, so each node decides
// for itself and publishes the answer on its own Node object; every agent reads
// the published set and elects the same winner without talking to anyone.

// poolsAnnotation lists the ExternalPools whose link this node can serve, comma
// separated. The election reads it from every Node; each node writes only its own
// (the same self-publication pattern as nodeAddrsAnnotation).
const poolsAnnotation = "cozyplane.io/external-pools"

// nodePoolIndex is the election's view of the cluster: which nodes are Ready, and
// which pools each can serve. Fed by the Node informer, read by the floating
// resync — hence the mutex, which nodeIPIndex does not need (it is written and
// read only from the informer goroutine).
type nodePoolIndex struct {
	mu    sync.Mutex
	nodes map[string]map[string]bool // node -> servable pool names (Ready nodes only)
	subs  []func()
}

func newNodePoolIndex() *nodePoolIndex {
	return &nodePoolIndex{nodes: map[string]map[string]bool{}}
}

// onChange registers a callback fired whenever the electorate changes. The
// floating watcher re-elects on it: a node joining, leaving or going NotReady
// re-homes the addresses it would have won.
func (n *nodePoolIndex) onChange(f func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subs = append(n.subs, f)
}

// set records a node's eligibility. A NotReady node is dropped from the
// electorate rather than tracked as ineligible — losing readiness and leaving the
// cluster mean the same thing to an address that must land somewhere alive.
func (n *nodePoolIndex) set(node *corev1.Node) {
	pools := map[string]bool{}
	if nodeReady(node) {
		for _, p := range strings.Split(node.Annotations[poolsAnnotation], ",") {
			if p = strings.TrimSpace(p); p != "" {
				pools[p] = true
			}
		}
	}
	n.mu.Lock()
	changed := !samePools(n.nodes[node.Name], pools)
	if len(pools) == 0 {
		delete(n.nodes, node.Name)
	} else {
		n.nodes[node.Name] = pools
	}
	subs := append([]func(){}, n.subs...)
	n.mu.Unlock()

	// Notify outside the lock: a subscriber calls back into serving().
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

// serving returns the Ready nodes that can serve a pool's link, sorted so the
// election is deterministic even where two nodes hash equal.
func (n *nodePoolIndex) serving(pool string) []string {
	if pool == "" {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for name, pools := range n.nodes {
		if pools[pool] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func samePools(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func nodeReady(node *corev1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// publishPoolEligibility asks the FIB which ExternalPools this node can serve and
// records the answer on its own Node object, making it electable for those pools.
// A pool is servable when its addresses are ON-LINK here: an L2 announcement only
// reaches a fabric this node is actually attached to. A routed pool is servable by
// nobody, and the election falls back to the target pod's node — which is the
// pre-HA behaviour, and the right one until a BGP speaker exists to attract a
// routed address (docs/floating-ha.md § increment 2).
//
// Best-effort and idempotent, driven by the same 30s pool poll as the uplink
// setup: pools are near-static, and a node that has just booted simply becomes
// electable a poll later.
func publishPoolEligibility(ctx context.Context, kube kubernetes.Interface, sdn sdnclientset.Interface,
	mgr *datapath.Manager, nodeName string, log *slog.Logger) (string, error) {
	pools, err := sdn.SdnV1alpha1().ExternalPools().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list externalpools: %w", err)
	}
	var servable []string
	for _, p := range pools.Items {
		for _, cidr := range p.Spec.CIDRs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ok, err := mgr.PoolServable(ip.String())
			if err != nil {
				log.Warn("pool serviceability", "pool", p.Name, "cidr", cidr, "err", err)
				continue
			}
			if ok {
				servable = append(servable, p.Name)
				break // one servable CIDR makes the pool servable
			}
		}
	}
	sort.Strings(servable)
	val := strings.Join(servable, ",")
	patch := fmt.Appendf(nil, `{"metadata":{"annotations":{%q:%q}}}`, poolsAnnotation, val)
	if _, err := kube.CoreV1().Nodes().Patch(ctx, nodeName, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return val, fmt.Errorf("annotate node with servable pools: %w", err)
	}
	return val, nil
}
