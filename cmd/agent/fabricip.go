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
	"strconv"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
)

// The flat pool's delivery table (docs/api-groups.md).
//
// With a per-node carve-out, `remotes` needed one entry per node: a pod's
// address was inside its node's CIDR, so an LPM hit on the CIDR resolved the
// node. A flat pool has no such structure — an address says nothing about where
// it lives — so delivery keys on the ADDRESS: one /32 (or /128) per pod, exactly
// as VPC networks have always done (`SetRemote(net, hostCIDR(port.Spec.IP), …)`).
//
// The cost is churn: every pod create/delete now moves an entry on every node,
// where before only node joins did. So this is EVENT-SCOPED — one map write per
// event — and never a full rebuild, which at net-0 pod density would be a
// cluster-wide storm on every pod launch.

// watchFabricIPs mirrors every pod's underlay address into `remotes`, keyed by
// address. It blocks until the cache is synced: the datapath must know how to
// reach existing pods before this agent starts forwarding for new ones.
func watchFabricIPs(ctx context.Context, factory localinformers.SharedInformerFactory,
	routes *fabricRemoteReconciler, log *slog.Logger) error {
	inf := factory.Local().V1alpha1().FabricIPs().Informer()
	if err := inf.AddIndexers(fabricClaimIndexers()); err != nil {
		return fmt.Errorf("index FabricIP ownership: %w", err)
	}

	_, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    routes.apply,
		UpdateFunc: func(oldObj, newObj any) { routes.apply(oldObj); routes.apply(newObj) },
		DeleteFunc: routes.apply,
	})
	if err != nil {
		return fmt.Errorf("add fabricip handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return fmt.Errorf("fabricip cache failed to sync")
	}
	if err := routes.syncInitial(); err != nil {
		return err
	}
	log.Info("fabric IP watch synced (flat pool: remotes keyed per pod)")
	return nil
}

// fabricByPodUID resolves a pod's UNDERLAY address from the FabricIP store.
//
// This is the join that replaces `Port.spec.fabricIP` (docs/api-groups.md). The
// address lives in exactly one object; `Port` (tenant identity) and `FabricIP`
// (underlay claim) both point at the pod, and the pod UID is the key. A churned
// address — a VM migrates, a pod is re-created — updates one object, and the
// next resync programs the truth. There is no copy to go stale.
func fabricByPodUID(factory localinformers.SharedInformerFactory, podUID, containerID, ifName string) string {
	return fabricClaimAddress(factory.Local().V1alpha1().FabricIPs().Informer().GetIndexer(), podUID, containerID, ifName)
}

const (
	fabricPodUIDIndex      = "fabric-by-pod-uid"
	fabricSandboxIndex     = "fabric-by-sandbox"
	fabricNodeSandboxIndex = "fabric-by-node-sandbox"
)

func fabricTupleKey(first, second, third string) string {
	// Length prefixes keep the tuple unambiguous even for unexpected legacy
	// values containing delimiters. Identity fields are still checked on read.
	return strconv.Itoa(len(first)) + ":" + first + strconv.Itoa(len(second)) + ":" + second + third
}

func fabricClaimIndexers() cache.Indexers {
	return cache.Indexers{
		fabricPodUIDIndex: func(obj any) ([]string, error) {
			claim, ok := obj.(*localv1alpha1.FabricIP)
			if !ok || claim == nil || claim.Spec.PodUID == "" {
				return nil, nil
			}
			return []string{claim.Spec.PodUID}, nil
		},
		fabricSandboxIndex: func(obj any) ([]string, error) {
			claim, ok := obj.(*localv1alpha1.FabricIP)
			if !ok || claim == nil || claim.Spec.PodUID == "" || claim.Spec.ContainerID == "" {
				return nil, nil
			}
			return []string{fabricTupleKey(claim.Spec.PodUID, claim.Spec.ContainerID, claim.Spec.IfName)}, nil
		},
		fabricNodeSandboxIndex: func(obj any) ([]string, error) {
			claim, ok := obj.(*localv1alpha1.FabricIP)
			if !ok || claim == nil || claim.Spec.Node == "" || claim.Spec.PodNamespace == "" || claim.Spec.ContainerID == "" {
				return nil, nil
			}
			return []string{fabricTupleKey(claim.Spec.Node, claim.Spec.PodNamespace, claim.Spec.ContainerID)}, nil
		},
	}
}

func fabricClaimAddress(store cache.Indexer, podUID, containerID, ifName string) string {
	if podUID == "" {
		return ""
	}
	index, key := fabricPodUIDIndex, podUID
	if containerID != "" {
		index, key = fabricSandboxIndex, fabricTupleKey(podUID, containerID, ifName)
	}
	claims, err := store.ByIndex(index, key)
	if err != nil {
		return ""
	}
	fallback := ""
	for _, obj := range claims {
		fip, ok := obj.(*localv1alpha1.FabricIP)
		if !ok || fip == nil || fip.Spec.PodUID != podUID || (containerID != "" && (fip.Spec.ContainerID != containerID || fip.Spec.IfName != ifName)) {
			continue
		}
		// A dual-stack pod holds one claim per family; the bridge keys on the
		// v4 fabric handle (the bridges map is v4 today), so prefer it.
		if ip := net.ParseIP(fip.Spec.Address); ip != nil {
			if ip.To4() != nil {
				return fip.Spec.Address
			}
			if fallback == "" {
				fallback = fip.Spec.Address
			}
		}
	}
	// No v4 claim: fall back to whatever family the pod does hold.
	return fallback
}

// nodeIPIndex tracks node name -> underlay (Geneve) address, so a FabricIP can
// be resolved to a tunnel endpoint without a second API read.
type nodeIPIndex struct {
	mu     sync.RWMutex
	byName map[string]net.IP
	subs   []func()
}

func newNodeIPIndex() *nodeIPIndex { return &nodeIPIndex{byName: map[string]net.IP{}} }

func (n *nodeIPIndex) onChange(f func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subs = append(n.subs, f)
}

func (n *nodeIPIndex) set(node *corev1.Node) {
	ip := net.ParseIP(internalIP(node))
	n.mu.Lock()
	changed := !n.byName[node.Name].Equal(ip)
	if ip == nil {
		delete(n.byName, node.Name)
	} else {
		n.byName[node.Name] = ip
	}
	var subs []func()
	if changed {
		subs = append(subs, n.subs...)
	}
	n.mu.Unlock()
	for _, f := range subs {
		f()
	}
}

func (n *nodeIPIndex) get(name string) net.IP {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return append(net.IP(nil), n.byName[name]...)
}

func (n *nodeIPIndex) del(name string) {
	n.mu.Lock()
	_, existed := n.byName[name]
	delete(n.byName, name)
	var subs []func()
	if existed {
		subs = append(subs, n.subs...)
	}
	n.mu.Unlock()
	for _, f := range subs {
		f()
	}
}
