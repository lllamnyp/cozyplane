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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
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
	mgr *datapath.Manager, nodeIPOf func(string) net.IP, selfName string, log *slog.Logger) error {
	inf := factory.Local().V1alpha1().FabricIPs().Informer()

	apply := func(obj any) {
		fip, ok := obj.(*localv1alpha1.FabricIP)
		if !ok {
			return
		}
		ip := net.ParseIP(fip.Spec.Address)
		if ip == nil || fip.Spec.Node == "" {
			return
		}
		// A local pod is delivered by the `locals` map (the CNI wrote it at ADD);
		// a remotes entry for it would send our own pods' traffic out the overlay
		// and back. Only remote pods belong here.
		if fip.Spec.Node == selfName {
			if err := mgr.DelRemote(0, hostCIDR(fip.Spec.Address)); err != nil {
				log.Debug("del remote (now local)", "addr", fip.Spec.Address, "err", err)
			}
			return
		}
		node := nodeIPOf(fip.Spec.Node)
		if node == nil {
			// The Node object has not arrived yet. The node watch re-applies on
			// every node event, so this resolves itself.
			return
		}
		if err := mgr.SetRemote(0, hostCIDR(fip.Spec.Address), node); err != nil {
			log.Error("set remote", "addr", fip.Spec.Address, "node", fip.Spec.Node, "err", err)
		}
	}

	_, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			fip, ok := obj.(*localv1alpha1.FabricIP)
			if !ok {
				if tomb, ok2 := obj.(cache.DeletedFinalStateUnknown); ok2 {
					fip, ok = tomb.Obj.(*localv1alpha1.FabricIP)
				}
				if !ok {
					return
				}
			}
			if err := mgr.DelRemote(0, hostCIDR(fip.Spec.Address)); err != nil {
				log.Error("del remote", "addr", fip.Spec.Address, "err", err)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("add fabricip handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return fmt.Errorf("fabricip cache failed to sync")
	}
	log.Info("fabric IP watch synced (flat pool: remotes keyed per pod)")
	return nil
}

// nodeIPIndex tracks node name -> underlay (Geneve) address, so a FabricIP can
// be resolved to a tunnel endpoint without a second API read.
type nodeIPIndex struct {
	byName map[string]net.IP
}

func newNodeIPIndex() *nodeIPIndex { return &nodeIPIndex{byName: map[string]net.IP{}} }

func (n *nodeIPIndex) set(node *corev1.Node) {
	if ip := internalIP(node); ip != "" {
		n.byName[node.Name] = net.ParseIP(ip)
	}
}

func (n *nodeIPIndex) get(name string) net.IP { return n.byName[name] }
