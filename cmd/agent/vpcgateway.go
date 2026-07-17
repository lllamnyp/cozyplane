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
	"log/slog"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

// watchVPCGateways programs the one thing a VPC's boundary fail-closes on today:
// whether a Service type=LoadBalancer may land on its pods (docs/north-south.md,
// tenet 7 — nothing crosses by default).
//
// Before this, an LB Service naming a VPC pod as its backend got a free ride: the
// platform attracted the address, the platform's uplink hook delivered it, and the
// tenant's own networking was never consulted. Now the VPC's gateway has to admit
// it, and a VPC with no gateway admits nothing.
//
// Recompute-and-diff against the pinned map, like every other watcher here: the
// map outlives the agent, so a gateway deleted while it was down must be pruned.
func watchVPCGateways(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager,
	nodes *nodePoolIndex, nodeIPs *nodeIPIndex, selfName, selfIP string, log *slog.Logger) {
	gws := factory.Sdn().V1alpha1().VPCGateways()
	vpcs := factory.Sdn().V1alpha1().VPCs()
	pools := factory.Sdn().V1alpha1().ExternalPools()

	var mu sync.Mutex
	resync := func() {
		mu.Lock()
		defer mu.Unlock()

		allGWs, err := gws.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list vpcgateways", "err", err)
			return
		}
		allVPCs, err := vpcs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list vpcs", "err", err)
			return
		}
		desired := desiredVPCIngress(allGWs, allVPCs)

		// The VPC's egress identity, and this node's slice of its port space.
		// Every node programs the WHOLE shard table: any node may be the one the
		// fabric hands a reply to, and it must know which node's connection table
		// holds the flow (docs/north-south.md § increment 2).
		wantNAT := desiredVPCNAT(allGWs, allVPCs)
		order := nodes.sortedNames()
		selfShard := indexOf(order, selfName)
		curNAT, err := mgr.VPCNATs()
		if err != nil {
			log.Error("read vpc_nat map", "err", err)
			return
		}
		for vni, id := range wantNAT {
			if selfShard >= 0 {
				base, span, ok := datapath.NATShardFor(selfShard)
				if !ok {
					log.Warn("more nodes than NAT port shards; this node cannot NAT",
						"node", selfName, "index", selfShard, "shards", datapath.NATShards)
				} else if err := mgr.SetVPCNAT(vni, id.V4, id.V6, base, span); err != nil {
					log.Error("set vpc nat", "vni", vni, "v4", id.V4, "v6", id.V6, "err", err)
					continue
				}
			}
			for i, n := range order {
				if i >= datapath.NATShards {
					break
				}
				// nodeIPIndex holds only the OTHER nodes — it exists to feed
				// `remotes`, and watchNodes skips self. But the shard table must
				// name every node INCLUDING this one, or the reverse lookup misses
				// on exactly the node that holds the flow: the reply falls through
				// to the kernel, which ARPs for an address the node itself
				// announces. (It did. That is how this was found.)
				ip := nodeIPs.get(n)
				if n == selfName {
					ip = net.ParseIP(selfIP)
				}
				if ip == nil {
					continue
				}
				// One shard table per family: a reply arrives addressed to the v4
				// or the v6 identity, and each demuxes through nat_owner by its own
				// address.
				for _, addr := range []string{id.V4, id.V6} {
					if addr == "" {
						continue
					}
					if err := mgr.SetNATOwner(addr, uint16(i), ip); err != nil {
						log.Error("set nat owner", "addr", addr, "shard", i, "err", err)
					}
				}
			}
			// Nothing here ATTRACTS the address (docs/north-south.md, tenet 3):
			// the platform must make the fabric hand it to a node — a CCM, a
			// static route, an address configured on a node. Whichever node it
			// lands on, from_uplink un-NATs the reply or forwards it to the node
			// whose shard owns the flow, so delivery does not care.
			if curNAT[vni] != id {
				log.Info("VPC egresses as its own address", "vni", vni, "v4", id.V4, "v6", id.V6)
			}
		}
		for vni, id := range curNAT {
			if _, ok := wantNAT[vni]; !ok {
				if err := mgr.DelVPCNAT(vni, id.V4, id.V6); err != nil {
					log.Error("del vpc nat", "vni", vni, "err", err)
					continue
				}
				for i := range datapath.NATShards {
					for _, addr := range []string{id.V4, id.V6} {
						if addr != "" {
							_ = mgr.DelNATOwner(addr, uint16(i))
						}
					}
				}
				log.Info("VPC lost its egress identity", "vni", vni, "v4", id.V4, "v6", id.V6)
			}
		}

		current, err := mgr.VPCIngresses()
		if err != nil {
			log.Error("read vpc_ingress map", "err", err)
			return
		}
		for net := range desired {
			if !current[net] {
				if err := mgr.SetVPCIngress(net); err != nil {
					log.Error("open vpc ingress", "vni", net, "err", err)
					continue
				}
				log.Info("VPC admits LoadBalancer ingress", "vni", net)
			}
		}
		for net := range current {
			if !desired[net] {
				if err := mgr.DelVPCIngress(net); err != nil {
					log.Error("close vpc ingress", "vni", net, "err", err)
					continue
				}
				log.Info("VPC no longer admits LoadBalancer ingress", "vni", net)
			}
		}
	}

	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, newObj any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	_, _ = gws.Informer().AddEventHandler(onAny)
	_, _ = pools.Informer().AddEventHandler(onAny)
	// The node set decides both the port shards and the announcer.
	nodes.onChange(resync)
	// VPCs too: the gate is keyed by VNI, which the VPC's status carries.
	_, _ = vpcs.Informer().AddEventHandler(onAny)

	go func() {
		if cache.WaitForCacheSync(ctx.Done(), gws.Informer().HasSynced, vpcs.Informer().HasSynced,
			pools.Informer().HasSynced) {
			resync()
		}
	}()
}

// desiredVPCIngress is the set of VNIs whose boundary admits LoadBalancer ingress.
// A VPC's boundary is its OLDEST gateway (EffectiveGateway) — a second gateway
// cannot open a door the first one closed.
func desiredVPCIngress(gws []*sdnv1alpha1.VPCGateway, vpcs []*sdnv1alpha1.VPC) map[uint32]bool {
	byNS := map[string][]sdnv1alpha1.VPCGateway{}
	for _, g := range gws {
		byNS[g.Namespace] = append(byNS[g.Namespace], *g)
	}
	out := map[uint32]bool{}
	for _, vpc := range vpcs {
		if vpc.Status.VNI == 0 {
			continue
		}
		gw := sdnv1alpha1.EffectiveGateway(byNS[vpc.Namespace], vpc.Name)
		if gw != nil && gw.Spec.Ingress.LoadBalancer {
			out[uint32(vpc.Status.VNI)] = true
		}
	}
	return out
}

// desiredVPCNAT is the set of VNIs with an allocated egress identity, keyed to the
// address(es) their traffic wears on the wire — a v4 and/or a v6 (docs/north-south.md
// §6a). A VPC's boundary is its OLDEST gateway.
func desiredVPCNAT(gws []*sdnv1alpha1.VPCGateway, vpcs []*sdnv1alpha1.VPC) map[uint32]datapath.NATIdentity {
	byNS := map[string][]sdnv1alpha1.VPCGateway{}
	for _, g := range gws {
		byNS[g.Namespace] = append(byNS[g.Namespace], *g)
	}
	out := map[uint32]datapath.NATIdentity{}
	for _, vpc := range vpcs {
		if vpc.Status.VNI == 0 {
			continue
		}
		gw := sdnv1alpha1.EffectiveGateway(byNS[vpc.Namespace], vpc.Name)
		if gw != nil && gw.Spec.NAT.Enabled && (gw.Status.NATAddress != "" || gw.Status.NATAddress6 != "") {
			out[uint32(vpc.Status.VNI)] = datapath.NATIdentity{V4: gw.Status.NATAddress, V6: gw.Status.NATAddress6}
		}
	}
	return out
}

func indexOf(names []string, self string) int {
	for i, n := range names {
		if n == self {
			return i
		}
	}
	return -1
}
