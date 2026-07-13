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
func watchVPCGateways(ctx context.Context, factory sdninformers.SharedInformerFactory, mgr *datapath.Manager, log *slog.Logger) {
	gws := factory.Sdn().V1alpha1().VPCGateways()
	vpcs := factory.Sdn().V1alpha1().VPCs()

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
	// VPCs too: the gate is keyed by VNI, which the VPC's status carries.
	_, _ = vpcs.Informer().AddEventHandler(onAny)

	go func() {
		if cache.WaitForCacheSync(ctx.Done(), gws.Informer().HasSynced, vpcs.Informer().HasSynced) {
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
