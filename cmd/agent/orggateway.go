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
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/orggateway"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

type orgGatewaySink interface {
	SyncOrgGateways(map[uint32][]netip.Addr, map[netip.AddrPort]netip.AddrPort) error
}

// watchOrgGateways programs org_gw (each VPC's network -> the addresses of its
// organisation's internal Gateway, internal/orggateway) and org_gw_be (the
// Gateway proxies' endpoints), recomputed on any VPC, Namespace, Service or
// Gateway EndpointSlice event. The caller cleared both pinned maps at startup;
// nothing is granted before every cache synced.
func watchOrgGateways(ctx context.Context, factory sdninformers.SharedInformerFactory, client kubernetes.Interface, mgr orgGatewaySink, cfg orggateway.Config, log *slog.Logger) {
	if !cfg.Enabled {
		return
	}
	vpcs := factory.Sdn().V1alpha1().VPCs()
	// Every Service: a reserve address held by any non-Gateway Service drops it.
	core := informers.NewSharedInformerFactory(client, 0)
	namespaces := core.Core().V1().Namespaces()
	services := core.Core().V1().Services()
	// Only the candidate Gateways' EndpointSlices (slices copy their Service's
	// labels): every node caches these, so keep the set small.
	gateways := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithTweakListOptions(func(o *metav1.ListOptions) {
		o.LabelSelector = cfg.ListSelector().String()
	}))
	endpointSlices := gateways.Discovery().V1().EndpointSlices()
	apply := func() {
		allVPCs, err := vpcs.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list VPCs for organisation gateways", "err", err)
			return
		}
		svcs, err := services.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list Services for organisation gateways", "err", err)
			return
		}
		eps, err := endpointSlices.Lister().List(labels.Everything())
		if err != nil {
			log.Error("list organisation gateway EndpointSlices", "err", err)
			return
		}
		getNS := func(name string) *corev1.Namespace {
			ns, err := namespaces.Lister().Get(name)
			if err != nil {
				return nil
			}
			return ns
		}
		syncOrgGateways(mgr, desiredOrgGateways(cfg, allVPCs, getNS, svcs), cfg.Backends(svcs, eps), log)
	}
	resync := resyncAfterCacheSync(ctx, apply, vpcs.Informer().HasSynced, namespaces.Informer().HasSynced,
		services.Informer().HasSynced, endpointSlices.Informer().HasSynced)
	onAny := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	}
	for _, inf := range []cache.SharedIndexInformer{vpcs.Informer(), namespaces.Informer(), services.Informer(), endpointSlices.Informer()} {
		_, _ = inf.AddEventHandler(onAny)
	}
	core.Start(ctx.Done())
	gateways.Start(ctx.Done())
}

func desiredOrgGateways(cfg orggateway.Config, vpcs []*sdnv1alpha1.VPC, getNS func(string) *corev1.Namespace, services []*corev1.Service) map[uint32][]netip.Addr {
	want := map[uint32][]netip.Addr{}
	for _, vpc := range vpcs {
		if vpc == nil || !vpc.DeletionTimestamp.IsZero() || vpc.Status.VNI <= 0 || vpc.Status.VNI >= 1<<22 {
			continue
		}
		if gw := cfg.Resolve(vpc.Namespace, getNS, services); len(gw.IPs) > 0 {
			want[uint32(vpc.Status.VNI)] = gw.IPs
		}
	}
	return want
}

// syncOrgGateways fails closed: a snapshot the maps cannot hold (capacity, or
// any write error) leaves no VPC reaching any Gateway rather than a stale or
// partial grant.
func syncOrgGateways(mgr orgGatewaySink, want map[uint32][]netip.Addr, backends map[netip.AddrPort]netip.AddrPort, log *slog.Logger) {
	if err := mgr.SyncOrgGateways(want, backends); err != nil {
		log.Error("program organisation gateways; clearing them", "err", err)
		if err := mgr.SyncOrgGateways(nil, nil); err != nil {
			log.Error("clear organisation gateways", "err", err)
		}
	}
}
