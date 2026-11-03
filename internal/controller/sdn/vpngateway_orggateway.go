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

package sdn

import (
	"context"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// The organisation Gateway over VPN (docs/vpn.md § "Organisation gateway"):
// the gateway namespace's Gateway addresses join what its clients and sites may
// reach — client AllowedIPs and filter, IPsec local selectors, BGP adverts —
// and the appliance masquerades TCP 80/443 to them behind its own VPC address,
// the only source the datapath re-sources toward Cilium.

// orgGatewayDestinations returns the /32s of the organisation Gateway serving
// VPCs in namespace; nil when the feature is off or there is none.
func (r *VPNGatewayReconciler) orgGatewayDestinations(ctx context.Context, namespace string) ([]string, error) {
	cfg := r.Config.OrgGateway
	if !cfg.Enabled {
		return nil, nil
	}
	var list corev1.ServiceList
	// Every Service: a reserve address any other Service holds is dropped.
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}
	services := make([]*corev1.Service, 0, len(list.Items))
	for i := range list.Items {
		services = append(services, &list.Items[i])
	}
	gw := cfg.Resolve(namespace, func(name string) *corev1.Namespace {
		ns := &corev1.Namespace{}
		if err := r.Get(ctx, client.ObjectKey{Name: name}, ns); err != nil {
			return nil // unreadable reads as absent: no Gateway, never a wider one
		}
		return ns
	}, services)
	out := make([]string, 0, len(gw.IPs))
	for _, ip := range gw.IPs {
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	return out, nil
}

// vpnDNSDestination is the cluster DNS /32 a client pool may reach: only with
// vpnDNS on and when the pool pushes exactly that resolver. A tenant-supplied
// pool DNS server never adds its own address to any filter or selector.
// ponytail: IPv4 cluster DNS only, like the appliance masquerade.
func (r *VPNGatewayReconciler) vpnDNSDestination(poolDNS []string) []string {
	dns, err := netip.ParseAddr(r.Config.ClusterDNS)
	if !r.Config.OrgGateway.Enabled || !r.Config.OrgGateway.VPNDNS || err != nil || !dns.Is4() || !slices.Contains(poolDNS, dns.String()) {
		return nil
	}
	return []string{netip.PrefixFrom(dns, 32).String()}
}

// clientPoolDNS is the resolver list the WireGuard client's pools push.
func clientPoolDNS(gw *sdnv1alpha1.VPNGateway, c *sdnv1alpha1.VPNConnection) []string {
	var dns []string
	if gw.Spec.WireGuard == nil || c.Spec.WireGuard == nil || c.Spec.WireGuard.Client == nil {
		return nil
	}
	for _, pool := range gw.Spec.WireGuard.AddressPools {
		if slices.Contains(c.Spec.WireGuard.Client.AddressPools, pool.Name) {
			dns = appendUnique(dns, pool.DNS...)
		}
	}
	return dns
}

// mapOrgGatewayServiceToVPNGateways re-renders the gateways of every namespace
// whose organisation Gateway proxy the changed Service may be. Any other
// Service holding a reserve address contests it wherever it is: all gateways.
func (r *VPNGatewayReconciler) mapOrgGatewayServiceToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return nil
	}
	if !r.Config.OrgGateway.Matches(svc) {
		if r.Config.OrgGateway.HoldsReserve(svc) {
			return r.vpnGatewaysInNamespace(ctx, metav1.NamespaceAll)
		}
		return nil
	}
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces, client.MatchingLabels{r.Config.OrgGateway.GatewayLabel: obj.GetNamespace()}); err != nil {
		return nil
	}
	var out []ctrl.Request
	for i := range namespaces.Items {
		out = append(out, r.vpnGatewaysInNamespace(ctx, namespaces.Items[i].Name)...)
	}
	return out
}

// mapNamespaceToVPNGateways re-renders the gateways of a namespace whose
// labels or ownership changed.
func (r *VPNGatewayReconciler) mapNamespaceToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.vpnGatewaysInNamespace(ctx, obj.GetName())
}

func (r *VPNGatewayReconciler) vpnGatewaysInNamespace(ctx context.Context, namespace string) []ctrl.Request {
	var list sdnv1alpha1.VPNGatewayList
	if err := r.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}
