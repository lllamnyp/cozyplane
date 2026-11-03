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

// Package orggateway resolves the internal organisation Gateway a VPC's
// namespace may use (docs/services-in-vpc.md § "Organisation gateway"): the
// private load-balancer addresses its workloads reach on TCP 80/443, and the
// apex names the split-horizon resolver answers with them. The Gateway runs
// in its own namespace G (Envoy Gateway's namespace mode), its proxy behind a
// LoadBalancer Service holding an address from the platform's private reserve.
// Every input is platform data — the namespace labels and ownerReferences the
// tenant chart writes, the proxy Service and its LB-assigned status — and each
// guard below exists because part of that data is tenant-influenced.
package orggateway

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/lllamnyp/cozyplane/internal/serviceidentity"
)

// NamespacePlaceholder, as a ServiceSelector value, stands for the Service's
// own namespace (Envoy Gateway labels its proxy with the owning namespace).
const NamespacePlaceholder = "{namespace}"

// maxAncestors bounds the ownerReference walk; the tenant tree is shallow.
const maxAncestors = 8

// Config holds the chart's orgGateway values. The zero value is disabled.
type Config struct {
	Enabled         bool
	GatewayLabel    string            // namespace label naming the Gateway-owning namespace
	ApexLabel       string            // namespace label carrying the tenant's host
	ServiceSelector map[string]string // labels of the Gateway's proxy Service in its namespace
	AddressCIDRs    []netip.Prefix    // the platform's private gateway reserve (IPv4)
	ApexSuffixes    []string          // an apex must sit strictly under one of these
	VPNDNS          bool              // VPN clients whose pool pushes the cluster DNS may reach it
	ClusterDomain   string            // never an apex; empty means cluster.local
}

// Gateway is what one VPC namespace may reach and resolve. Empty when none.
type Gateway struct {
	Apexes []string
	IPs    []netip.Addr
}

// FromEnv reads the COZYPLANE_ORG_GATEWAY_* variables the chart renders from
// orgGateway.*. Disabled unless COZYPLANE_ORG_GATEWAY=true; an incomplete or
// malformed enabled config is an error, never a partial one.
func FromEnv() (Config, error) {
	if os.Getenv("COZYPLANE_ORG_GATEWAY") != "true" {
		return Config{}, nil
	}
	c := Config{
		Enabled:         true,
		GatewayLabel:    os.Getenv("COZYPLANE_ORG_GATEWAY_NAMESPACE_LABEL"),
		ApexLabel:       os.Getenv("COZYPLANE_ORG_GATEWAY_APEX_LABEL"),
		ServiceSelector: map[string]string{},
		VPNDNS:          os.Getenv("COZYPLANE_ORG_GATEWAY_VPN_DNS") == "true",
	}
	if c.GatewayLabel == "" || c.ApexLabel == "" {
		return Config{}, fmt.Errorf("orgGateway: gatewayNamespaceLabel and apexLabel are required")
	}
	for _, raw := range split(os.Getenv("COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR")) {
		k, v, _ := strings.Cut(raw, "=")
		if len(validation.IsQualifiedName(k)) != 0 || (v != NamespacePlaceholder && len(validation.IsValidLabelValue(v)) != 0) {
			return Config{}, fmt.Errorf("orgGateway.serviceSelector: %q is not a label=value pair", raw)
		}
		c.ServiceSelector[k] = v
	}
	for _, raw := range split(os.Getenv("COZYPLANE_ORG_GATEWAY_CIDRS")) {
		p, err := netip.ParsePrefix(raw)
		// The datapath rewrite is IPv4-only: a v6 reserve would resolve to an
		// address nothing forwards.
		if err != nil || !p.Addr().Is4() {
			return Config{}, fmt.Errorf("orgGateway.addressCIDRs: %q is not an IPv4 prefix", raw)
		}
		c.AddressCIDRs = append(c.AddressCIDRs, p.Masked())
	}
	for _, raw := range split(os.Getenv("COZYPLANE_ORG_GATEWAY_APEX_SUFFIXES")) {
		s := strings.ToLower(strings.Trim(raw, "."))
		if len(validation.IsDNS1123Subdomain(s)) != 0 {
			return Config{}, fmt.Errorf("orgGateway.apexSuffixes: %q is not a DNS name", raw)
		}
		c.ApexSuffixes = append(c.ApexSuffixes, s)
	}
	if len(c.ServiceSelector) == 0 || len(c.AddressCIDRs) == 0 || len(c.ApexSuffixes) == 0 {
		return Config{}, fmt.Errorf("orgGateway: serviceSelector, addressCIDRs and apexSuffixes are required")
	}
	return c, nil
}

// ListSelector narrows an EndpointSlice list or watch (slices copy their
// Service's labels) to candidate Gateways; Matches decides exactly.
func (c Config) ListSelector() labels.Selector {
	sel := labels.NewSelector()
	for k, v := range c.ServiceSelector {
		op, values := selection.Equals, []string{v}
		if v == NamespacePlaceholder {
			op, values = selection.Exists, nil
		}
		if r, err := labels.NewRequirement(k, op, values); err == nil {
			sel = sel.Add(*r)
		}
	}
	return sel
}

// Matches reports whether obj carries every selector label, the placeholder
// read as obj's own namespace.
func (c Config) Matches(obj metav1.Object) bool {
	for k, want := range c.ServiceSelector {
		if want == NamespacePlaceholder {
			want = obj.GetNamespace()
		}
		if got, ok := obj.GetLabels()[k]; !ok || got != want {
			return false
		}
	}
	return len(c.ServiceSelector) > 0
}

// Resolve returns the Gateway of the VPC namespace `namespace`. getNS returns
// a Namespace by name, nil when absent; services must hold every Service in
// the cluster that HoldsReserve — candidate Gateways and any other — because a
// reserve address held twice is dropped (claims).
func (c Config) Resolve(namespace string, getNS func(string) *corev1.Namespace, services []*corev1.Service) Gateway {
	if !c.Enabled {
		return Gateway{}
	}
	ns := getNS(namespace)
	if ns == nil {
		return Gateway{}
	}
	// The label names the nearest Gateway-owning ancestor (inclusive). Verify
	// it against the ownerReference chain rather than trusting it.
	owner := ns.Labels[c.GatewayLabel]
	ownerNS := ancestorOrSelf(ns, owner, getNS)
	if ownerNS == nil {
		return Gateway{}
	}
	var gw Gateway
	for ip, svc := range c.claims(services) {
		if svc != nil && svc.Namespace == owner {
			gw.IPs = append(gw.IPs, ip)
		}
	}
	if len(gw.IPs) == 0 {
		return Gateway{}
	}
	slices.SortFunc(gw.IPs, func(a, b netip.Addr) int { return a.Compare(b) })
	for _, host := range []string{ns.Labels[c.ApexLabel], ownerNS.Labels[c.ApexLabel]} {
		if apex := c.apex(host); apex != "" && !slices.Contains(gw.Apexes, apex) {
			gw.Apexes = append(gw.Apexes, apex)
		}
	}
	return gw
}

// endpointSliceController manages the only EndpointSlices Backends trusts:
// those derived from a Service's pod selector, never hand-written ones. The
// label alone can be forged, so a slice must also be controller-owned by the
// current Gateway Service and not terminating (serviceidentity), or it is
// ignored and contests nothing.
const endpointSliceController = "endpointslice-controller.k8s.io"

// Backends maps every proxy endpoint (address, target port) behind a claimed
// Gateway address to that address and its service port (80/443): the source a
// proxy reply carries when Cilium reverse-NATs it only after Cozyplane, i.e.
// when the proxy runs on another node. It grants nothing by itself — the
// datapath translates a reply only onto a flow it recorded. An endpoint that
// would map to two targets (two Gateway namespaces, or one proxy serving two
// Gateway addresses) is dropped rather than picked: fail-closed, and the result
// never depends on iteration order. A reserve address is never an endpoint.
func (c Config) Backends(services []*corev1.Service, endpointSlices []*discoveryv1.EndpointSlice) map[netip.AddrPort]netip.AddrPort {
	type target struct {
		to        netip.AddrPort
		contested bool
	}
	seen := map[netip.AddrPort]target{}
	if !c.Enabled {
		return map[netip.AddrPort]netip.AddrPort{}
	}
	for ip, svc := range c.claims(services) {
		if svc == nil {
			continue
		}
		for _, sp := range svc.Spec.Ports {
			if (sp.Protocol != "" && sp.Protocol != corev1.ProtocolTCP) || (sp.Port != 80 && sp.Port != 443) {
				continue
			}
			to := netip.AddrPortFrom(ip, uint16(sp.Port))
			for _, eps := range endpointSlices {
				if !serviceidentity.OwnsEndpointSlice(svc, eps) || eps.Labels[discoveryv1.LabelManagedBy] != endpointSliceController {
					continue
				}
				for _, p := range eps.Ports {
					if p.Port == nil || *p.Port < 1 || *p.Port > 65535 || (p.Name == nil && sp.Name != "") || (p.Name != nil && *p.Name != sp.Name) {
						continue
					}
					for _, e := range eps.Endpoints {
						for _, a := range e.Addresses {
							addr, err := netip.ParseAddr(a)
							if err != nil || !addr.Is4() || c.inReserve(addr) {
								continue
							}
							key := netip.AddrPortFrom(addr, uint16(*p.Port))
							if prev, ok := seen[key]; !ok {
								seen[key] = target{to: to}
							} else if prev.to != to {
								seen[key] = target{contested: true}
							}
						}
					}
				}
			}
		}
	}
	out := map[netip.AddrPort]netip.AddrPort{}
	for key, t := range seen {
		if !t.contested {
			out[key] = t.to
		}
	}
	return out
}

// HoldsReserve reports whether svc carries a reserve address in its LB status
// or externalIPs: the Services Resolve and Backends must see.
func (c Config) HoldsReserve(svc *corev1.Service) bool {
	for _, raw := range heldAddresses(svc) {
		if ip, err := netip.ParseAddr(raw); err == nil && c.inReserve(ip) {
			return true
		}
	}
	return false
}

func heldAddresses(svc *corev1.Service) []string {
	held := slices.Clone(svc.Spec.ExternalIPs)
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		held = append(held, ing.IP)
	}
	return held
}

// claims maps each reserve address to the one Gateway Service whose LB status
// claims it; nil once contested — claimed by a second Service, or held by any
// non-Gateway Service (LB status or externalIPs), a frontend Cilium could
// serve instead of the Gateway a VPC is steered to.
func (c Config) claims(services []*corev1.Service) map[netip.Addr]*corev1.Service {
	out := map[netip.Addr]*corev1.Service{}
	for _, svc := range services {
		gateway := c.Matches(svc)
		held := heldAddresses(svc)
		if gateway {
			held = held[len(svc.Spec.ExternalIPs):] // a Gateway claims by LB status only
		}
		for _, raw := range held {
			ip, err := netip.ParseAddr(raw)
			if err != nil || !c.inReserve(ip) {
				continue
			}
			prev, seen := out[ip]
			switch {
			case !gateway:
				out[ip] = nil
			case !seen:
				out[ip] = svc
			case prev != nil && (prev.Namespace != svc.Namespace || prev.Name != svc.Name):
				out[ip] = nil
			}
		}
	}
	return out
}

// ancestorOrSelf returns the namespace named owner when it is ns itself or an
// ancestor reached through controller ownerReferences of kind Namespace whose
// UIDs match the live objects, within maxAncestors levels; else nil.
func ancestorOrSelf(ns *corev1.Namespace, owner string, getNS func(string) *corev1.Namespace) *corev1.Namespace {
	if owner == "" {
		return nil
	}
	for level := 0; ; level++ {
		if ns.Name == owner {
			return ns
		}
		ref := metav1.GetControllerOf(ns)
		if level == maxAncestors || ref == nil || ref.APIVersion != "v1" || ref.Kind != "Namespace" {
			return nil
		}
		parent := getNS(ref.Name)
		if parent == nil || parent.UID != ref.UID {
			return nil
		}
		ns = parent
	}
}

func (c Config) inReserve(ip netip.Addr) bool {
	for _, p := range c.AddressCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// apex normalizes a host label value; "" when it is not a DNS name, falls in
// the cluster domain, or is not strictly under an operator suffix.
func (c Config) apex(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(validation.IsDNS1123Subdomain(host)) != 0 {
		return ""
	}
	domain := strings.ToLower(strings.Trim(c.ClusterDomain, "."))
	if domain == "" {
		domain = "cluster.local"
	}
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return ""
	}
	for _, s := range c.ApexSuffixes {
		if strings.HasSuffix(host, "."+s) {
			return host
		}
	}
	return ""
}

func split(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
