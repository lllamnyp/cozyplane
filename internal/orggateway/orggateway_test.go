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

package orggateway

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

var testConfig = Config{
	Enabled:      true,
	GatewayLabel: "namespace.cozystack.io/gateway",
	ApexLabel:    "namespace.cozystack.io/host",
	ServiceSelector: map[string]string{
		"gateway.envoyproxy.io/owning-gateway-name":      "cozystack",
		"gateway.envoyproxy.io/owning-gateway-namespace": NamespacePlaceholder,
	},
	AddressCIDRs: []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")},
	ApexSuffixes: []string{"apps.example.test"},
}

// namespace builds a tenant namespace the way the tenant chart writes it: the
// gateway and host labels plus a controller ownerReference to its parent.
func namespace(name, parent, gateway, host string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   name,
		UID:    types.UID("uid-" + name),
		Labels: map[string]string{testConfig.GatewayLabel: gateway, testConfig.ApexLabel: host},
	}}
	if parent != "" {
		yes := true
		ns.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: parent, UID: types.UID("uid-" + parent), Controller: &yes}}
	}
	return ns
}

// gatewayService is the Envoy Gateway proxy Service in its Gateway's namespace.
func gatewayService(ns string, ips ...string) *corev1.Service {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: "envoy-" + ns + "-cozystack-0123abcd", UID: types.UID("svc-" + ns),
		Labels: map[string]string{
			"gateway.envoyproxy.io/owning-gateway-name":      "cozystack",
			"gateway.envoyproxy.io/owning-gateway-namespace": ns,
		},
	}}
	for _, ip := range ips {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: ip})
	}
	return svc
}

func TestResolve(t *testing.T) {
	org := namespace("tenant-org", "tenant-root", "tenant-org", "org.apps.example.test")
	project := namespace("tenant-org-web", "tenant-org", "tenant-org", "web.org.apps.example.test")
	other := namespace("tenant-other", "tenant-root", "tenant-other", "other.apps.example.test")
	root := namespace("tenant-root", "", "", "")
	base := []*corev1.Namespace{root, org, project, other}

	cases := []struct {
		name       string
		vpcNS      string
		mutate     func(map[string]*corev1.Namespace) // namespace edits
		services   []*corev1.Service
		cfg        func(Config) Config
		wantIPs    []string
		wantApexes []string
	}{
		{
			name: "child namespace reaches its ancestor's gateway", vpcNS: "tenant-org-web",
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
			wantIPs:  []string{"10.240.0.5"}, wantApexes: []string{"web.org.apps.example.test", "org.apps.example.test"},
		},
		{
			name: "gateway owner itself", vpcNS: "tenant-org",
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
			wantIPs:  []string{"10.240.0.5"}, wantApexes: []string{"org.apps.example.test"},
		},
		{
			name: "missing gateway label", vpcNS: "tenant-org-web",
			mutate:   func(m map[string]*corev1.Namespace) { delete(m["tenant-org-web"].Labels, testConfig.GatewayLabel) },
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
		},
		{
			name: "label names a non-ancestor", vpcNS: "tenant-org-web",
			mutate: func(m map[string]*corev1.Namespace) {
				m["tenant-org-web"].Labels[testConfig.GatewayLabel] = "tenant-other"
			},
			services: []*corev1.Service{gatewayService("tenant-other", "10.240.0.9")},
		},
		{
			name: "ownerReference UID does not match the live parent", vpcNS: "tenant-org-web",
			mutate:   func(m map[string]*corev1.Namespace) { m["tenant-org"].UID = "recreated" },
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
		},
		{
			name: "Service without the selector labels", vpcNS: "tenant-org",
			services: func() []*corev1.Service {
				s := gatewayService("tenant-org", "10.240.0.5")
				delete(s.Labels, "gateway.envoyproxy.io/owning-gateway-name")
				return []*corev1.Service{s}
			}(),
		},
		{
			name: "Service in G labelled for another namespace", vpcNS: "tenant-org",
			services: func() []*corev1.Service {
				s := gatewayService("tenant-org", "10.240.0.5")
				s.Labels["gateway.envoyproxy.io/owning-gateway-namespace"] = "tenant-other"
				return []*corev1.Service{s}
			}(),
		},
		{
			name: "address outside the reserve", vpcNS: "tenant-org",
			services: []*corev1.Service{gatewayService("tenant-org", "203.0.113.7", "10.240.0.5", "fd00::5")},
			wantIPs:  []string{"10.240.0.5"}, wantApexes: []string{"org.apps.example.test"},
		},
		{
			name: "a non-gateway Service holding the address in its LB status drops it", vpcNS: "tenant-org",
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5", "10.240.0.6"), {
				ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-any", Name: "lb"},
				Status:     corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "10.240.0.5"}}}},
			}},
			wantIPs: []string{"10.240.0.6"}, wantApexes: []string{"org.apps.example.test"},
		},
		{
			name: "a non-gateway Service listing the address as externalIP drops it", vpcNS: "tenant-org",
			services: []*corev1.Service{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-any", Name: "ext"},
				Spec:       corev1.ServiceSpec{ExternalIPs: []string{"10.240.0.6"}},
			}, gatewayService("tenant-org", "10.240.0.5", "10.240.0.6")},
			wantIPs: []string{"10.240.0.5"}, wantApexes: []string{"org.apps.example.test"},
		},
		{
			name: "two Gateway Services of one namespace claiming an address drop it", vpcNS: "tenant-org",
			services: func() []*corev1.Service {
				twin := gatewayService("tenant-org", "10.240.0.5")
				twin.Name += "-twin"
				return []*corev1.Service{gatewayService("tenant-org", "10.240.0.5", "10.240.0.6"), twin}
			}(),
			wantIPs: []string{"10.240.0.6"}, wantApexes: []string{"org.apps.example.test"},
		},
		{
			name: "address claimed by two gateway namespaces", vpcNS: "tenant-org",
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5", "10.240.0.6"), gatewayService("tenant-other", "10.240.0.5")},
			wantIPs:  []string{"10.240.0.6"}, wantApexes: []string{"org.apps.example.test"},
		},
		{
			name: "bad apexes are dropped, the address stays", vpcNS: "tenant-org-web",
			mutate: func(m map[string]*corev1.Namespace) {
				m["tenant-org-web"].Labels[testConfig.ApexLabel] = "victim.example.com"
				m["tenant-org"].Labels[testConfig.ApexLabel] = "apps.example.test" // the suffix itself
			},
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
			wantIPs:  []string{"10.240.0.5"},
		},
		{
			name: "an apex inside the cluster domain is never answered", vpcNS: "tenant-org",
			mutate: func(m map[string]*corev1.Namespace) {
				m["tenant-org"].Labels[testConfig.ApexLabel] = "svc.cluster.local"
			},
			cfg:      func(c Config) Config { c.ApexSuffixes = append(c.ApexSuffixes, "local"); return c },
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
			wantIPs:  []string{"10.240.0.5"},
		},
		{
			name: "disabled", vpcNS: "tenant-org",
			cfg:      func(Config) Config { return Config{} },
			services: []*corev1.Service{gatewayService("tenant-org", "10.240.0.5")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			byName := map[string]*corev1.Namespace{}
			for _, ns := range base {
				byName[ns.Name] = ns.DeepCopy()
			}
			if tc.mutate != nil {
				tc.mutate(byName)
			}
			cfg := testConfig
			if tc.cfg != nil {
				cfg = tc.cfg(cfg)
			}
			gw := cfg.Resolve(tc.vpcNS, func(name string) *corev1.Namespace { return byName[name] }, tc.services)
			var ips []string
			for _, ip := range gw.IPs {
				ips = append(ips, ip.String())
			}
			if !slices.Equal(ips, tc.wantIPs) || !slices.Equal(gw.Apexes, tc.wantApexes) {
				t.Fatalf("got IPs %v apexes %v, want %v %v", ips, gw.Apexes, tc.wantIPs, tc.wantApexes)
			}
		})
	}
}

// The ancestor walk is bounded: a chain deeper than maxAncestors never
// resolves, however the labels read.
func TestResolveBoundsAncestorDepth(t *testing.T) {
	byName := map[string]*corev1.Namespace{"n0": namespace("n0", "", "n0", "")}
	parent := "n0"
	for i := 1; i <= maxAncestors+1; i++ {
		name := fmt.Sprintf("n%d", i)
		byName[name] = namespace(name, parent, "n0", "")
		parent = name
	}
	get := func(name string) *corev1.Namespace { return byName[name] }
	services := []*corev1.Service{gatewayService("n0", "10.240.0.5")}
	if gw := testConfig.Resolve(fmt.Sprintf("n%d", maxAncestors), get, services); len(gw.IPs) != 1 {
		t.Fatalf("depth %d must resolve, got %+v", maxAncestors, gw)
	}
	if gw := testConfig.Resolve(fmt.Sprintf("n%d", maxAncestors+1), get, services); len(gw.IPs) != 0 {
		t.Fatalf("depth %d must not resolve, got %+v", maxAncestors+1, gw)
	}
}

func TestFromEnv(t *testing.T) {
	set := func(kv map[string]string) {
		for _, k := range []string{"COZYPLANE_ORG_GATEWAY", "COZYPLANE_ORG_GATEWAY_NAMESPACE_LABEL", "COZYPLANE_ORG_GATEWAY_APEX_LABEL",
			"COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR", "COZYPLANE_ORG_GATEWAY_CIDRS", "COZYPLANE_ORG_GATEWAY_APEX_SUFFIXES", "COZYPLANE_ORG_GATEWAY_VPN_DNS"} {
			t.Setenv(k, kv[k])
		}
	}
	valid := map[string]string{
		"COZYPLANE_ORG_GATEWAY": "true", "COZYPLANE_ORG_GATEWAY_NAMESPACE_LABEL": "g", "COZYPLANE_ORG_GATEWAY_APEX_LABEL": "h",
		"COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR": "owner=cozystack, owner-ns={namespace}", "COZYPLANE_ORG_GATEWAY_CIDRS": "10.240.0.0/24, 100.64.10.0/24",
		"COZYPLANE_ORG_GATEWAY_APEX_SUFFIXES": "Apps.Example.Test.", "COZYPLANE_ORG_GATEWAY_VPN_DNS": "true",
	}
	set(valid)
	c, err := FromEnv()
	if err != nil || !c.Enabled || !c.VPNDNS || len(c.AddressCIDRs) != 2 || c.ApexSuffixes[0] != "apps.example.test" ||
		c.ServiceSelector["owner"] != "cozystack" || c.ServiceSelector["owner-ns"] != NamespacePlaceholder {
		t.Fatalf("valid config: %+v %v", c, err)
	}
	set(nil)
	if c, err := FromEnv(); err != nil || c.Enabled {
		t.Fatalf("unset must be disabled: %+v %v", c, err)
	}
	for _, bad := range [][2]string{
		{"COZYPLANE_ORG_GATEWAY_CIDRS", "fd00::/64"},
		{"COZYPLANE_ORG_GATEWAY_APEX_SUFFIXES", ""},
		{"COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR", ""},
		{"COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR", "owner=bad value"},
		{"COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR", "=cozystack"},
	} {
		broken := map[string]string{}
		for k, v := range valid {
			broken[k] = v
		}
		broken[bad[0]] = bad[1]
		set(broken)
		if c, err := FromEnv(); err == nil || c.Enabled {
			t.Fatalf("%s=%q accepted: %+v", bad[0], bad[1], c)
		}
	}
}

// Backends maps each proxy endpoint behind a claimed Gateway address to that
// address and its service port; contested addresses and other ports map nothing.
func TestBackends(t *testing.T) {
	ports := []corev1.ServicePort{{Name: "http-80", Port: 80}, {Name: "https-443", Port: 443}, {Name: "admin", Port: 19000}}
	gateway := func(ns, ip string) *corev1.Service {
		s := gatewayService(ns, ip)
		s.Spec.Ports = ports
		return s
	}
	svc, contested, thief := gateway("tenant-org", "10.240.0.5"), gateway("tenant-x", "10.240.0.7"), gateway("tenant-y", "10.240.0.7")
	other := gateway("tenant-b", "10.240.0.9")
	name := func(s string) *string { return &s }
	port := func(p int32) *int32 { return &p }
	yes := true
	// slice is what the EndpointSlice controller writes for owner: its label and
	// a controller ownerReference to the Service's current UID.
	slice := func(owner *corev1.Service, addrs ...string) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: owner.Namespace, Name: owner.Name + "-x",
				Labels:          map[string]string{discoveryv1.LabelServiceName: owner.Name, discoveryv1.LabelManagedBy: endpointSliceController},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: owner.Name, UID: owner.UID, Controller: &yes}},
			},
			Ports:     []discoveryv1.EndpointPort{{Name: name("http-80"), Port: port(10080)}, {Name: name("https-443"), Port: port(10443)}, {Name: name("admin"), Port: port(19000)}},
			Endpoints: []discoveryv1.Endpoint{{Addresses: addrs}},
		}
	}
	unmanaged := slice(other, "10.244.3.7")
	delete(unmanaged.Labels, discoveryv1.LabelManagedBy)
	unowned := slice(other, "10.244.3.7") // the label forged, no Service-UID ownerRef
	unowned.OwnerReferences = nil
	stale := slice(other, "10.244.3.7") // owned by a previous incarnation of the Service
	stale.OwnerReferences[0].UID = "svc-tenant-b-old"
	terminating := slice(other, "10.244.3.7")
	terminating.DeletionTimestamp = &metav1.Time{Time: time.Unix(1, 0)}
	services := []*corev1.Service{svc, contested, thief, other}
	endpointSlices := []*discoveryv1.EndpointSlice{
		slice(svc, "10.244.3.7", "10.244.3.20"),
		slice(contested, "10.244.3.8"),
		// tenant-b names tenant-org's proxy in slices it does not genuinely own:
		// none of them may contest the mapping...
		unmanaged, unowned, stale, terminating,
		// ...while a genuinely owned slice listing a shared endpoint drops it,
		// and a reserve address is never an endpoint.
		slice(other, "10.244.3.20", "10.240.0.5"),
	}
	want := map[netip.AddrPort]netip.AddrPort{
		netip.MustParseAddrPort("10.244.3.7:10080"): netip.MustParseAddrPort("10.240.0.5:80"),
		netip.MustParseAddrPort("10.244.3.7:10443"): netip.MustParseAddrPort("10.240.0.5:443"),
	}
	// Any input order yields the same map: contested endpoints are dropped, never picked.
	for i := range len(endpointSlices) {
		svcOrder, sliceOrder := slicesRotate(services, i), slicesRotate(endpointSlices, i)
		got := testConfig.Backends(svcOrder, sliceOrder)
		if len(got) != len(want) {
			t.Fatalf("order %d: got %v, want %v", i, got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("order %d: got %v, want %v", i, got, want)
			}
		}
	}
}

func slicesRotate[T any](in []T, n int) []T {
	n %= len(in)
	return append(append([]T{}, in[n:]...), in[:n]...)
}

func TestListSelector(t *testing.T) {
	sel := testConfig.ListSelector()
	svc := gatewayService("tenant-org")
	if !sel.Matches(labels.Set(svc.Labels)) {
		t.Fatalf("%s does not select the proxy Service", sel)
	}
	svc.Labels["gateway.envoyproxy.io/owning-gateway-name"] = "public"
	if sel.Matches(labels.Set(svc.Labels)) {
		t.Fatalf("%s selects another Gateway's Service", sel)
	}
}
