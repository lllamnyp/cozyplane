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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/lllamnyp/cozyplane/datapath"
)

func ptrIntOrString(port int) *intstr.IntOrString {
	return new(intstr.FromInt32(int32(port)))
}

func ptrIntOrStringNamed(name string) *intstr.IntOrString {
	return new(intstr.FromString(name))
}

func npPod(ns, name, ip string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

func npNS(name string, lbls map[string]string) *corev1.Namespace {
	if lbls == nil {
		lbls = map[string]string{}
	}
	lbls["kubernetes.io/metadata.name"] = name
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: lbls}}
}

func identOf(c npCompiled, ip string) (datapath.NPIdent, bool) {
	for _, id := range c.idents {
		if id.IP.String() == ip {
			return id, true
		}
	}
	return datapath.NPIdent{}, false
}

func hasAllow(c npCompiled, dst, src uint64, proto uint8, port uint16) bool {
	for _, a := range c.allows {
		if a.DstID == dst && a.SrcID == src && a.Dir == datapath.NPDirIn &&
			a.Proto == proto && a.Port == port {
			return true
		}
	}
	return false
}

func TestNPIdentity(t *testing.T) {
	// Same {namespace, labels} -> same id; namespace or labels differ -> not.
	a := npIdentityOf("ns1", map[string]string{"app": "web"})
	b := npIdentityOf("ns1", map[string]string{"app": "web"})
	if a != b {
		t.Fatal("identity is not deterministic")
	}
	if npIdentityOf("ns2", map[string]string{"app": "web"}) == a {
		t.Fatal("namespace not part of identity")
	}
	if npIdentityOf("ns1", map[string]string{"app": "db"}) == a {
		t.Fatal("labels not part of identity")
	}
	if a < datapath.NPFirstRealID {
		t.Fatal("identity collided with a reserved id")
	}

	// Churn labels are erased: a rollout doesn't mint a new identity.
	base := npFilterLabels(map[string]string{"app": "web", "pod-template-hash": "abc123"})
	next := npFilterLabels(map[string]string{"app": "web", "pod-template-hash": "def456"})
	if npIdentityOf("ns1", base) != npIdentityOf("ns1", next) {
		t.Fatal("pod-template-hash leaked into identity")
	}
	if !npFilteredLabel("batch.kubernetes.io/job-name") || npFilteredLabel("app") {
		t.Fatal("filter set wrong")
	}
}

func TestNPCompileIsolationAndPairs(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
		npPod("prod", "web-2", "10.244.1.10", map[string]string{"app": "web"}), // same identity
		npPod("prod", "cli-1", "10.244.0.11", map[string]string{"role": "cli"}),
		npPod("prod", "other", "10.244.2.12", map[string]string{"app": "other"}),
	}
	nss := []*corev1.Namespace{npNS("prod", nil)}
	nps := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web-ingress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "cli"}},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{
					Port: ptrIntOrString(8080),
				}},
			}},
		},
	}}

	c := compileNetworkPolicies(pods, nss, nps)

	w1, ok1 := identOf(c, "10.244.0.10")
	w2, ok2 := identOf(c, "10.244.1.10")
	cli, ok3 := identOf(c, "10.244.0.11")
	oth, ok4 := identOf(c, "10.244.2.12")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		t.Fatalf("missing ident rows: %+v", c.idents)
	}
	if w1.ID != w2.ID {
		t.Fatal("same-labels pods got different identities")
	}
	if w1.Flags&datapath.NPIngIsolated == 0 || w2.Flags&datapath.NPIngIsolated == 0 {
		t.Fatal("selected pods not ingress-isolated")
	}
	if w1.Flags&datapath.NPEgIsolated != 0 {
		t.Fatal("ingress-only policy set egress isolation")
	}
	if cli.Flags != 0 || oth.Flags != 0 {
		t.Fatal("unselected pods isolated")
	}
	// Exactly the cli->web pair on TCP/8080; nothing for the bystander.
	if !hasAllow(c, w1.ID, cli.ID, 6, 8080) {
		t.Fatalf("missing cli->web allow: %+v", c.allows)
	}
	if hasAllow(c, w1.ID, oth.ID, 6, 8080) {
		t.Fatal("bystander allowed")
	}
}

func TestNPCompileReservedPeersAndPorts(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
	}
	nss := []*corev1.Namespace{npNS("prod", nil)}

	// Empty from: allow everything (NP_SRC_ANY), all ports of both protos.
	openNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "open"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
		},
	}
	c := compileNetworkPolicies(pods, nss, []*networkingv1.NetworkPolicy{openNP})
	w, _ := identOf(c, "10.244.0.10")
	if !hasAllow(c, w.ID, datapath.NPSrcAny, 6, 0) || !hasAllow(c, w.ID, datapath.NPSrcAny, 17, 0) {
		t.Fatalf("empty from: did not compile to NP_SRC_ANY any-port rows: %+v", c.allows)
	}

	// namespaceSelector {}: any pod (NP_SRC_ANY_POD), not external.
	anyPodNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "anypod"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{},
				}},
			}},
		},
	}
	c = compileNetworkPolicies(pods, nss, []*networkingv1.NetworkPolicy{anyPodNP})
	w, _ = identOf(c, "10.244.0.10")
	if !hasAllow(c, w.ID, datapath.NPSrcAnyPod, 6, 0) {
		t.Fatalf("namespaceSelector {} did not compile to NP_SRC_ANY_POD: %+v", c.allows)
	}
	if hasAllow(c, w.ID, datapath.NPSrcAny, 6, 0) {
		t.Fatal("namespaceSelector {} wrongly admits external sources")
	}
}

func TestNPCompileNamespaceSelector(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
		npPod("mon", "prom", "10.244.3.10", map[string]string{"app": "prometheus"}),
		npPod("dev", "hacker", "10.244.4.10", map[string]string{"app": "prometheus"}),
	}
	nss := []*corev1.Namespace{
		npNS("prod", nil),
		npNS("mon", map[string]string{"team": "sre"}),
		npNS("dev", map[string]string{"team": "dev"}),
	}
	nps := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "from-mon"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "sre"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "prometheus"}},
				}},
			}},
		},
	}}
	c := compileNetworkPolicies(pods, nss, nps)
	w, _ := identOf(c, "10.244.0.10")
	prom, _ := identOf(c, "10.244.3.10")
	hacker, _ := identOf(c, "10.244.4.10")
	if !hasAllow(c, w.ID, prom.ID, 6, 0) {
		t.Fatalf("mon/prometheus not admitted: %+v", c.allows)
	}
	if hasAllow(c, w.ID, hacker.ID, 6, 0) {
		t.Fatal("same labels in a non-matching namespace admitted")
	}
}

func TestNPCompileSkipsAndWarnings(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
		{ // hostNetwork pods are exempt plumbing: no identity row
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "hostnet", Labels: map[string]string{"app": "web"}},
			Spec:       corev1.PodSpec{HostNetwork: true},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "172.18.0.2"}}},
		},
	}
	nss := []*corev1.Namespace{npNS("prod", nil)}
	nps := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "warny"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pod-template-hash": "abc"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{
					Port: ptrIntOrStringNamed("http"),
				}},
			}},
		},
	}}
	c := compileNetworkPolicies(pods, nss, nps)
	if _, ok := identOf(c, "172.18.0.2"); ok {
		t.Fatal("hostNetwork pod got an identity row")
	}
	var sawFiltered, sawNamed bool
	for _, w := range c.warnings {
		sawFiltered = sawFiltered || strings.Contains(w, "identity-filtered")
		sawNamed = sawNamed || strings.Contains(w, "named port")
	}
	if !sawFiltered || !sawNamed {
		t.Fatalf("missing warnings: %v", c.warnings)
	}
	// The unserved port compiled the whole rule to nothing — fail closed:
	// no allows, and no cidr entries for the ipBlock either.
	if len(c.allows) != 0 || len(c.cidrs) != 0 {
		t.Fatalf("unserved constructs leaked rows: %+v %+v", c.allows, c.cidrs)
	}
}

func TestNPCompileIPBlock(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
	}
	nss := []*corev1.Namespace{npNS("prod", nil)}
	nps := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "from-range"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{
						CIDR:   "192.0.2.0/24",
						Except: []string{"192.0.2.128/25"},
					},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Port: ptrIntOrString(8080)}},
			}},
		},
	}}
	c := compileNetworkPolicies(pods, nss, nps)
	w, _ := identOf(c, "10.244.0.10")
	var allow, deny bool
	for _, e := range c.cidrs {
		if e.ID != w.ID || e.Dir != datapath.NPDirIn || e.Proto != 6 || e.Port != 8080 {
			t.Fatalf("cidr entry mis-keyed: %+v", e)
		}
		if e.CIDR.String() == "192.0.2.0/24" && e.Allow {
			allow = true
		}
		if e.CIDR.String() == "192.0.2.128/25" && !e.Allow {
			deny = true
		}
	}
	if !allow || !deny {
		t.Fatalf("ipBlock not compiled to allow+except: %+v", c.cidrs)
	}
	// No identity pairs from a pure-ipBlock rule.
	if len(c.allows) != 0 {
		t.Fatalf("ipBlock leaked pair rows: %+v", c.allows)
	}
}

func TestNPCompileEgress(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "cli-1", "10.244.0.11", map[string]string{"role": "cli"}),
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
	}
	nss := []*corev1.Namespace{npNS("prod", nil)}
	nps := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "cli-egress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "cli"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To:    []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}},
					Ports: []networkingv1.NetworkPolicyPort{{Port: ptrIntOrString(8080)}},
				},
				{
					To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "198.51.100.0/24"}}},
				},
				{
					// namespaceSelector {}: any pod destination.
					To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}},
					Ports: []networkingv1.NetworkPolicyPort{{
						Protocol: new(corev1.ProtocolUDP), Port: ptrIntOrString(53),
					}},
				},
			},
		},
	}}
	c := compileNetworkPolicies(pods, nss, nps)
	cli, _ := identOf(c, "10.244.0.11")
	web, _ := identOf(c, "10.244.0.10")
	if cli.Flags&datapath.NPEgIsolated == 0 {
		t.Fatal("egress policy did not isolate the subject")
	}
	if cli.Flags&datapath.NPIngIsolated != 0 {
		t.Fatal("egress-only policy wrongly ingress-isolated the subject")
	}
	if web.Flags != 0 {
		t.Fatal("peer wrongly isolated")
	}
	// Pair row: subject in the SRC slot, peer in the DST slot, dir EG.
	found := false
	for _, a := range c.allows {
		if a.Dir == datapath.NPDirEg && a.SrcID == cli.ID && a.DstID == web.ID && a.Proto == 6 && a.Port == 8080 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing egress pair row: %+v", c.allows)
	}
	// ANY_POD destination for the DNS rule.
	found = false
	for _, a := range c.allows {
		if a.Dir == datapath.NPDirEg && a.SrcID == cli.ID && a.DstID == datapath.NPSrcAnyPod && a.Proto == 17 && a.Port == 53 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing ANY_POD egress DNS row: %+v", c.allows)
	}
	// The egress ipBlock is keyed by the SUBJECT identity, dir EG, and the
	// rule's empty ports mean any-port rows for both protocols.
	var v4any bool
	for _, e := range c.cidrs {
		if e.ID == cli.ID && e.Dir == datapath.NPDirEg && e.CIDR.String() == "198.51.100.0/24" && e.Allow && e.Port == 0 {
			v4any = true
		}
	}
	if !v4any {
		t.Fatalf("missing egress cidr entry: %+v", c.cidrs)
	}
}

func TestNPCompileEgressFlagAndDefaultTypes(t *testing.T) {
	pods := []*corev1.Pod{
		npPod("prod", "web-1", "10.244.0.10", map[string]string{"app": "web"}),
	}
	nss := []*corev1.Namespace{npNS("prod", nil)}
	// No policyTypes, egress present: Ingress + Egress both implied.
	nps := []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "both"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}}
	c := compileNetworkPolicies(pods, nss, nps)
	w, _ := identOf(c, "10.244.0.10")
	if w.Flags&datapath.NPIngIsolated == 0 || w.Flags&datapath.NPEgIsolated == 0 {
		t.Fatalf("default policyTypes not derived: flags=%d", w.Flags)
	}
}
