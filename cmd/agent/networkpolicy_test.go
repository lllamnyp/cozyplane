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
	var sawFiltered, sawIPBlock, sawNamed bool
	for _, w := range c.warnings {
		sawFiltered = sawFiltered || strings.Contains(w, "identity-filtered")
		sawIPBlock = sawIPBlock || strings.Contains(w, "ipBlock")
		sawNamed = sawNamed || strings.Contains(w, "named port")
	}
	if !sawFiltered || !sawIPBlock || !sawNamed {
		t.Fatalf("missing warnings: %v", c.warnings)
	}
	// The unserved peers/ports compiled to nothing — fail closed, no allows.
	if len(c.allows) != 0 {
		t.Fatalf("unserved constructs leaked allows: %+v", c.allows)
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
