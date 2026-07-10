// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func lbSvc(etp corev1.ServiceExternalTrafficPolicy, ingress ...corev1.LoadBalancerIngress) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			ClusterIP:             "10.96.0.50",
			ClusterIPs:            []string{"10.96.0.50"},
			ExternalTrafficPolicy: etp,
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80},
			},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{Ingress: ingress},
		},
	}
}

func slice(node1, node2 string) []*discoveryv1.EndpointSlice {
	ready := true
	port := int32(8080)
	name := "http"
	return []*discoveryv1.EndpointSlice{{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: "web-1"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &name, Port: &port}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.244.0.10"}, NodeName: &node1, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.244.1.10"}, NodeName: &node2, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}}
}

func keyFor(ip string, port uint16) svcKey {
	a, _ := addr128(net.ParseIP(ip))
	return svcKey{Net: 0, Vip: a, Proto: 6, Port: htons(port)}
}

func TestLBRows(t *testing.T) {
	lbIP := "198.51.100.7"
	svc := lbSvc(corev1.ServiceExternalTrafficPolicyLocal, corev1.LoadBalancerIngress{IP: lbIP})
	slices := slice("node-a", "node-b")

	// node-a: one local backend -> one LB row with only 10.244.0.10.
	rows := computeRows(svc, slices, "node-a")
	lbKey := keyFor(lbIP, 80)
	v, ok := rows[lbKey]
	if !ok {
		t.Fatalf("no LB row on node-a: %v", rows)
	}
	if v.N != 1 {
		t.Fatalf("LB row backend count = %d, want 1 (local only)", v.N)
	}
	want, _ := addr128(net.ParseIP("10.244.0.10"))
	if v.Be[0].IP != want || v.Be[0].Port != htons(8080) {
		t.Fatalf("LB backend = %v:%d, want local 10.244.0.10:8080", v.Be[0].IP, v.Be[0].Port)
	}
	// The ClusterIP row keeps the cluster-wide set.
	cv, ok := rows[keyFor("10.96.0.50", 80)]
	if !ok || cv.N != 2 {
		t.Fatalf("ClusterIP row = %+v, want 2 cluster-wide backends", cv)
	}

	// A node with no local backend gets no LB row (Local's contract).
	rows = computeRows(svc, slices, "node-c")
	if _, ok := rows[lbKey]; ok {
		t.Fatal("node-c has an LB row despite no local backend")
	}

	// etp: Cluster is deferred — no LB rows anywhere.
	rows = computeRows(lbSvc(corev1.ServiceExternalTrafficPolicyCluster,
		corev1.LoadBalancerIngress{IP: lbIP}), slices, "node-a")
	if _, ok := rows[lbKey]; ok {
		t.Fatal("etp: Cluster produced an LB row")
	}

	// ipMode: Proxy means the LB proxies — no interception.
	proxy := corev1.LoadBalancerIPModeProxy
	rows = computeRows(lbSvc(corev1.ServiceExternalTrafficPolicyLocal,
		corev1.LoadBalancerIngress{IP: lbIP, IPMode: &proxy}), slices, "node-a")
	if _, ok := rows[lbKey]; ok {
		t.Fatal("ipMode Proxy produced an LB row")
	}

	// Empty nodeName (env unset) disables LB rows but keeps ClusterIP rows.
	rows = computeRows(svc, slices, "")
	if _, ok := rows[lbKey]; ok {
		t.Fatal("empty nodeName produced an LB row")
	}
	if _, ok := rows[keyFor("10.96.0.50", 80)]; !ok {
		t.Fatal("empty nodeName dropped the ClusterIP row")
	}
}
