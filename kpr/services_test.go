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
	rows, _ := computeRows(svc, slices, "node-a", nil, false)
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
	rows, _ = computeRows(svc, slices, "node-c", nil, false)
	if _, ok := rows[lbKey]; ok {
		t.Fatal("node-c has an LB row despite no local backend")
	}

	// etp: Cluster with the DSR opt-in carries the cluster-wide backend set
	// (remote ones DSR).
	cluster := lbSvc(corev1.ServiceExternalTrafficPolicyCluster,
		corev1.LoadBalancerIngress{IP: lbIP})
	rows, _ = computeRows(cluster, slices, "node-a", nil, true)
	if v, ok := rows[lbKey]; !ok || v.N != 2 {
		t.Fatalf("etp Cluster LB row = %+v ok=%v, want the cluster-wide 2 backends", rows[lbKey], ok)
	}

	// Without the opt-in, Cluster degrades to node-local delivery: the local
	// backend on node-a, no row at all on backend-less node-c.
	rows, _ = computeRows(cluster, slices, "node-a", nil, false)
	if v, ok := rows[lbKey]; !ok || v.N != 1 || v.Be[0].IP != want {
		t.Fatalf("gated-off Cluster LB row = %+v ok=%v, want the 1 local backend", rows[lbKey], ok)
	}
	rows, _ = computeRows(cluster, slices, "node-c", nil, false)
	if _, ok := rows[lbKey]; ok {
		t.Fatal("gated-off Cluster produced an LB row on a backend-less node")
	}

	// ipMode: Proxy means the LB proxies — no interception.
	proxy := corev1.LoadBalancerIPModeProxy
	rows, _ = computeRows(lbSvc(corev1.ServiceExternalTrafficPolicyLocal,
		corev1.LoadBalancerIngress{IP: lbIP, IPMode: &proxy}), slices, "node-a", nil, false)
	if _, ok := rows[lbKey]; ok {
		t.Fatal("ipMode Proxy produced an LB row")
	}

	// Empty nodeName (env unset) disables LB rows but keeps ClusterIP rows.
	rows, _ = computeRows(svc, slices, "", nil, false)
	if _, ok := rows[lbKey]; ok {
		t.Fatal("empty nodeName produced an LB row")
	}
	if _, ok := rows[keyFor("10.96.0.50", 80)]; !ok {
		t.Fatal("empty nodeName dropped the ClusterIP row")
	}
}

func TestNodePortAndSourceRangeRows(t *testing.T) {
	lbIP := "198.51.100.7"
	svc := lbSvc(corev1.ServiceExternalTrafficPolicyLocal, corev1.LoadBalancerIngress{IP: lbIP})
	svc.Spec.Ports[0].NodePort = 30080
	svc.Spec.LoadBalancerSourceRanges = []string{"192.0.2.0/24", "bogus"}
	slices := slice("node-a", "node-b")
	nodeAddrs := []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("fd00::5")}

	rows, srcs := computeRows(svc, slices, "node-a", nodeAddrs, false)

	// NodePort row keyed by the node's v4 address x nodePort, local backends.
	npKey := keyFor("10.0.0.5", 30080)
	if v, ok := rows[npKey]; !ok || v.N != 1 {
		t.Fatalf("NodePort row = %+v ok=%v, want 1 local backend", rows[npKey], ok)
	}
	// The v6 node address has no v6 backends in the fixture: no row.
	if _, ok := rows[keyFor("fd00::5", 30080)]; ok {
		t.Fatal("v6 NodePort row despite no v6 backends")
	}
	// The LB row carries the src-ranges flag; the NodePort row does not.
	lbKey := keyFor(lbIP, 80)
	if rows[lbKey].Flags&svcFSrcRanges == 0 {
		t.Fatal("LB row missing SVC_F_SRC_RANGES")
	}
	if rows[npKey].Flags&svcFSrcRanges != 0 {
		t.Fatal("NodePort row wrongly range-flagged")
	}
	// One LPM entry: the valid /24 in NAT64 form (prefixlen 128+96+24);
	// the bogus range is ignored.
	if len(srcs) != 1 {
		t.Fatalf("lb_src entries = %d, want 1: %v", len(srcs), srcs)
	}
	want, _ := addr128(net.ParseIP("192.0.2.0"))
	lb128, _ := addr128(net.ParseIP(lbIP))
	if _, ok := srcs[lbSrcKey{Prefixlen: 128 + 96 + 24, Vip: lb128, Client: want}]; !ok {
		t.Fatalf("missing expected lb_src key: %v", srcs)
	}

	// etp Cluster (DSR opted in): rows carry the cluster-wide set, sourceRanges
	// still apply, and NodePort rows exist too (Cluster is NodePort's upstream
	// default).
	cl := lbSvc(corev1.ServiceExternalTrafficPolicyCluster, corev1.LoadBalancerIngress{IP: lbIP})
	cl.Spec.Ports[0].NodePort = 30080
	cl.Spec.LoadBalancerSourceRanges = []string{"192.0.2.0/24"}
	rows, srcs = computeRows(cl, slices, "node-a", nodeAddrs, true)
	if v, ok := rows[keyFor(lbIP, 80)]; !ok || v.N != 2 || v.Flags&svcFSrcRanges == 0 {
		t.Fatalf("etp Cluster LB row = %+v ok=%v, want 2 backends + range flag", v, ok)
	}
	if v, ok := rows[keyFor("10.0.0.5", 30080)]; !ok || v.N != 2 {
		t.Fatalf("etp Cluster NodePort row = %+v ok=%v, want 2 backends", v, ok)
	}
	if len(srcs) != 1 {
		t.Fatalf("etp Cluster lb_src entries = %d, want 1: %v", len(srcs), srcs)
	}

	// Gated off, the same service's rows degrade to the node-local backend.
	rows, _ = computeRows(cl, slices, "node-a", nodeAddrs, false)
	if v, ok := rows[keyFor(lbIP, 80)]; !ok || v.N != 1 {
		t.Fatalf("gated-off Cluster LB row = %+v ok=%v, want 1 local backend", v, ok)
	}
	if v, ok := rows[keyFor("10.0.0.5", 30080)]; !ok || v.N != 1 {
		t.Fatalf("gated-off Cluster NodePort row = %+v ok=%v, want 1 local backend", v, ok)
	}
}
