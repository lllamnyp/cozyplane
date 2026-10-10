package main

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestNetworkPolicyCompilerBoundsUniqueIdentityMatrix(t *testing.T) {
	var pods []*corev1.Pod
	for i := 0; i < 450; i++ {
		pods = append(pods, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: fmt.Sprint("pod-", i), Labels: map[string]string{"identity": fmt.Sprint(i)}}, Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: fmt.Sprintf("10.180.%d.%d", i/250, i%250+1)}}}})
	}
	policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "all-peers"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}}}}
	compiled := compileNetworkPolicies(pods, []*corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}}, []*networkingv1.NetworkPolicy{policy})
	if len(compiled.allows) > 65536 {
		t.Fatalf("quadratic policy retained %d rules before kernel capacity check", len(compiled.allows))
	}
	if compiled.err == nil {
		t.Fatal("oversized snapshot was accepted")
	}
	compiled = compileNetworkPolicies(pods[:20], nil, []*networkingv1.NetworkPolicy{policy})
	if compiled.err != nil || len(compiled.allows) != 800 {
		t.Fatalf("bounded recovery: rules=%d err=%v", len(compiled.allows), compiled.err)
	}
}

func TestNetworkPolicyCompilerBoundsDuplicateWork(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant"}, Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.180.1.1"}}}}
	policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant"}, Spec: networkingv1.NetworkPolicySpec{Ingress: []networkingv1.NetworkPolicyIngressRule{{}}}}
	policies := make([]*networkingv1.NetworkPolicy, npCompileLimit)
	for i := range policies {
		policies[i] = policy
	}
	pods := make([]*corev1.Pod, 30)
	for i := range pods {
		p := pod.DeepCopy()
		p.Labels = map[string]string{"id": fmt.Sprint(i)}
		pods[i] = p
	}
	c := compileNetworkPolicies(pods, nil, policies)
	if c.err == nil {
		t.Fatal("duplicate rules did not exhaust CPU work budget")
	}
}
