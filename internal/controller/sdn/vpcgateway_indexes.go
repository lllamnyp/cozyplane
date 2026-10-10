package sdn

import (
	"maps"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const gatewayPodNamespaceIndex = "cozyplane.gateway-pod-namespace"

const gatewayVPCIndex = "cozyplane.gateway-vpc"

func gatewayVPCKeys(obj client.Object) []string {
	var name string
	switch g := obj.(type) {
	case *sdnv1alpha1.VPCGateway:
		name = g.Spec.VPCRef.Name
	case *sdnv1alpha1.VPNGateway:
		out := []string{}
		seen := map[string]bool{}
		add := func(name string) {
			if vpnlimits.ObjectName(name) && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		add(g.Spec.VPCRef.Name)
		if len(g.Spec.AdditionalVPCRefs) <= 9 {
			for _, ref := range g.Spec.AdditionalVPCRefs {
				add(ref.Name)
			}
		}
		return out
	}
	if !vpnlimits.ObjectName(name) {
		return nil
	}
	return []string{name}
}

func gatewayPodEvents() predicate.Predicate {
	terminal := func(p *corev1.Pod) bool {
		return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
	}
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		old, oldOK := e.ObjectOld.(*corev1.Pod)
		current, currentOK := e.ObjectNew.(*corev1.Pod)
		if !oldOK || !currentOK {
			return false
		}
		return old.UID != current.UID || !maps.Equal(old.Labels, current.Labels) || old.DeletionTimestamp.IsZero() != current.DeletionTimestamp.IsZero() || terminal(old) != terminal(current)
	}}
}

func gatewayPodNamespaceKeys(obj client.Object) []string {
	g, ok := obj.(*sdnv1alpha1.VPCGateway)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(ns string) {
		if ns == "" {
			ns = g.Namespace
		}
		if !vpnlimits.NamespaceName(ns) {
			return
		}
		if !seen[ns] {
			seen[ns] = true
			out = append(out, ns)
		}
	}
	if g.Spec.Appliance != nil {
		add(g.Spec.Appliance.Namespace)
	}
	if len(g.Spec.Routes) > vpnlimits.RoutePrefixes {
		return out // Do not expand a legacy route array the resolver rejects.
	}
	for _, route := range g.Spec.Routes {
		add(route.Via.Namespace)
	}
	return out
}
