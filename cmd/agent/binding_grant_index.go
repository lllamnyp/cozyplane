package main

import (
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
)

type bindingGrantKey struct{ consumerNS, vpcNS, vpcName string }
type resolvedBindingGrant struct {
	attached, forwarding bool
	cidrs                []string
}

func portBindingKey(port *sdnv1.Port) bindingGrantKey {
	return bindingGrantKey{port.Spec.PodNamespace, port.Spec.VPCRef.Namespace, port.Spec.VPCRef.Name}
}

// indexLocalBindingGrants belongs to one complete reconciliation. Unions are
// immutable and shared by endpoints for the same consumer and full VPC key.
func indexLocalBindingGrants(bindings []*sdnv1.VPCBinding, ports []*sdnv1.Port, endpoints localEndpointIndex) map[bindingGrantKey]resolvedBindingGrant {
	needed := map[bindingGrantKey][]*sdnv1.VPCBinding{}
	for _, port := range ports {
		if port.Spec.PodNamespace == "" || len(endpoints.forPort(port)) == 0 {
			continue
		}
		needed[portBindingKey(port)] = nil
	}
	for _, binding := range bindings {
		if binding == nil || !binding.DeletionTimestamp.IsZero() {
			continue
		}
		ref := binding.Spec.VPCRef
		if ref.Namespace == "" {
			ref.Namespace = binding.Namespace
		}
		if !vpnlimits.ObjectName(ref.Name) || !vpnlimits.NamespaceName(ref.Namespace) {
			continue
		}
		key := bindingGrantKey{binding.Namespace, ref.Namespace, ref.Name}
		if _, wanted := needed[key]; wanted {
			needed[key] = append(needed[key], binding)
		}
	}
	grants := make(map[bindingGrantKey]resolvedBindingGrant, len(needed))
	for key, bindings := range needed {
		a, f, c := sdnv1.BindingGrants(bindings, key.consumerNS, key.vpcNS, key.vpcName)
		grants[key] = resolvedBindingGrant{a, f, c}
	}
	return grants
}
