package v1alpha1

import (
	"fmt"
	"net"
)

// MaxForwardingPrefixes bounds union work, including duplicate input prefixes.
// It matches the global forwarding-prefix map ceiling, not a per-leg quota.
const MaxForwardingPrefixes = 4096

const MaxForwardingPrefixBytes = 64

func ValidateForwardingPrefixes(cidrs []string) error {
	if len(cidrs) > MaxForwardingPrefixes {
		return fmt.Errorf("forwarding grant exceeds %d input prefixes", MaxForwardingPrefixes)
	}
	for i, cidr := range cidrs {
		if len(cidr) > MaxForwardingPrefixBytes {
			return fmt.Errorf("forwarding prefix at index %d exceeds %d bytes", i, MaxForwardingPrefixBytes)
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("forwarding prefix at index %d is not a valid IP CIDR", i)
		}
	}
	return nil
}

// BindingGrants resolves the union of live grants for a consumer and VPC.
// An unrestricted forwarding grant wins over scoped grants.
func BindingGrants(bindings []*VPCBinding, consumerNS, vpcNS, vpcName string) (attached, forwarding bool, cidrs []string) {
	attached, forwarding, cidrs, _ = BindingGrantsWithBudget(bindings, consumerNS, vpcNS, vpcName)
	return
}

// BindingGrantsWithBudget reports oversized scoped unions to CNI callers.
// On rejection attachment remains authorized, while forwarding is disabled.
func BindingGrantsWithBudget(bindings []*VPCBinding, consumerNS, vpcNS, vpcName string) (attached, forwarding bool, cidrs []string, err error) {
	for _, binding := range bindings {
		if BindingAuthorizesAttachment(binding, consumerNS, vpcNS, vpcName) && binding.Spec.AllowForwarding && len(binding.Spec.ForwardingCIDRs) == 0 {
			return true, true, nil, nil // no scoped union is needed
		}
	}
	grant := NewBindingGrantAccumulator(consumerNS, vpcNS, vpcName)
	for _, binding := range bindings {
		grant.Add(binding)
	}
	return grant.Result()
}

// BindingGrantAccumulator resolves a streamed snapshot without retaining list
// objects. Result is authoritative only after the caller completes its scan.
// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false
type BindingGrantAccumulator struct {
	consumerNS, vpcNS, vpcName    string
	attached, forwarding, blanket bool
	cidrs                         []string
	err                           error
}

func NewBindingGrantAccumulator(consumerNS, vpcNS, vpcName string) BindingGrantAccumulator {
	return BindingGrantAccumulator{consumerNS: consumerNS, vpcNS: vpcNS, vpcName: vpcName}
}

func (g *BindingGrantAccumulator) Add(binding *VPCBinding) {
	if !BindingAuthorizesAttachment(binding, g.consumerNS, g.vpcNS, g.vpcName) {
		return
	}
	g.attached = true
	if !binding.Spec.AllowForwarding {
		return
	}
	g.forwarding = true
	if len(binding.Spec.ForwardingCIDRs) == 0 {
		g.blanket, g.cidrs, g.err = true, nil, nil
		return
	}
	if g.blanket || g.err != nil {
		return
	}
	if len(binding.Spec.ForwardingCIDRs) > MaxForwardingPrefixes-len(g.cidrs) {
		g.err = fmt.Errorf("forwarding grant exceeds %d input prefixes", MaxForwardingPrefixes)
	} else {
		g.err = ValidateForwardingPrefixes(binding.Spec.ForwardingCIDRs)
	}
	if g.err != nil {
		g.cidrs = nil
		return
	}
	g.cidrs = append(g.cidrs, binding.Spec.ForwardingCIDRs...)
}

func (g *BindingGrantAccumulator) Result() (attached, forwarding bool, cidrs []string, err error) {
	if g.err != nil {
		return g.attached, false, nil, g.err
	}
	return g.attached, g.forwarding, g.cidrs, nil
}

// BindingAuthorizesAttachment checks consent without interpreting forwarding
// payloads, which cannot affect the independent attachment authorization.
func BindingAuthorizesAttachment(binding *VPCBinding, consumerNS, vpcNS, vpcName string) bool {
	if binding == nil || binding.Namespace != consumerNS || !binding.DeletionTimestamp.IsZero() {
		return false
	}
	ref := binding.Spec.VPCRef
	if ref.Namespace == "" {
		ref.Namespace = binding.Namespace
	}
	return ref.Namespace == vpcNS && ref.Name == vpcName
}
