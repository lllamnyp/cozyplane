package sdn

import (
	"fmt"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"slices"
)

// blackholeVPNRoutes retains a bounded previously accepted prefix set while
// authorization is drained. Clearing it would enable ordinary cleartext egress.
func blackholeVPNRoutes(routes []sdnv1alpha1.VPCGatewayRouteStatus) ([]sdnv1alpha1.VPCGatewayRouteStatus, error) {
	if len(routes) > vpnlimits.RoutePrefixes {
		return nil, fmt.Errorf("retained VPN route rows exceed %d", vpnlimits.RoutePrefixes)
	}
	prefixes := 0
	for _, route := range routes {
		if len(route.CIDRs) > vpnlimits.RoutePrefixes-prefixes {
			return nil, fmt.Errorf("retained VPN prefixes exceed %d", vpnlimits.RoutePrefixes)
		}
		prefixes += len(route.CIDRs)
		for _, cidr := range route.CIDRs {
			if len(cidr) > sdnv1alpha1.MaxVPCCIDRBytes {
				return nil, fmt.Errorf("retained VPN prefix exceeds %d bytes", sdnv1alpha1.MaxVPCCIDRBytes)
			}
		}
	}
	var out []sdnv1alpha1.VPCGatewayRouteStatus
	for _, route := range routes {
		if len(route.CIDRs) != 0 {
			out = append(out, sdnv1alpha1.VPCGatewayRouteStatus{VPCRef: route.VPCRef, CIDRs: slices.Clone(route.CIDRs)})
		}
	}
	return out, nil
}

func vpnGatewayInputProblem(gw *sdnv1alpha1.VPNGateway) string {
	if wg := gw.Spec.WireGuard; wg != nil && len(wg.AddressPools) > 0 {
		if gw.Spec.IPsec != nil || (haMode(gw) != "" && haMode(gw) != sdnv1alpha1.VPNGatewayHAModeWarmStandby) {
			return "WireGuard client gateways require single or WarmStandby WireGuard appliances"
		}
		pools := make([]vpnlimits.WireGuardAddressPool, 0, min(len(wg.AddressPools), vpnlimits.AddressPools+1))
		if len(wg.AddressPools) > vpnlimits.AddressPools {
			return "WireGuard address pools exceed 128"
		}
		for _, p := range wg.AddressPools {
			pools = append(pools, vpnlimits.WireGuardAddressPool{Name: p.Name, CIDR: p.CIDR, DNS: p.DNS})
		}
		if problem := vpnlimits.WireGuardAddressPoolsProblem(pools); problem != "" {
			return problem
		}
	}
	if len(gw.Spec.AdditionalVPCRefs) > 9 {
		return "additional VPC references exceed nine"
	}
	seen := map[string]bool{gw.Spec.VPCRef.Name: true}
	for _, ref := range gw.Spec.AdditionalVPCRefs {
		if !vpnlimits.ObjectName(ref.Name) || seen[ref.Name] {
			return "additional VPC references must be valid and distinct"
		}
		seen[ref.Name] = true
	}
	if len(gw.Spec.AdditionalVPCRefs) > 0 && haMode(gw) == sdnv1alpha1.VPNGatewayHAModeLiveMigration {
		return "multi-VPC hubs do not support live migration"
	}

	if len(gw.Spec.ExternalAddress.AddressClaimNames) > 2 {
		return "external address claims exceed two"
	}
	for _, ref := range gw.Spec.ExternalAddress.AddressClaimNames {
		if !vpnlimits.ObjectName(ref) {
			return "external address claim references must be nonempty DNS subdomain names of at most 253 bytes"
		}
	}
	refs := []string{gw.Spec.VPCRef.Name, gw.Spec.ExternalAddress.AddressClaimName}
	refs = append(refs, gw.Spec.ExternalAddress.AddressClaimNames...)
	if ipsec := gw.Spec.IPsec; ipsec != nil {
		refs = append(refs, ipsec.CredentialSecretRef, ipsec.TrustedCASecretRef)
	}
	if ha := gw.Spec.HA; ha != nil && ha.VirtualMachine != nil {
		refs = append(refs, ha.VirtualMachine.StateClaimName, ha.VirtualMachine.CloudInitSecretRef)
	}
	for _, ref := range refs {
		if ref != "" && !vpnlimits.ObjectName(ref) {
			return "VPN object references must be DNS subdomain names of at most 253 bytes"
		}
	}
	if ipsec := gw.Spec.IPsec; ipsec != nil {
		if len(ipsec.AddressPools) > 0 && haMode(gw) == sdnv1alpha1.VPNGatewayHAModeActiveActive {
			return "IPsec address pools do not support ActiveActive independent lease allocation"
		}
		if len(ipsec.AddressPools) > vpnlimits.AddressPools {
			return "IPsec address pools exceed 128"
		}
		for _, pool := range ipsec.AddressPools {
			if problem := vpnlimits.IPsecPoolNameProblem(pool.Name, true); problem != "" {
				return problem
			}
			if len(pool.DNS) > vpnlimits.PoolDNSServers {
				return "IPsec pool DNS servers exceed 16"
			}
		}
	}
	if ha := gw.Spec.HA; ha != nil && ha.ActiveActive != nil && len(ha.ActiveActive.PeerAddresses) > vpnlimits.BGPNeighbors {
		return "BGP neighbors exceed 64"
	}
	return ""
}

func vpnConnectionReferenceProblem(c *sdnv1alpha1.VPNConnection) string {
	refs := []string{c.Spec.GatewayRef.Name}
	if wg := c.Spec.WireGuard; wg != nil {
		refs = append(refs, wg.PresharedKeySecretRef)
	}
	if ipsec := c.Spec.IPsec; ipsec != nil {
		if problem := vpnlimits.IPsecPoolNameProblem(ipsec.AddressPool, false); problem != "" {
			return problem
		}
		refs = append(refs, ipsec.Auth.PSKSecretRef)
		if eap := ipsec.Auth.EAP; eap != nil {
			refs = append(refs, eap.SecretRef)
		}
	}
	for _, ref := range refs {
		if ref != "" && !vpnlimits.ObjectName(ref) {
			return "VPN connection references must be DNS subdomain names of at most 253 bytes"
		}
	}
	return ""
}
