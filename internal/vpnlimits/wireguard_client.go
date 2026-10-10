package vpnlimits

import "net/netip"

// WireGuardAddressPool is API-independent so admission and legacy reconciliation
// can apply the same bounded input contract before allocation or rendering.
type WireGuardAddressPool struct {
	Name string
	CIDR string
	DNS  []string
}

// WireGuardAddressPoolsProblem never includes input values in diagnostics.
func WireGuardAddressPoolsProblem(pools []WireGuardAddressPool) string {
	if len(pools) > AddressPools {
		return "WireGuard address pools exceed 128"
	}
	names := make(map[string]struct{}, len(pools))
	prefixes := make([]netip.Prefix, 0, len(pools))
	for _, pool := range pools {
		if !ObjectName(pool.Name) {
			return "WireGuard pool names must be nonempty DNS subdomains of at most 253 bytes"
		}
		if _, exists := names[pool.Name]; exists {
			return "WireGuard pool names must be unique"
		}
		names[pool.Name] = struct{}{}
		if len(pool.CIDR) > RoutePrefixBytes {
			return "WireGuard pool CIDRs must contain at most 64 bytes"
		}
		prefix, err := netip.ParsePrefix(pool.CIDR)
		if err != nil || prefix.Addr().Is4In6() {
			return "WireGuard pools require valid IPv4 or IPv6 CIDRs without mapped IPv4 addresses"
		}
		prefix = prefix.Masked()
		for _, previous := range prefixes {
			if prefix.Overlaps(previous) {
				return "WireGuard address pools must not overlap"
			}
		}
		prefixes = append(prefixes, prefix)
		if len(pool.DNS) > PoolDNSServers {
			return "WireGuard pool DNS servers exceed 16"
		}
		for _, dns := range pool.DNS {
			if len(dns) > RoutePrefixBytes {
				return "WireGuard pool DNS addresses must contain at most 64 bytes"
			}
			addr, err := netip.ParseAddr(dns)
			if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() {
				return "WireGuard pool DNS servers must be unicast IPv4 or IPv6 addresses without zones"
			}
		}
	}
	return ""
}

// WireGuardClientProblem validates workstation inputs before index construction
// or gateway lookups. Pool existence/families and served VPCs need the gateway
// and are checked by the controller, not by this structural helper.
func WireGuardClientProblem(peer WireGuardPeer, pools, vpcs, remoteCIDRs []string) string {
	if len(remoteCIDRs) != 0 {
		return "WireGuard clients cannot declare remoteCIDRs"
	}
	if peer.Endpoint != "" || len(peer.Endpoints) != 0 || len(peer.PublicKeys) != 0 {
		return "WireGuard clients require one public key and no fixed peer endpoints"
	}
	if problem := WireGuardPeerProblem(peer); problem != "" {
		return problem
	}
	if len(pools) < 1 || len(pools) > 2 {
		return "WireGuard clients require one or two named address pools"
	}
	for i, name := range pools {
		if !ObjectName(name) {
			return "WireGuard client pool names must be DNS subdomains of at most 253 bytes"
		}
		if i == 1 && name == pools[0] {
			return "WireGuard client address pools must be distinct"
		}
	}
	if len(vpcs) < 1 || len(vpcs) > 10 {
		return "WireGuard clients require one to ten explicit VPC references"
	}
	names := make(map[string]struct{}, len(vpcs))
	for _, name := range vpcs {
		if !ObjectName(name) {
			return "WireGuard client VPC names must be DNS subdomains of at most 253 bytes"
		}
		if _, exists := names[name]; exists {
			return "WireGuard client VPC references must be distinct"
		}
		names[name] = struct{}{}
	}
	return ""
}
