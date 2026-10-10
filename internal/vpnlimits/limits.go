// Package vpnlimits defines input budgets shared by VPN admission and reconciliation.
package vpnlimits

// RoutePrefixes limits input candidates per gateway, including duplicates and
// selected pool prefixes. The node route map is shared and can fill sooner.
const RoutePrefixes = 4096

// RoutePrefixBytes bounds parsing and diagnostics for a single textual prefix.
// IPv6 addresses, including embedded IPv4 and host bits, fit within this limit.
const RoutePrefixBytes = 64

const (
	AddressPools   = 128
	PoolDNSServers = 16
	BGPNeighbors   = 64
)
