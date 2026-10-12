package vpnclientfilter

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// MaxPeers is the policy budget before any per-peer allocation in the appliance.
	MaxPeers        = 4096
	maxSources      = 8192
	maxDenied       = 9216
	maxDestinations = 65536
)

// Peer contains authenticated host sources and the VPC destinations they may use.
type Peer struct {
	Addresses    []string
	Destinations []string
}

type rules struct {
	sources      map[clientAddressKey]uint32
	denied       map[clientAddressKey]uint32
	destinations map[clientDestinationKey]uint32
}

func addressKey(addr netip.Addr) (clientAddressKey, error) {
	if !addr.IsValid() || addr.Is4In6() || addr.Zone() != "" {
		return clientAddressKey{}, fmt.Errorf("invalid address family")
	}
	bytes := addr.As16()
	encoded, err := datapath.EncodeAddress128(net.IP(bytes[:]))
	family := uint32(6)
	if addr.Is4() {
		family = 4
	}
	return clientAddressKey{Family: family, Address: encoded}, err
}

// compile preflights all budgets and ownership before touching kernel maps.
func compile(peers []Peer, local []netip.Addr) (*rules, error) {
	if len(peers) > MaxPeers || len(local) > 1024 {
		return nil, fmt.Errorf("client policy capacity exceeded")
	}
	r := &rules{sources: map[clientAddressKey]uint32{}, denied: map[clientAddressKey]uint32{}, destinations: map[clientDestinationKey]uint32{}}
	for _, addr := range local {
		key, err := addressKey(addr)
		if err != nil {
			return nil, err
		}
		r.denied[key] = 1
	}
	work := 0
	for index, peer := range peers {
		if len(peer.Addresses) == 0 || len(peer.Addresses) > 2 || len(peer.Destinations) == 0 || len(peer.Destinations) > vpnlimits.RoutePrefixes {
			return nil, fmt.Errorf("client peer %d has invalid policy bounds", index)
		}
		id := uint32(index + 1)
		for _, raw := range peer.Addresses {
			if len(raw) > vpnlimits.RoutePrefixBytes {
				return nil, fmt.Errorf("client source exceeds size budget")
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Bits() != prefix.Addr().BitLen() || !prefix.Addr().IsGlobalUnicast() {
				return nil, fmt.Errorf("client source must be a unicast host prefix")
			}
			key, err := addressKey(prefix.Addr())
			if err != nil {
				return nil, err
			}
			if _, found := r.sources[key]; found {
				return nil, fmt.Errorf("duplicate client source")
			}
			if _, found := r.denied[key]; found {
				return nil, fmt.Errorf("client source conflicts with appliance address")
			}
			r.sources[key], r.denied[key] = id, 1
		}
		for _, raw := range peer.Destinations {
			work++
			if work > maxDestinations || len(raw) > vpnlimits.RoutePrefixBytes {
				return nil, fmt.Errorf("client destination capacity exceeded")
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid client destination")
			}
			prefix = prefix.Masked()
			if !prefix.Addr().IsGlobalUnicast() || prefix.Bits() == 0 {
				return nil, fmt.Errorf("client destination must be a VPC prefix")
			}
			key, err := addressKey(prefix.Addr())
			if err != nil {
				return nil, err
			}
			bits := uint32(prefix.Bits())
			if key.Family == 4 {
				bits += 96
			}
			r.destinations[clientDestinationKey{Prefixlen: 64 + bits, Family: key.Family, Peer: id, Address: key.Address}] = 1
		}
	}
	if len(r.sources) > maxSources || len(r.denied) > maxDenied {
		return nil, fmt.Errorf("client address capacity exceeded")
	}
	return r, nil
}

// Install attaches a persistent classic TC filter to the down WireGuard device.
// The TC attachment retains program/maps if the process dies. The caller must
// delete or bring down the device before removal; closing map FDs is harmless.
func Install(device netlink.Link, peers []Peer) error {
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("enumerate appliance addresses: %w", err)
	}
	if len(addresses) > 1024 {
		return fmt.Errorf("appliance address capacity exceeded")
	}
	local := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		addr, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			return fmt.Errorf("invalid appliance address")
		}
		local = append(local, addr.Unmap())
	}
	r, err := compile(peers, local)
	if err != nil {
		return err
	}
	var objects clientObjects
	if err := loadClientObjects(&objects, nil); err != nil {
		return fmt.Errorf("load client policy: %w", err)
	}
	defer objects.Close()
	for key, value := range r.sources {
		if err := objects.Sources.Put(key, value); err != nil {
			return err
		}
	}
	for key, value := range r.denied {
		if err := objects.Denied.Put(key, value); err != nil {
			return err
		}
	}
	for key, value := range r.destinations {
		if err := objects.Destinations.Put(key, value); err != nil {
			return err
		}
	}
	attrs := netlink.QdiscAttrs{LinkIndex: device.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}
	if err := netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: attrs, QdiscType: "clsact"}); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create client policy hook: %w", err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: device.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
		Fd:          objects.VpnClientIngress.FD(), Name: "vpn_client", DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("attach client policy: %w", err)
	}
	return nil
}
