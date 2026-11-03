package vpnipsecfilter

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

type rules struct {
	denied       map[ipsecAddressKey]uint32
	destinations map[ipsecDestinationKey]uint32
}

func addressKey(addr netip.Addr) (ipsecAddressKey, error) {
	if !addr.IsValid() || addr.Is4In6() || addr.Zone() != "" {
		return ipsecAddressKey{}, fmt.Errorf("invalid address family")
	}
	bytes := addr.As16()
	encoded, err := datapath.EncodeAddress128(net.IP(bytes[:]))
	family := uint32(6)
	if addr.Is4() {
		family = 4
	}
	return ipsecAddressKey{Family: family, Address: encoded}, err
}

func compile(destinations []string, local []netip.Addr) (*rules, error) {
	if len(destinations) == 0 || len(destinations) > vpnlimits.RoutePrefixes || len(local) > 1024 {
		return nil, fmt.Errorf("IPsec policy capacity exceeded")
	}
	r := &rules{denied: map[ipsecAddressKey]uint32{}, destinations: map[ipsecDestinationKey]uint32{}}
	for _, addr := range local {
		key, err := addressKey(addr)
		if err != nil {
			return nil, err
		}
		r.denied[key] = 1
	}
	for _, raw := range destinations {
		if len(raw) > vpnlimits.RoutePrefixBytes {
			return nil, fmt.Errorf("IPsec destination exceeds size budget")
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid IPsec destination")
		}
		prefix = prefix.Masked()
		if !prefix.Addr().IsGlobalUnicast() || prefix.Bits() == 0 {
			return nil, fmt.Errorf("IPsec destination must be a VPC prefix")
		}
		key, err := addressKey(prefix.Addr())
		if err != nil {
			return nil, err
		}
		bits := prefix.Bits()
		if prefix.Addr().Is4() {
			bits += 96
		}
		r.destinations[ipsecDestinationKey{Prefixlen: uint32(32 + bits), Family: key.Family, Address: key.Address}] = 1
	}
	return r, nil
}

// Install requires a fresh, down XFRM interface. Populate immutable maps before
// attaching; classic TC retains them across process death until device removal.
func Install(device netlink.Link, destinations []string) error {
	if device.Attrs().Flags&net.FlagUp != 0 {
		return fmt.Errorf("IPsec interface must be down before policy installation")
	}
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
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
	r, err := compile(destinations, local)
	if err != nil {
		return err
	}
	var objects ipsecObjects
	if err := loadIpsecObjects(&objects, nil); err != nil {
		return fmt.Errorf("load IPsec policy: %w", err)
	}
	defer objects.Close()
	for k, v := range r.denied {
		if err := objects.Denied.Put(k, v); err != nil {
			return err
		}
	}
	for k, v := range r.destinations {
		if err := objects.Destinations.Put(k, v); err != nil {
			return err
		}
	}
	attrs := netlink.QdiscAttrs{LinkIndex: device.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}
	if err := netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: attrs, QdiscType: "clsact"}); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create IPsec policy hook: %w", err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: device.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
		Fd:          objects.VpnIpsecIngress.FD(), Name: "vpn_ipsec", DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("attach IPsec policy: %w", err)
	}
	return nil
}
