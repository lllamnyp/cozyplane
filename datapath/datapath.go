/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// Manager owns the node-level datapath: the loaded eBPF objects, the Geneve
// device, and the remotes map. It is used by the agent. The CNI plugin uses the
// pinned program/maps directly (see attach.go) rather than this Manager.
type Manager struct {
	objs          overlayObjects
	geneveIfindex int
	uplinkIfindex int
	uplinkMAC     net.HardwareAddr
	// The floating uplink, when floating addresses live on a different link
	// than the default route (EnsureFloatingUplink); zero = same as uplink.
	floatIfindex int
	floatMAC     net.HardwareAddr
	recreatedPins []string
}

// New returns an unloaded Manager.
func New() *Manager { return &Manager{} }

// RecreatedPins returns the names of pinned maps Load removed because the new
// object file could not reuse them (a map-ABI change); their state was rebuilt
// by RebuildLocalState / the agent's watches. Empty on a compatible restart.
func (m *Manager) RecreatedPins() []string { return m.recreatedPins }

// Load removes the memlock limit, reconciles stale pins, loads the eBPF
// objects (pinning maps by name under PinRoot), pins the classifier program,
// and records the VNI.
func (m *Manager) Load(vni uint32) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	if err := os.MkdirAll(PinRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir pin root: %w", err)
	}

	// A pinned map the new object cannot reuse (map-ABI change) would fail the
	// load below; remove such pins so they are created fresh (issue #7). The
	// caller rebuilds their CNI-written state via RebuildLocalState.
	recreated, err := reconcilePins()
	if err != nil {
		return fmt.Errorf("reconcile pinned maps: %w", err)
	}
	m.recreatedPins = recreated

	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: PinRoot}}
	if err := loadOverlayObjects(&m.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load bpf objects: %+v", ve)
		}
		return fmt.Errorf("load bpf objects: %w", err)
	}

	progPath := filepath.Join(PinRoot, progPinName)
	_ = os.Remove(progPath)
	if err := m.objs.CozyplaneFromPod.Pin(progPath); err != nil {
		return fmt.Errorf("pin from_pod program: %w", err)
	}
	toPodPath := filepath.Join(PinRoot, toPodPinName)
	_ = os.Remove(toPodPath)
	if err := m.objs.CozyplaneToPod.Pin(toPodPath); err != nil {
		return fmt.Errorf("pin to_pod program: %w", err)
	}

	if err := m.objs.Params.Put(cfgVNI, vni); err != nil {
		return fmt.Errorf("set vni: %w", err)
	}

	return nil
}

// EnsureGeneve creates (if absent) and brings up the collect_metadata Geneve
// device and records its ifindex in the config map.
func (m *Manager) EnsureGeneve(port uint16) error {
	link, err := netlink.LinkByName(GeneveDevice)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = GeneveDevice
		g := &netlink.Geneve{LinkAttrs: la, Dport: port, FlowBased: true}
		if err := netlink.LinkAdd(g); err != nil {
			return fmt.Errorf("create geneve device: %w", err)
		}
		link, err = netlink.LinkByName(GeneveDevice)
		if err != nil {
			return fmt.Errorf("lookup geneve device: %w", err)
		}
	}

	// All nodes' Geneve devices share OverlayMAC so decapsulated frames (whose
	// inner destination MAC the encap path rewrites to it) are delivered as
	// PACKET_HOST and forwarded to the local pod by the kernel.
	if err := netlink.LinkSetHardwareAddr(link, OverlayMAC); err != nil {
		return fmt.Errorf("set geneve MAC: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set geneve up: %w", err)
	}
	m.geneveIfindex = link.Attrs().Index

	if err := m.objs.Params.Put(cfgGeneveIfindex, uint32(m.geneveIfindex)); err != nil {
		return fmt.Errorf("set geneve ifindex: %w", err)
	}

	// Decapsulated traffic arrives on the Geneve device from a tunnel whose
	// outer source is a remote node; reverse-path filtering would drop it.
	_ = WriteProcSys(fmt.Sprintf("net/ipv4/conf/%s/rp_filter", GeneveDevice), "0")

	return nil
}

// AttachUplink attaches the classifier at the egress of the node's default-route
// interface so host-originated traffic to remote pod CIDRs is encapsulated too
// (node→remote-pod reachability). Returns the uplink interface name.
func (m *Manager) AttachUplink() (string, error) {
	idx, name, err := defaultRouteLink()
	if err != nil {
		return "", err
	}
	if err := AttachEgress(idx, m.objs.CozyplaneFromPod); err != nil {
		return "", err
	}
	return name, nil
}

// AttachUplinkIngress attaches from_uplink at the ingress of the node's
// default-route interface — the entry point for off-cluster traffic destined to
// a floating IP advertised from this node. It is a no-op for every other packet
// (one hash lookup), so it is safe to attach unconditionally. Returns the uplink
// interface name.
func (m *Manager) AttachUplinkIngress() (string, error) {
	idx, name, err := defaultRouteLink()
	if err != nil {
		return "", err
	}
	if err := AttachIngress(idx, m.objs.CozyplaneFromUplink); err != nil {
		return "", err
	}
	// from_pod redirects floating-IP replies out this interface (redirect_neigh).
	if err := m.objs.Params.Put(cfgUplinkIfindex, uint32(idx)); err != nil {
		return "", fmt.Errorf("set uplink ifindex: %w", err)
	}
	// from_uplink answers ARP for floating IPs with this MAC (the advertisement).
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return "", fmt.Errorf("lookup uplink %d: %w", idx, err)
	}
	if err := m.setUplinkMAC(link.Attrs().HardwareAddr); err != nil {
		return "", err
	}
	m.uplinkIfindex = idx
	m.uplinkMAC = link.Attrs().HardwareAddr
	return name, nil
}

// setUplinkMAC records the uplink's MAC for the floating-IP ARP responder.
func (m *Manager) setUplinkMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("uplink MAC %q is not 6 bytes", mac)
	}
	var v overlayCozyMac
	copy(v.Addr[:], mac)
	if err := m.objs.UplinkMac.Put(uint32(0), &v); err != nil {
		return fmt.Errorf("set uplink mac: %w", err)
	}
	return nil
}

// defaultRouteLink returns the ifindex and name of the IPv4 default-route link.
func defaultRouteLink() (int, string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return 0, "", fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		isDefault := r.Dst == nil || r.Dst.IP.IsUnspecified()
		if isDefault && r.Gw != nil && r.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				return 0, "", err
			}
			return r.LinkIndex, link.Attrs().Name, nil
		}
	}
	return 0, "", fmt.Errorf("no default route found")
}

// DefaultRouteSrcIP returns the IPv4 address host-originated traffic to off-link
// destinations sources from — the primary global-scope address of the
// default-route link. A remote pod's reply to this node is addressed to it, so
// the agent advertises it and peers map it to this node's Geneve endpoint (see
// node_remotes / SetNodeRemote). On a single-NIC node this equals the InternalIP;
// on a multi-NIC node (e.g. the dev cluster's OCI split of management vs cluster NIC) it may
// differ, which is exactly why it must be advertised rather than inferred.
func DefaultRouteSrcIP() (net.IP, error) {
	idx, _, err := defaultRouteLink()
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list addrs on default-route link: %w", err)
	}
	for _, a := range addrs {
		if a.IP.IsGlobalUnicast() && a.Scope == int(netlink.SCOPE_UNIVERSE) {
			return a.IP, nil
		}
	}
	return nil, fmt.Errorf("no global IPv4 on default-route link")
}

// SetRemote installs (or replaces) a route to a remote endpoint within a
// network scope: a node pod CIDR (scope 0, the default network) or a VPC pod
// /32 (scope = VNI). Overlapping VPCs never collide because the scope is part
// of the key.
func (m *Manager) SetRemote(scope uint32, cidr string, nodeIP net.IP) error {
	key, err := lpmKey(scope, cidr)
	if err != nil {
		return err
	}
	ip4 := nodeIP.To4()
	if ip4 == nil {
		return fmt.Errorf("node IP %q is not IPv4", nodeIP)
	}
	// remote_ipv4 is consumed by bpf_skb_set_tunnel_key in host byte order.
	return m.objs.Remotes.Put(key, binary.BigEndian.Uint32(ip4))
}

// SetNodeRemote maps a node address (any of its interface IPs) to that node's
// Geneve underlay IP, so a default-network pod's traffic to that address is
// encapsulated over the overlay rather than leaving on the wire with a pod
// source (which a spoof-guarding underlay, e.g. OCI, drops). geneveIP is the
// node's overlay endpoint — its InternalIP, the same address SetRemote uses for
// that node's pod CIDR.
func (m *Manager) SetNodeRemote(addr, geneveIP net.IP) error {
	key, err := addr128(addr)
	if err != nil {
		return err
	}
	ip4 := geneveIP.To4()
	if ip4 == nil {
		return fmt.Errorf("node geneve IP %q is not IPv4", geneveIP)
	}
	return m.objs.NodeRemotes.Put(key, binary.BigEndian.Uint32(ip4))
}

// DelNodeRemote removes a node address from the node_remotes map.
func (m *Manager) DelNodeRemote(addr net.IP) error {
	key, err := addr128(addr)
	if err != nil {
		return err
	}
	if err := m.objs.NodeRemotes.Delete(key); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// SetNetwork maps a CIDR, as seen from a scope network, to a destination net
// id. A VPC's own CIDR is stored at its own scope; a peering stores each side's
// CIDR under the other's scope.
func (m *Manager) SetNetwork(scope uint32, cidr string, id uint32) error {
	key, err := lpmKey(scope, cidr)
	if err != nil {
		return err
	}
	return m.objs.Networks.Put(key, id)
}

// DelNetwork removes a (scope, CIDR) entry from the networks map.
func (m *Manager) DelNetwork(scope uint32, cidr string) error {
	key, err := lpmKey(scope, cidr)
	if err != nil {
		return err
	}
	if err := m.objs.Networks.Delete(key); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// PeerNet is a peering delivery entry: within Scope, CIDR resolves to Net (the
// peer's network id), so from_pod/to_pod can find and admit peered traffic.
type PeerNet struct {
	Scope uint32
	CIDR  string
	Net   uint32
}

// SyncPeerNetworks makes the networks map's cross-scope (peer) entries exactly
// `desired`, leaving own-CIDR entries untouched. A peer entry is identifiable
// because its value differs from its scope (an own entry maps a VPC's CIDR to
// its own id); enumerating the pinned map lets a restarted agent prune
// peerings deleted while it was down. Mirrors the diff-against-pinned-map
// pattern used for the peers and gateways maps.
func (m *Manager) SyncPeerNetworks(desired []PeerNet) error {
	want := map[overlayLpmKey]uint32{}
	for _, d := range desired {
		key, err := lpmKey(d.Scope, d.CIDR)
		if err != nil {
			return err
		}
		want[key] = d.Net
	}

	var key overlayLpmKey
	var val uint32
	var stale []overlayLpmKey
	it := m.objs.Networks.Iterate()
	for it.Next(&key, &val) {
		if val == key.ScopeNet {
			continue // own-CIDR entry, not ours to touch
		}
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate networks: %w", err)
	}
	for _, k := range stale {
		if err := m.objs.Networks.Delete(k); err != nil && !isNotExist(err) {
			return err
		}
	}
	for k, v := range want {
		if err := m.objs.Networks.Put(k, v); err != nil {
			return err
		}
	}
	return nil
}

// DelRemote removes a (scope, CIDR) entry from the remotes map.
func (m *Manager) DelRemote(scope uint32, cidr string) error {
	key, err := lpmKey(scope, cidr)
	if err != nil {
		return err
	}
	if err := m.objs.Remotes.Delete(key); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// Close releases the loaded objects (pins persist).
func (m *Manager) Close() error { return m.objs.Close() }

// lpmKey builds the scoped LPM-trie key for a CIDR within a network. The
// address is laid out in network byte order in memory (LPM matches MSB-first);
// on a little-endian host that means the uint32 field decodes the network bytes
// little-endian. The scope net occupies the leading 32 key bits (always fully
// specified: prefixlen = 32 + CIDR ones), so lookups never cross scopes and
// overlapping CIDRs in different networks stay distinct.
func lpmKey(scope uint32, cidr string) (overlayLpmKey, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return overlayLpmKey{}, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	addr, err := addr128(ipnet.IP)
	if err != nil {
		return overlayLpmKey{}, err
	}
	ones, _ := ipnet.Mask.Size()
	// A v4 CIDR sits under the /96 NAT64 prefix, so its match length includes
	// those 96 leading bits; a v6 CIDR uses its own length. The 32-bit scope net
	// always leads the key (fully specified), so lookups never cross scopes.
	off := uint32(0)
	if ipnet.IP.To4() != nil {
		off = 96
	}
	return overlayLpmKey{
		Prefixlen: 32 + off + uint32(ones),
		ScopeNet:  scope,
		Addr:      addr,
	}, nil
}

// addr128 maps an IP to the 16-byte, network-order form the datapath keys on: a
// v6 address as-is, a v4 address in its RFC 6052 (NAT64) form 64:ff9b::a.b.c.d —
// a routable v6 address, so a future cross-family translator matches these
// entries. Must stay in lockstep with v4_to_128 in bpf/overlay.c.
func addr128(ip net.IP) (overlayAddr128, error) {
	var a overlayAddr128
	if v4 := ip.To4(); v4 != nil {
		a.B[1], a.B[2], a.B[3] = 0x64, 0xff, 0x9b // 64:ff9b::/96
		copy(a.B[12:], v4)
		return a, nil
	}
	if v6 := ip.To16(); v6 != nil {
		copy(a.B[:], v6)
		return a, nil
	}
	return a, fmt.Errorf("invalid IP %q", ip)
}

// addr128Str parses an IP string into its 16-byte map form.
func addr128Str(s string) (overlayAddr128, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return overlayAddr128{}, fmt.Errorf("invalid IP %q", s)
	}
	return addr128(ip)
}

// addr128ToIP renders a 16-byte map address back to an IP: a 64:ff9b::/96 NAT64
// address unwraps to its embedded v4, anything else is the v6 as-is.
func addr128ToIP(a overlayAddr128) net.IP {
	nat64 := a.B[1] == 0x64 && a.B[2] == 0xff && a.B[3] == 0x9b
	for i := 4; i < 12 && nat64; i++ {
		nat64 = a.B[i] == 0
	}
	if nat64 && a.B[0] == 0 {
		return net.IP(a.B[12:16]).To4()
	}
	ip := make(net.IP, 16)
	copy(ip, a.B[:])
	return ip
}

func isNotExist(err error) bool {
	return err != nil && (errors.Is(err, ebpf.ErrKeyNotExist) || os.IsNotExist(err) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH))
}

// isExist reports whether err is an "already exists" error (e.g. re-adding an
// ip rule that survived a previous CNI ADD).
func isExist(err error) bool {
	return err != nil && errors.Is(err, syscall.EEXIST)
}

// WriteProcSys writes a /proc/sys value (path uses '/' separators, e.g.
// "net/ipv4/conf/eth0/proxy_arp").
func WriteProcSys(path, val string) error {
	return os.WriteFile(filepath.Join("/proc/sys", path), []byte(val), 0o644)
}
