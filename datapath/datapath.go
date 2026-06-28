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
	"fmt"
	"net"
	"os"
	"path/filepath"

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
}

// New returns an unloaded Manager.
func New() *Manager { return &Manager{} }

// Load removes the memlock limit, loads the eBPF objects (pinning maps by name
// under PinRoot), pins the classifier program, and records the VNI.
func (m *Manager) Load(vni uint32) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	if err := os.MkdirAll(PinRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir pin root: %w", err)
	}

	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: PinRoot}}
	if err := loadOverlayObjects(&m.objs, opts); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}

	progPath := filepath.Join(PinRoot, progPinName)
	_ = os.Remove(progPath)
	if err := m.objs.CozyplaneFromPod.Pin(progPath); err != nil {
		return fmt.Errorf("pin program: %w", err)
	}

	if err := m.objs.Params.Put(cfgVNI, vni); err != nil {
		return fmt.Errorf("set vni: %w", err)
	}

	return nil
}

// EnsureGeneve creates (if absent) and brings up the collect_metadata Geneve
// device and records its ifindex in the config map.
func (m *Manager) EnsureGeneve() error {
	link, err := netlink.LinkByName(GeneveDevice)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = GeneveDevice
		g := &netlink.Geneve{LinkAttrs: la, Dport: GenevePort, FlowBased: true}
		if err := netlink.LinkAdd(g); err != nil {
			return fmt.Errorf("create geneve device: %w", err)
		}
		link, err = netlink.LinkByName(GeneveDevice)
		if err != nil {
			return fmt.Errorf("lookup geneve device: %w", err)
		}
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

// SetRemote installs (or replaces) a route to another node's pod CIDR.
func (m *Manager) SetRemote(podCIDR string, nodeIP net.IP) error {
	key, err := lpmKey(podCIDR)
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

// DelRemote removes a node's pod CIDR from the remotes map.
func (m *Manager) DelRemote(podCIDR string) error {
	key, err := lpmKey(podCIDR)
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

// lpmKey builds the LPM-trie key for a pod CIDR. The address is laid out in
// network byte order in memory (LPM matches MSB-first); on a little-endian host
// that means the uint32 field decodes the network bytes little-endian.
func lpmKey(cidr string) (overlayLpmKey, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return overlayLpmKey{}, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return overlayLpmKey{}, fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	return overlayLpmKey{
		Prefixlen: uint32(ones),
		Addr:      binary.LittleEndian.Uint32(ip4),
	}, nil
}

func isNotExist(err error) bool { return err != nil && os.IsNotExist(err) }

// WriteProcSys writes a /proc/sys value (path uses '/' separators, e.g.
// "net/ipv4/conf/eth0/proxy_arp").
func WriteProcSys(path, val string) error {
	return os.WriteFile(filepath.Join("/proc/sys", path), []byte(val), 0o644)
}
