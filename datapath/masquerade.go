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

	"github.com/coreos/go-iptables/iptables"
)

// SyncMasqSources makes the masq_srcs map exactly `cidrs` — the source
// networks (the cluster pod supernet) whose off-cluster egress the eBPF
// datapath masquerades to the node address (#10). Pruning matters on a mode
// switch: --masquerade=iptables must not leave stale bpf-SNAT sources behind.
func (m *Manager) SyncMasqSources(cidrs []string) error {
	want := map[overlayLpmKey]bool{}
	for _, c := range cidrs {
		key, err := lpmKey(0, c)
		if err != nil {
			return err
		}
		want[key] = true
	}
	var key overlayLpmKey
	var val uint8
	var stale []overlayLpmKey
	it := m.objs.MasqSrcs.Iterate()
	for it.Next(&key, &val) {
		if !want[key] {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate masq_srcs: %w", err)
	}
	for _, k := range stale {
		if err := m.objs.MasqSrcs.Delete(&k); err != nil && !isNotExist(err) {
			return err
		}
	}
	var one uint8 = 1
	for k := range want {
		if err := m.objs.MasqSrcs.Put(&k, one); err != nil {
			return fmt.Errorf("set masq source: %w", err)
		}
	}
	return nil
}

// SetNodeIP publishes the node's v4 address. The bpf masquerade SNATs to it
// (though its gate is masq_srcs — empty sources disable it regardless) and
// the DNS steer re-addresses VPC pods' resolver queries to it. Stored as the
// raw network-order bytes read natively, matching how the datapath compares
// it against header addresses.
func (m *Manager) SetNodeIP(ip net.IP) error {
	var v uint32
	if ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("node IP %q is not IPv4", ip)
		}
		v = binary.NativeEndian.Uint32(ip4)
	}
	if err := m.objs.Params.Put(cfgNodeIP, v); err != nil {
		return fmt.Errorf("set node IP: %w", err)
	}
	return nil
}

// SetNodeIP6 publishes the node's v6 address for the v6 bpf masquerade (nil
// clears it, disabling the v6 masq hooks — e.g. on a v4-only node).
func (m *Manager) SetNodeIP6(ip net.IP) error {
	var v overlayAddr128
	if ip != nil {
		a, err := addr128(ip)
		if err != nil {
			return err
		}
		v = a
	}
	if err := m.objs.NodeIp6.Put(uint32(0), &v); err != nil {
		return fmt.Errorf("set node IPv6: %w", err)
	}
	return nil
}

// RemoveMasquerade tears down the iptables masquerade (chain + jump) — used
// when --masquerade is not "iptables" so a mode switch doesn't double-NAT.
// Best-effort by nature: on a netfilter-less node there is nothing to remove.
func RemoveMasquerade(clusterCIDR string) {
	ipt, err := iptables.New()
	if err != nil {
		return
	}
	spec := []string{"-s", clusterCIDR, "!", "-d", clusterCIDR, "-j", masqChain}
	_ = ipt.DeleteIfExists("nat", "POSTROUTING", spec...)
	_ = ipt.ClearAndDeleteChain("nat", masqChain)
}
