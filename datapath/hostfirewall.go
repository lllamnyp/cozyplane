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
	"fmt"
	"net"
)

// Host firewall (docs/host-firewall.md). The agent compiles the HostFirewalls
// selecting THIS node into hf_allow ({proto, port} + source-CIDR LPM rows)
// and arms enforcement with CFG_HF_ENABLED; hf_self holds the node's own
// addresses (the same set fed to np_nodes for self). All syncs are
// full-state diffs against the pinned maps.

// HFAllow is one compiled rule row: source range -> {proto, port} with
// Allow=false being an `except` (a longer-prefix mask of its rule's allow).
// Port is host order (stored network order); 0 = any port. Port ranges are
// expanded to per-port rows by the compiler, not here — the address is the
// LPM tail, so the port cannot be a suffix like np_allow's.
type HFAllow struct {
	Proto uint8
	Port  uint16
	CIDR  *net.IPNet
	Allow bool
}

// SyncHFAllows makes hf_allow exactly `entries` (full-state diff). A v4
// range lives in NAT64 form (/N -> /(96+N)); the key prefix is the 32 fixed
// bits (proto+pad+port) plus that. At an identical key an allow from any
// policy wins (policies union; the np_cidr rule).
func (m *Manager) SyncHFAllows(entries []HFAllow) error {
	want := map[overlayHfAllowKey]uint8{}
	for _, e := range entries {
		if e.CIDR == nil {
			continue
		}
		ones, _ := e.CIDR.Mask.Size()
		ip := e.CIDR.IP
		var bits uint32
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 96 + uint32(ones)
		} else {
			bits = uint32(ones)
		}
		a, err := addr128(ip)
		if err != nil {
			return fmt.Errorf("hf_allow range %q: %w", e.CIDR, err)
		}
		key := overlayHfAllowKey{
			Prefixlen: 32 + bits,
			Proto:     e.Proto,
			Port:      htons(e.Port),
			Src:       a,
		}
		var v uint8
		if e.Allow {
			v = 1
		}
		if prev, ok := want[key]; ok && prev == 1 {
			continue
		}
		want[key] = v
	}
	return syncMap(m.objs.HfAllow, want)
}

// SyncHFSelf makes hf_self exactly `ips` — the node's own addresses, which
// is what "host-destined" means to hf_ingress.
func (m *Manager) SyncHFSelf(ips []net.IP) error {
	want := map[overlayAddr128]uint8{}
	for _, ip := range ips {
		a, err := addr128(ip)
		if err != nil {
			return fmt.Errorf("hf self IP: %w", err)
		}
		want[a] = 1
	}
	return syncMap(m.objs.HfSelf, want)
}

// SetHFEnabled arms (or disarms) host-firewall enforcement. The caller
// orders this against the rule sync — set after syncing on enable, clear
// before wiping on disable — so there is no fail-open window.
func (m *Manager) SetHFEnabled(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return m.objs.Params.Put(cfgHFEnabled, v)
}

// HFDrops returns the host-firewall drop total (summed across CPUs).
func (m *Manager) HFDrops() (uint64, error) {
	var perCPU []uint64
	if err := m.objs.HfDrops.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("lookup hf_drops: %w", err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}
