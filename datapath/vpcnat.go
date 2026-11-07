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
	"math/bits"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	localsdnv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
)

// NATGatewayBlocks is how many active blocks one node may hold per NAT gateway
// (NATGW_BLOCKS in bpf/overlay.c).
const NATGatewayBlocks = 8

// NATGateway is one NAT gateway as this node programs it into nat_gw.
type NATGateway struct {
	V4, V6    string // addresses; empty = none
	Net       uint32 // the VPC
	BlockSize uint16
	Blocks    []uint16 // this node's ACTIVE blocks, at most NATGatewayBlocks
}

// SyncNATGateways makes nat_gw and nat_addrs exactly `want` (keyed by NAT
// gateway id). Every node programs every NAT gateway: nat_addrs so any node can
// recognize a reply, nat_gw so the datapath can tell "no block here" from "no
// address".
func (m *Manager) SyncNATGateways(want map[uint32]NATGateway) error {
	gws := map[uint32]overlayNatGw{}
	addrs := map[overlayAddr128]overlayNatAddrVal{}
	for id, g := range want {
		if len(g.Blocks) > NATGatewayBlocks {
			return fmt.Errorf("NAT gateway %d: %d active blocks, at most %d", id, len(g.Blocks), NATGatewayBlocks)
		}
		v := overlayNatGw{Net: g.Net, BlockSize: g.BlockSize, Nblocks: uint8(len(g.Blocks))}
		copy(v.Blocks[:], g.Blocks)
		for _, a := range []struct {
			s   string
			dst *overlayAddr128
		}{{g.V4, &v.Ip}, {g.V6, &v.Ip6}} {
			if a.s == "" {
				continue
			}
			ip, err := addr128Str(a.s)
			if err != nil {
				return fmt.Errorf("NAT gateway %d: %w", id, err)
			}
			*a.dst = ip
			addrs[ip] = overlayNatAddrVal{Natgw: id, Net: g.Net, BlockSize: g.BlockSize}
		}
		gws[id] = v
	}
	if err := syncMap(m.objs.NatGw, gws); err != nil {
		return fmt.Errorf("sync nat_gw: %w", err)
	}
	if err := syncMap(m.objs.NatAddrs, addrs); err != nil {
		return fmt.Errorf("sync nat_addrs: %w", err)
	}
	return nil
}

// NATBlock identifies one block of one NAT gateway.
type NATBlock struct {
	NATGateway uint32
	Block      uint16
}

// SyncNATBlockOwners makes nat_blk_owner exactly `want`: every leased block of
// every NAT gateway, to the v4 Geneve endpoint of the node holding it.
func (m *Manager) SyncNATBlockOwners(want map[NATBlock]net.IP) error {
	w := map[overlayNatBlkKey]uint32{}
	for b, ip := range want {
		v4 := ip.To4()
		if v4 == nil {
			return fmt.Errorf("NAT block %d/%d: node IP %s is not v4", b.NATGateway, b.Block, ip)
		}
		// Host order, as `remotes` stores node IPs (what encap() wants).
		w[overlayNatBlkKey{Natgw: b.NATGateway, Block: b.Block}] = binary.BigEndian.Uint32(v4)
	}
	return syncMap(m.objs.NatBlkOwner, w)
}

// SetNATFlowQuota sets the live NAT flows one VPC may hold on this node; 0
// removes the limit.
func (m *Manager) SetNATFlowQuota(n uint32) error {
	return m.objs.Params.Put(cfgNATVPCQuota, n)
}

// NATTimeouts are the idle timeouts after which the sweep deletes a flow
// (docs/vpc-egress.md §4.2).
type NATTimeouts struct {
	TCPEstablished, TCPTransitory, UDP, ICMP time.Duration
}

// DefaultNATTimeouts are the RFC minimums.
var DefaultNATTimeouts = NATTimeouts{
	TCPEstablished: 7440 * time.Second, // RFC 5382
	TCPTransitory:  240 * time.Second,  // RFC 5382
	UDP:            300 * time.Second,  // RFC 4787
	ICMP:           60 * time.Second,   // RFC 5508
}

const (
	natFlagReply = 1 // NAT_F_REPLY
	natFlagFin   = 2 // NAT_F_FIN
)

func (t NATTimeouts) of(proto uint8, flags uint8) time.Duration {
	switch proto {
	case unix.IPPROTO_TCP:
		if flags&natFlagReply != 0 && flags&natFlagFin == 0 {
			return t.TCPEstablished
		}
		return t.TCPTransitory
	case unix.IPPROTO_UDP:
		return t.UDP
	default:
		return t.ICMP
	}
}

// NATSweep is what one sweep found: the live flows after expiry.
type NATSweep struct {
	Expired int
	// Flows counts live flows per VPC (net) and per NAT gateway id.
	FlowsByNet        map[uint32]uint32
	FlowsByNATGateway map[uint32]uint32
	// LiveBlocks is the set of blocks that still hold a live flow.
	LiveBlocks map[NATBlock]bool
}

// monotonicNow is CLOCK_MONOTONIC, the clock bpf_ktime_get_ns reads.
func monotonicNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

// SweepNAT deletes expired flows from nat_rev and nat_fwd (both halves, always
// together) and rewrites nat_flows from what is left. blockSize maps a NAT
// gateway id to its block size, for LiveBlocks.
func (m *Manager) SweepNAT(t NATTimeouts, blockSize map[uint32]int) (NATSweep, error) {
	now, err := monotonicNow()
	if err != nil {
		return NATSweep{}, err
	}
	out := NATSweep{
		FlowsByNet:        map[uint32]uint32{},
		FlowsByNATGateway: map[uint32]uint32{},
		LiveBlocks:        map[NATBlock]bool{},
	}
	type stale struct {
		rk overlayNatRevKey
		fk overlayNatFwdKey
	}
	var dead []stale
	var k overlayNatRevKey
	var v overlayNatRevVal
	it := m.objs.NatRev.Iterate()
	for it.Next(&k, &v) {
		idle := time.Duration(0)
		if now > v.LastSeen {
			idle = time.Duration(now - v.LastSeen)
		}
		if idle > t.of(k.Proto, v.Flags) {
			dead = append(dead, stale{rk: k, fk: overlayNatFwdKey{
				Proto: k.Proto, Net: v.Net,
				PodIp: v.PodIp, RemoteIp: k.RemoteIp,
				PodPort: v.PodPort, RemotePort: k.RemotePort,
			}})
			continue
		}
		out.FlowsByNet[v.Net]++
		out.FlowsByNATGateway[k.Natgw]++
		port := bits.ReverseBytes16(k.Port) // network order in the key
		if b := localsdnv1alpha1.NATBlockOf(port, blockSize[k.Natgw]); b >= 0 {
			out.LiveBlocks[NATBlock{NATGateway: k.Natgw, Block: uint16(b)}] = true
		}
	}
	if err := it.Err(); err != nil {
		return out, fmt.Errorf("iterate nat_rev: %w", err)
	}
	for _, d := range dead {
		// nat_fwd first: an egress hit must never find a fwd entry whose rev
		// is gone and the port already reallocated.
		var fv overlayNatFwdVal
		if err := m.objs.NatFwd.Lookup(&d.fk, &fv); err == nil && fv.Natgw == d.rk.Natgw && fv.Port == d.rk.Port {
			if err := m.objs.NatFwd.Delete(&d.fk); err != nil && !isNotExist(err) {
				return out, err
			}
		}
		if err := m.objs.NatRev.Delete(&d.rk); err != nil && !isNotExist(err) {
			return out, err
		}
		out.Expired++
	}
	if err := syncMap(m.objs.NatFlows, out.FlowsByNet); err != nil {
		return out, fmt.Errorf("sync nat_flows: %w", err)
	}
	return out, nil
}

// NAT stat counters (NATS_* in bpf/overlay.c), by the reason names of
// docs/vpc-egress.md §4.6.
var natStatNames = map[uint32]string{
	0: "no_block",
	1: "exhausted",
	2: "quota",
	3: "table_full",
	4: "no_address",
	5: "deep",
	6: "unsupported",
}

// NATStats returns nat_stats as {NAT gateway id: {counter name: count}}.
func (m *Manager) NATStats() (map[uint32]map[string]uint64, error) {
	out := map[uint32]map[string]uint64{}
	var k overlayNatStatKey
	var v uint64
	it := m.objs.NatStats.Iterate()
	for it.Next(&k, &v) {
		name, ok := natStatNames[k.Counter]
		if !ok {
			continue
		}
		if out[k.Natgw] == nil {
			out[k.Natgw] = map[string]uint64{}
		}
		out[k.Natgw][name] = v
	}
	return out, it.Err()
}

// PruneNATStats drops the counters of NAT gateways not in `keep`, so a deleted
// NAT gateway's id can be reused without inheriting its counts.
func (m *Manager) PruneNATStats(keep map[uint32]bool) error {
	var stale []overlayNatStatKey
	var k overlayNatStatKey
	var v uint64
	it := m.objs.NatStats.Iterate()
	for it.Next(&k, &v) {
		if !keep[k.Natgw] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range stale {
		if err := m.objs.NatStats.Delete(&stale[i]); err != nil && !isNotExist(err) {
			return err
		}
	}
	return nil
}

// ClearLegacyVPCNAT empties vpc_nat, nat_of and the shard-keyed nat_owner, which
// the datapath no longer reads (docs/vpc-egress.md §5.1). Their pins stay.
func (m *Manager) ClearLegacyVPCNAT() error {
	for _, mp := range []*ebpf.Map{m.objs.VpcNat, m.objs.NatOf, m.objs.NatOwner} {
		if err := clearMap(mp); err != nil {
			return err
		}
	}
	return nil
}

// clearMap deletes every entry of a hash map.
func clearMap(mp *ebpf.Map) error {
	key := make([]byte, mp.KeySize())
	val := make([]byte, mp.ValueSize())
	var keys [][]byte
	it := mp.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, append([]byte(nil), key...))
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := mp.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}
