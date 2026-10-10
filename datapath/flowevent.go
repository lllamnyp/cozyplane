// Copyright 2026 The cozyplane Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datapath

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// Flow observability (docs/observability.md): the Go mirror of struct
// flow_event in bpf/overlay.c. The record is 64 bytes, fixed layout; a unit
// test pins the size and every offset, so a drift from the C struct fails
// loudly instead of decoding garbage.

// FlowEventSize is sizeof(struct flow_event) in bpf/overlay.c.
const FlowEventSize = 64

// Verdicts — must match FE_V_* in bpf/overlay.c.
const (
	FlowVerdictAllow = 0
	FlowVerdictDeny  = 1
)

// Reasons — must match FR_* in bpf/overlay.c.
const (
	FlowReasonAllow      = 0
	FlowReasonSGIngress  = 1
	FlowReasonSGEgress   = 2
	FlowReasonSGNS       = 3
	FlowReasonNPIngress  = 4
	FlowReasonNPEgress   = 5
	FlowReasonHFIngress  = 6
	FlowReasonHFEgress   = 7
	FlowReasonIsolation  = 8
	FlowReasonSpoof      = 9
	FlowReasonLBClosed   = 10
	FlowReasonLBSrcRange = 11
	FlowReasonNoGateway  = 12
	flowReasonMax        = 15 // FR_MALFORMED/FR_INFRA reserved (v2)
)

// FlowReasonNames renders a reason for output and metric labels.
var FlowReasonNames = [flowReasonMax]string{
	"allow", "sg_ingress", "sg_egress", "sg_ns", "np_ingress", "np_egress",
	"hf_ingress", "hf_egress", "isolation", "spoof", "lb_closed",
	"lb_srcrange", "no_gateway", "malformed", "infra",
}

// Hooks — must match FE_* in bpf/overlay.c.
var FlowHookNames = [8]string{
	"from_pod", "to_pod", "from_overlay", "from_uplink",
	"lb_ingress", "lb_dsr", "hf_ingress", "hf_egress",
}

// Event flags — must match FE_F_* in bpf/overlay.c.
const (
	FlowFlagSYN = 0x1
	FlowFlagFwd = 0x2
	FlowFlagNS  = 0x4
)

// FlowNoDoor is the door byte of an event that crossed no north-south door.
const FlowNoDoor = 0xff

// FlowEvent is one decoded datapath flow record. Addresses are unwrapped from
// their NAT64 map form; ports are host-order numbers; TS is the raw
// bpf_ktime_get_ns (CLOCK_MONOTONIC) value — the reader anchors it to wall
// time, the datapath never does.
type FlowEvent struct {
	TS       uint64
	Src      net.IP
	Dst      net.IP
	SrcNet   uint32
	DstNet   uint32
	Sport    uint16
	Dport    uint16
	Proto    uint8
	Verdict  uint8
	Reason   uint8
	Hook     uint8
	Door     uint8
	Flags    uint8
	TCPFlags uint8 // raw TCP flags byte; set only on admitted TCP flows (per-flow)
	ICMPType uint8 // set only on admitted ICMP/ICMPv6 flows
	ICMPCode uint8
}

// TCP flag bits (RFC 793), for decoding TCPFlags into named series.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// TCPFlagNames renders the set flags as short names, in wire-bit order. Returns
// nil for a non-TCP or flag-less record. SYN+ACK collapses to "syn-ack" (the
// handshake reply) so the common case is one series, not two.
func (e *FlowEvent) TCPFlagNames() []string {
	if e.Proto != 6 || e.TCPFlags == 0 {
		return nil
	}
	var out []string
	if e.TCPFlags&tcpSYN != 0 && e.TCPFlags&tcpACK != 0 {
		out = append(out, "syn-ack")
	} else if e.TCPFlags&tcpSYN != 0 {
		out = append(out, "syn")
	} else if e.TCPFlags&tcpACK != 0 {
		out = append(out, "ack")
	}
	if e.TCPFlags&tcpFIN != 0 {
		out = append(out, "fin")
	}
	if e.TCPFlags&tcpRST != 0 {
		out = append(out, "rst")
	}
	if e.TCPFlags&tcpPSH != 0 {
		out = append(out, "psh")
	}
	return out
}

// Direction reports whether this flow is ingress or egress relative to the
// endpoint it concerns, derived from the reason (which encodes the gate's
// side) and, where the reason is side-neutral, from the observing hook. Kept
// in userspace so no datapath change is needed for the label.
func (e *FlowEvent) Direction() string {
	switch e.Reason {
	case FlowReasonSGIngress, FlowReasonNPIngress, FlowReasonHFIngress,
		FlowReasonSGNS, FlowReasonLBClosed, FlowReasonLBSrcRange:
		return "ingress"
	case FlowReasonSGEgress, FlowReasonNPEgress, FlowReasonHFEgress, FlowReasonNoGateway:
		return "egress"
	}
	// isolation / spoof / allow: the hook names the side.
	switch e.Hook {
	case 1, 4, 5: // to_pod, lb_ingress, lb_dsr — delivery into the destination
		return "ingress"
	default: // from_pod, from_overlay, from_uplink, hf_egress — leaving the source
		return "egress"
	}
}

// ReasonName renders the reason, tolerating values a newer datapath may emit.
func (e *FlowEvent) ReasonName() string {
	if int(e.Reason) < len(FlowReasonNames) {
		return FlowReasonNames[e.Reason]
	}
	return fmt.Sprintf("reason_%d", e.Reason)
}

// HookName renders the observing program's name.
func (e *FlowEvent) HookName() string {
	if int(e.Hook) < len(FlowHookNames) {
		return FlowHookNames[e.Hook]
	}
	return fmt.Sprintf("hook_%d", e.Hook)
}

// VerdictName renders the verdict.
func (e *FlowEvent) VerdictName() string {
	if e.Verdict == FlowVerdictAllow {
		return "allow"
	}
	return "deny"
}

// DoorName renders the north-south door, or "" when the flow crossed none.
func (e *FlowEvent) DoorName() string {
	if e.Door == FlowNoDoor {
		return ""
	}
	if int(e.Door) < len(NSDoorNames) {
		return NSDoorNames[e.Door]
	}
	return fmt.Sprintf("door_%d", e.Door)
}

// DecodeFlowEvent parses one raw ring-buffer record. Scalars the datapath
// wrote natively (ts, nets) decode little-endian (the bpfel target); the ports
// were stored as raw wire halfwords, so their bytes sit in network order.
func DecodeFlowEvent(b []byte) (FlowEvent, error) {
	if len(b) < FlowEventSize {
		return FlowEvent{}, fmt.Errorf("flow event: %d bytes, want %d", len(b), FlowEventSize)
	}
	var src, dst overlayAddr128
	copy(src.B[:], b[8:24])
	copy(dst.B[:], b[24:40])
	return FlowEvent{
		TS:       binary.LittleEndian.Uint64(b[0:8]),
		Src:      addr128ToIP(src),
		Dst:      addr128ToIP(dst),
		SrcNet:   binary.LittleEndian.Uint32(b[40:44]),
		DstNet:   binary.LittleEndian.Uint32(b[44:48]),
		Sport:    binary.BigEndian.Uint16(b[48:50]),
		Dport:    binary.BigEndian.Uint16(b[50:52]),
		Proto:    b[52],
		Verdict:  b[53],
		Reason:   b[54],
		Hook:     b[55],
		Door:     b[56],
		Flags:    b[57],
		TCPFlags: b[58],
		ICMPType: b[59],
		ICMPCode: b[60],
	}, nil
}

// SetFlowEnabled arms (or disarms) flow-event emission on this node. Off, the
// datapath pays one params lookup per emission site and nothing else.
func (m *Manager) SetFlowEnabled(on bool) error {
	return m.objs.Params.Put(cfgFlowEnabled, boolToU32(on))
}

// FlowEventsMap hands the pinned ring buffer to the agent's reader goroutine.
func (m *Manager) FlowEventsMap() *ebpf.Map {
	return m.objs.FlowEvents
}

// FlowLostCount sums the per-CPU count of events dropped by a full ring.
func (m *Manager) FlowLostCount() (uint64, error) {
	var per []uint64
	zero := uint32(0)
	if err := m.objs.FlowLost.Lookup(zero, &per); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range per {
		total += v
	}
	return total, nil
}
