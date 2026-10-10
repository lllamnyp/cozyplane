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
	"testing"
)

// The decode offsets below ARE the ABI contract with struct flow_event in
// bpf/overlay.c (64 bytes: ts@0, src@8, dst@24, srcnet@40, dstnet@44,
// sport@48, dport@50, then proto/verdict/reason/hook/door/flags one byte each
// from 52, and 6 explicit pad bytes). These tests lock the layout so a drift
// on either side fails here instead of decoding garbage on a live node.

func sampleFlowEventBytes(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, FlowEventSize)
	binary.LittleEndian.PutUint64(b[0:8], 1234567890) // ts, native (bpfel)
	src, err := addr128Str("10.1.0.5")                // NAT64-mapped v4
	if err != nil {
		t.Fatal(err)
	}
	dst, err := addr128Str("fd00::1:2") // native v6
	if err != nil {
		t.Fatal(err)
	}
	copy(b[8:24], src.B[:])
	copy(b[24:40], dst.B[:])
	binary.LittleEndian.PutUint32(b[40:44], 100) // srcnet, native
	binary.LittleEndian.PutUint32(b[44:48], 101) // dstnet, native
	// Ports were stored as raw wire halfwords: network order on the wire.
	binary.BigEndian.PutUint16(b[48:50], 40000) // sport
	binary.BigEndian.PutUint16(b[50:52], 443)   // dport
	b[52] = 6                                   // proto TCP
	b[53] = FlowVerdictDeny
	b[54] = FlowReasonIsolation
	b[55] = 1 // to_pod
	b[56] = FlowNoDoor
	b[57] = FlowFlagFwd
	b[58] = tcpSYN | tcpACK // tcp_flags
	b[59] = 8               // icmp_type (ignored for TCP, but pins the offset)
	b[60] = 0               // icmp_code
	return b
}

func TestDecodeFlowEventLayout(t *testing.T) {
	e, err := DecodeFlowEvent(sampleFlowEventBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	if e.TS != 1234567890 {
		t.Errorf("TS = %d", e.TS)
	}
	if got := e.Src.String(); got != "10.1.0.5" {
		t.Errorf("Src = %q (NAT64 unwrap)", got)
	}
	if got := e.Dst.String(); got != "fd00::1:2" {
		t.Errorf("Dst = %q", got)
	}
	if e.SrcNet != 100 || e.DstNet != 101 {
		t.Errorf("nets = %d/%d", e.SrcNet, e.DstNet)
	}
	if e.Sport != 40000 || e.Dport != 443 {
		t.Errorf("ports = %d/%d", e.Sport, e.Dport)
	}
	if e.Proto != 6 || e.Verdict != FlowVerdictDeny || e.Reason != FlowReasonIsolation {
		t.Errorf("proto/verdict/reason = %d/%d/%d", e.Proto, e.Verdict, e.Reason)
	}
	if e.HookName() != "to_pod" || e.DoorName() != "" || e.Flags != FlowFlagFwd {
		t.Errorf("hook/door/flags = %q/%q/%d", e.HookName(), e.DoorName(), e.Flags)
	}
	if e.ReasonName() != "isolation" || e.VerdictName() != "deny" {
		t.Errorf("names = %q/%q", e.ReasonName(), e.VerdictName())
	}
	if e.TCPFlags != (tcpSYN|tcpACK) || e.ICMPType != 8 || e.ICMPCode != 0 {
		t.Errorf("l4 = flags %d, icmp %d/%d", e.TCPFlags, e.ICMPType, e.ICMPCode)
	}
	// TCP proto → SYN+ACK collapses to one series; isolation on to_pod is ingress.
	if got := e.TCPFlagNames(); len(got) != 1 || got[0] != "syn-ack" {
		t.Errorf("TCPFlagNames = %v", got)
	}
	if e.Direction() != "ingress" {
		t.Errorf("Direction = %q, want ingress (to_pod)", e.Direction())
	}
}

func TestFlowDirectionDerivation(t *testing.T) {
	cases := []struct {
		reason, hook uint8
		want         string
	}{
		{FlowReasonSGEgress, 0, "egress"},
		{FlowReasonNPIngress, 1, "ingress"},
		{FlowReasonHFEgress, 6, "egress"},
		{FlowReasonNoGateway, 0, "egress"},
		{FlowReasonSpoof, 0, "egress"},  // from_pod
		{FlowReasonAllow, 1, "ingress"}, // to_pod delivery
		{FlowReasonLBClosed, 4, "ingress"},
	}
	for _, c := range cases {
		e := FlowEvent{Reason: c.reason, Hook: c.hook}
		if got := e.Direction(); got != c.want {
			t.Errorf("reason %d hook %d: Direction = %q, want %q", c.reason, c.hook, got, c.want)
		}
	}
}

func TestDecodeFlowEventShortBuffer(t *testing.T) {
	if _, err := DecodeFlowEvent(make([]byte, FlowEventSize-1)); err == nil {
		t.Fatal("short buffer must not decode")
	}
}

// Unknown values from a newer datapath render as numbered placeholders, never
// a panic or an out-of-range index.
func TestFlowEventUnknownValuesRender(t *testing.T) {
	e := FlowEvent{Reason: 200, Hook: 200, Door: 200}
	if e.ReasonName() != "reason_200" || e.HookName() != "hook_200" || e.DoorName() != "door_200" {
		t.Errorf("got %q/%q/%q", e.ReasonName(), e.HookName(), e.DoorName())
	}
}
