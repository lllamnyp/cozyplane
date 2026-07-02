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
	"net"
	"testing"
)

// The eBPF bridge keys the `bridges` map on the fabric IP and stores the VPC IP,
// both read straight out of the packet by the datapath (network byte order).
// The Go side must marshal them to those same network-order bytes, whatever the
// host endianness — the same on-wire contract the LPM/local keys are held to.
func TestBridgeKeyIsNetworkOrder(t *testing.T) {
	fabric := binary.LittleEndian.Uint32(net.ParseIP("10.244.2.91").To4())
	vpc := binary.LittleEndian.Uint32(net.ParseIP("10.66.0.2").To4())

	var fb, vb [4]byte
	binary.NativeEndian.PutUint32(fb[:], fabric)
	binary.NativeEndian.PutUint32(vb[:], vpc)

	if fb != ([4]byte{10, 244, 2, 91}) {
		t.Errorf("fabric key marshals to %v, want network order 10.244.2.91", fb)
	}
	if vb != ([4]byte{10, 66, 0, 2}) {
		t.Errorf("vpc value marshals to %v, want network order 10.66.0.2", vb)
	}
}
