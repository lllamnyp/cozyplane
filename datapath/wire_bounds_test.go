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
	"net"
	"testing"
)

func TestRACannotAdvertiseTruncatedOrInvalidIPv6MTU(t *testing.T) {
	for _, mtu := range []int{-1, 0, 1279, 65536} {
		if got := raFrame(net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.ParseIP("fd00::2"), mtu, nil); len(got) != 0 {
			t.Errorf("invalid MTU %d produced RA", mtu)
		}
	}
}

func TestDHCPv6OptionCannotTruncateWireLength(t *testing.T) {
	before := []byte{1, 2}
	if got := appendOpt(before, 1, make([]byte, 65536)); len(got) != len(before) {
		t.Errorf("oversize DHCP option emitted %d bytes", len(got))
	}
	if got := appendOpt(nil, 1, make([]byte, 65535)); len(got) != 65539 {
		t.Errorf("valid largest DHCP option dropped: %d", len(got))
	}
}
