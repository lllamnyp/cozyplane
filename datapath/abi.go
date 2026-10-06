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
	"math"
	"net"
)

// Ifindex validates the positive signed-32-bit kernel ABI before map access.
func Ifindex(index int) (uint32, error) {
	if index < 1 || index > math.MaxInt32 {
		return 0, fmt.Errorf("invalid interface index %d", index)
	}
	return uint32(index), nil
}

// cidrAddressPrefix rejects malformed/family-mismatched masks before any map
// changes. IPv4 keys use the NAT64 /96 prefix, matching addr128 and eBPF.
func cidrAddressPrefix(cidr *net.IPNet) (overlayAddr128, uint32, error) {
	if cidr == nil {
		return overlayAddr128{}, 0, fmt.Errorf("missing CIDR")
	}
	ones, bits := cidr.Mask.Size()
	if ones < 0 || ones > 128 || (bits != 32 && bits != 128) || ones > bits {
		return overlayAddr128{}, 0, fmt.Errorf("invalid CIDR mask")
	}
	v4 := cidr.IP.To4() != nil
	if (v4 && bits != 32) || (!v4 && (bits != 128 || cidr.IP.To16() == nil)) {
		return overlayAddr128{}, 0, fmt.Errorf("CIDR mask does not match address family")
	}
	a, err := addr128(cidr.IP.Mask(cidr.Mask))
	prefix := uint32(ones)
	if v4 {
		prefix += 96
	}
	return a, prefix, err
}
