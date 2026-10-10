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

package sdn

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/lllamnyp/cozyplane/pkg/netid"
)

// Claim names. A Port ("v<vni>.<escaped-ip>") and a ServiceVIP
// ("sv<vni>.<escaped-ip>") are cluster-scoped and named by the address they
// hold: the name IS the allocation claim. etcd name uniqueness serializes
// same-kind allocators, and the aggregated registry rejects a create whose
// twin name (the same <vni>.<ip> under the other kind's prefix) exists.
// That cross-kind GET is not atomic; controllers also repair concurrent claims.

// ClaimPrefixPort and ClaimPrefixServiceVIP are the kind discriminators in
// front of the shared <vni>.<escaped-ip> claim.
const (
	ClaimPrefixPort       = "v"
	ClaimPrefixServiceVIP = "sv"
)

// EscapeIP retains valid legacy names. Edge-compressed IPv6 addresses need an
// alternate encoding because DNS labels cannot start/end with '-'. The x prefix
// is disjoint from hexadecimal IPv6 and numeric IPv4 legacy suffixes. Callers
// validate canonical address strings; invalid addresses remain invalid names.
func EscapeIP(ip string) string {
	escaped := strings.NewReplacer(".", "-", ":", "-").Replace(ip)
	if strings.HasPrefix(escaped, "-") || strings.HasSuffix(escaped, "-") {
		if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() && addr.Zone() == "" {
			bytes := addr.As16()
			return "x" + hex.EncodeToString(bytes[:])
		}
	}
	return escaped
}

// PortName is the claim name of a Port on ip in the VPC with the given VNI.
func PortName(vni int32, ip string) string {
	return fmt.Sprintf("%s%d.%s", ClaimPrefixPort, vni, EscapeIP(ip))
}

// ServiceVIPName is the claim name of a ServiceVIP on ip in the VPC with the
// given VNI. It mirrors PortName under the other prefix.
func ServiceVIPName(vni int32, ip string) string {
	return fmt.Sprintf("%s%d.%s", ClaimPrefixServiceVIP, vni, EscapeIP(ip))
}

// ParseClaim splits a claim name of the given prefix into its VNI and
// escaped-address halves. ok is false when the name does not have the
// prefix+"<vni>.<escaped-ip>" shape (VNI 0 and empty halves included).
func ParseClaim(prefix, name string) (vni int32, escapedIP string, ok bool) {
	rest, found := strings.CutPrefix(name, prefix)
	if !found {
		return 0, "", false
	}
	vniStr, esc, found := strings.Cut(rest, ".")
	if !found || vniStr == "" || esc == "" {
		return 0, "", false
	}
	n, err := strconv.ParseInt(vniStr, 10, 32)
	if err != nil || n < int64(netid.FirstVNI) || n > int64(netid.LastVNI) {
		return 0, "", false
	}
	return int32(n), esc, true
}
