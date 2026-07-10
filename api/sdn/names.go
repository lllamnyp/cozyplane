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
	"fmt"
	"strconv"
	"strings"
)

// Claim names. A Port ("v<vni>.<escaped-ip>") and a ServiceVIP
// ("sv<vni>.<escaped-ip>") are cluster-scoped and named by the address they
// hold: the name IS the allocation claim. etcd name uniqueness serializes
// same-kind allocators, and the aggregated registry rejects a create whose
// twin name (the same <vni>.<ip> under the other kind's prefix) exists, so
// the two kinds can never hold the same {VNI, IP}.

// ClaimPrefixPort and ClaimPrefixServiceVIP are the kind discriminators in
// front of the shared <vni>.<escaped-ip> claim.
const (
	ClaimPrefixPort       = "v"
	ClaimPrefixServiceVIP = "sv"
)

// EscapeIP maps an address to its object-name form. Both the v4 dot and the
// v6 colon are invalid in a Kubernetes object name, so both become '-'
// (10.0.0.2 -> 10-0-0-2, fd00:10::2 -> fd00-10--2). The escaping is not
// reversible and need not be: the address is carried in the spec, the name
// only has to be unique per VNI — which it is for addresses in canonical
// form.
func EscapeIP(ip string) string {
	return strings.NewReplacer(".", "-", ":", "-").Replace(ip)
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
	if err != nil || n <= 0 {
		return 0, "", false
	}
	return int32(n), esc, true
}
