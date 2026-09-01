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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// Multi-attach: several VPCs on one pod (docs/multi-attach.md).
//
// A pod that merely LIVES in a network wants one attachment, and the original
// single-VPC annotation still says that in the fewest characters. A pod whose job
// IS the boundary between two — a tenant firewall, a router, an NFV appliance —
// needs a list, and needs to say more about each entry than a name.

// maxAttachments is bounded by the host veth name, not by taste. IFNAMSIZ leaves
// 15 usable characters; "cph" plus 11 of the container ID already uses 14, so the
// index gets the one that is left. Ten attachments is well past any use we have,
// and the alternative — a shorter container-ID slice — trades a real property
// (names that stay distinct across concurrent sandboxes) for a hypothetical one.
const maxAttachments = 10

// hostVethPrefix is the host-side veth prefix. It must stay in step with
// datapath's podVethPrefix (unexported there), which the agent's rebuild scan and
// the masquerade RETURN rules both match on. An indexed name keeps the prefix, so
// both continue to recognise it.
const hostVethPrefix = "cph"

// attachment is one entry of the pod's requested network list, after defaulting.
type attachment struct {
	// Index is the entry's position, and it is meaningful: entry 0 is the pod's
	// PRIMARY attachment — it carries the fabric bridge (so it is what
	// status.podIP resolves to and what kubelet probes reach) and it alone gets
	// the default route.
	Index int
	// VPCNamespace is the VPC's owner namespace, defaulted to the pod's.
	VPCNamespace string
	VPCName      string
	// IP, when set, is the tenant address to pin instead of letting IPAM walk
	// the VPC CIDR. MAC likewise pins the interface MAC.
	IP  net.IP
	MAC net.HardwareAddr
	// IfName is the interface name inside the pod (defaults to eth<Index>).
	IfName string
}

// Primary reports whether this attachment owns the pod's fabric handle, its
// default route and its status.podIP.
func (a attachment) Primary() bool { return a.Index == 0 }

// netEntry is the wire form of one entry in the networks annotation.
type netEntry struct {
	VPC  string `json:"vpc"`
	IP   string `json:"ip,omitempty"`
	MAC  string `json:"mac,omitempty"`
	Name string `json:"name,omitempty"`
}

// parseAttachments turns the pod's annotations into the ordered attachment list.
// It returns nil (no error) when the pod requests no VPC at all — the
// default-network case.
//
// Carrying BOTH annotations is an error rather than a precedence rule. A pod that
// says "one VPC" and "these VPCs" is a pod whose author disagrees with themselves,
// and guessing which half they meant is how a workload ends up attached to a
// network nobody asked for.
func parseAttachments(vpcAnno, networksAnno, podNS string) ([]attachment, error) {
	if vpcAnno != "" && networksAnno != "" {
		return nil, fmt.Errorf("%s and %s are mutually exclusive: use one or the other",
			vpcAnnotation, networksAnnotation)
	}

	if vpcAnno != "" {
		ns, name := parseVPCRef(vpcAnno, podNS)
		return []attachment{{Index: 0, VPCNamespace: ns, VPCName: name, IfName: contVethName}}, nil
	}
	if networksAnno == "" {
		return nil, nil
	}

	var entries []netEntry
	if err := json.Unmarshal([]byte(networksAnno), &entries); err != nil {
		return nil, fmt.Errorf("%s is not a JSON list of network entries: %w", networksAnnotation, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s is an empty list: omit it to stay on the default network", networksAnnotation)
	}
	if len(entries) > maxAttachments {
		return nil, fmt.Errorf("%s asks for %d attachments; the limit is %d (host interface names)",
			networksAnnotation, len(entries), maxAttachments)
	}

	out := make([]attachment, 0, len(entries))
	seenName := map[string]bool{}
	for i, e := range entries {
		if e.VPC == "" {
			return nil, fmt.Errorf("%s entry %d has no vpc", networksAnnotation, i)
		}
		ns, name := parseVPCRef(e.VPC, podNS)
		a := attachment{Index: i, VPCNamespace: ns, VPCName: name, IfName: e.Name}
		if a.IfName == "" {
			a.IfName = defaultIfName(i)
		}
		// Two entries on one interface name is not a preference to resolve: the
		// second would silently replace the first inside the pod.
		if seenName[a.IfName] {
			return nil, fmt.Errorf("%s: interface name %q requested twice", networksAnnotation, a.IfName)
		}
		seenName[a.IfName] = true

		if e.IP != "" {
			ip := net.ParseIP(e.IP)
			// Canonical form, like Port.spec.ip: the Port name IS the address
			// claim, so a non-canonical spelling would claim a different name
			// for the same address.
			if ip == nil || ip.String() != e.IP {
				return nil, fmt.Errorf("%s entry %d: ip %q is not an IP address in canonical form",
					networksAnnotation, i, e.IP)
			}
			a.IP = ip
		}
		if e.MAC != "" {
			mac, err := net.ParseMAC(e.MAC)
			if err != nil {
				return nil, fmt.Errorf("%s entry %d: mac %q: %w", networksAnnotation, i, e.MAC, err)
			}
			if len(mac) != 6 {
				return nil, fmt.Errorf("%s entry %d: mac %q is not a 6-byte address", networksAnnotation, i, e.MAC)
			}
			a.MAC = mac
		}
		out = append(out, a)
	}
	return out, nil
}

// defaultIfName is eth0, eth1, … — the names a guest expects to find.
func defaultIfName(index int) string {
	if index == 0 {
		return contVethName
	}
	return "eth" + strconv.Itoa(index)
}

// hostVethNameForIndex names the host side of attachment `index`.
//
// Index 0 keeps hostVethNameFor's exact output, unchanged. That is not tidiness:
// pods created before multi-attach existed have host veths under the old name and
// a DEL that reconstructs a different one would leave their map entries and links
// behind. Only the additional interfaces take the indexed form.
func hostVethNameForIndex(containerID string, index int) string {
	if index == 0 {
		return hostVethNameFor(containerID)
	}
	id := containerID
	if len(id) > 10 {
		id = id[:10]
	}
	return hostVethPrefix + strconv.Itoa(index) + id
}
