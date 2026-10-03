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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
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

// maxDelegates bounds legacy netN Multus interface names by the one character
// available in their backwards-compatible host-veth name: net0..net25.
const maxDelegates = 25

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
	// Delegated marks an attachment realized because MULTUS called us, one
	// invocation per NetworkAttachmentDefinition, rather than because the pod's
	// annotation asked for it. A delegated attachment is never the primary: the
	// primary is the pod network, and a VM has exactly one
	// (docs/kubevirt-multi-nic.md).
	Delegated bool
}

// Primary reports whether this attachment owns the pod's fabric handle, its
// default route and its status.podIP.
//
// A delegated attachment never is, whatever its index: Multus invokes the
// delegate once per secondary NIC, and the pod's one fabric handle belongs to
// the pod network that KubeVirt attached first.
func (a attachment) Primary() bool { return !a.Delegated && a.Index == 0 }

// NICID identifies this attachment among a VM's NICs, for the persistent Port
// that pins its {VPC IP, MAC} across a migration (LabelVMNIC).
//
// The two attachment paths use disjoint value spaces on purpose. The annotation
// path numbers its entries; a delegated NIC uses its Multus interface name,
// which is unique within the pod by construction. A decimal index and a name
// beginning "net" can never be equal, so the two paths cannot select each
// other's Port even for two NICs of one VM on one VPC.
func (a attachment) NICID() string {
	if a.Delegated {
		return a.IfName
	}
	return strconv.Itoa(a.Index)
}

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
		// A netN entry describes a MULTUS-delegated NIC (docs/kubevirt-multi-nic.md).
		// It is not a leg this invocation builds — Multus calls us separately for
		// it — it is only where that NIC's ip/mac are pinned. Skip it here, but
		// still take its name so a duplicate is caught.
		if isDelegatedIfName(e.Name) {
			if seenName[e.Name] {
				return nil, fmt.Errorf("%s: interface name %q requested twice", networksAnnotation, e.Name)
			}
			seenName[e.Name] = true
			continue
		}
		// Indices run over the SURVIVING entries, not over the raw list: index 0
		// must exist and must be the attachment carrying the fabric handle, so a
		// delegated entry appearing first cannot shift it away.
		idx := len(out)
		ns, name := parseVPCRef(e.VPC, podNS)
		a := attachment{Index: idx, VPCNamespace: ns, VPCName: name, IfName: e.Name}
		if a.IfName == "" {
			a.IfName = defaultIfName(idx)
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
	// Every entry may have been a delegated pin, leaving nothing to build. That is
	// a legitimate shape — management on the default network, transit legs on VPCs
	// through NADs — and the caller falls through to the default network.
	return out, nil
}

// isDelegatedIfName reports whether an interface name belongs to Multus rather
// than to the annotation path. Multus traditionally assigns netN. Recent
// KubeVirt releases request pod plus an eleven-character lowercase hex digest
// for secondary launcher-pod interfaces. Both spaces are reserved so the two
// attachment paths cannot claim the same interface.
func isDelegatedIfName(name string) bool {
	if strings.HasPrefix(name, "net") && len(name) > len("net") {
		for _, c := range name[len("net"):] {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	if !strings.HasPrefix(name, "pod") || len(name) != len("pod")+11 {
		return false
	}
	for _, c := range name[len("pod"):] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// delegateIndex extracts N from netN. KubeVirt's digest-shaped name has no
// ordinal; Index is not used for delegated datapath identity, so zero is the
// canonical value for that form.
func delegateIndex(ifName string) (int, error) {
	if strings.HasPrefix(ifName, "pod") && isDelegatedIfName(ifName) {
		return 0, nil
	}
	if !strings.HasPrefix(ifName, "net") || !isDelegatedIfName(ifName) {
		return 0, fmt.Errorf("delegated interface name %q is neither net<N> nor KubeVirt's pod<digest> form", ifName)
	}
	n, err := strconv.Atoi(ifName[len("net"):])
	if err != nil {
		return 0, fmt.Errorf("delegated interface name %q: %w", ifName, err)
	}
	return n, nil
}

// delegateAttachment builds the single attachment of a Multus-delegated
// invocation: the VPC comes from the NAD (the plugin config), the interface name
// from Multus, and ip/mac — if pinned at all — from the pod's networks annotation
// entry naming this interface.
//
// It is never primary. A disagreement between the NAD's VPC and the annotation
// entry's is a hard error: two sources naming different networks for one NIC is
// not a precedence to resolve.
func delegateAttachment(confVPC, ifName, networksAnno, podNS string) (attachment, error) {
	if confVPC == "" {
		return attachment{}, fmt.Errorf("delegate mode needs a vpc in the plugin config")
	}
	idx, err := delegateIndex(ifName)
	if err != nil {
		return attachment{}, err
	}
	ns, name := parseVPCRef(confVPC, podNS)
	a := attachment{Index: idx, VPCNamespace: ns, VPCName: name, IfName: ifName, Delegated: true}

	if networksAnno == "" {
		return a, nil
	}
	var entries []netEntry
	if err := json.Unmarshal([]byte(networksAnno), &entries); err != nil {
		return attachment{}, fmt.Errorf("%s is not a JSON list of network entries: %w", networksAnnotation, err)
	}
	for i, e := range entries {
		if e.Name != ifName {
			continue
		}
		if e.VPC != "" {
			ens, ename := parseVPCRef(e.VPC, podNS)
			if ens != ns || ename != name {
				return attachment{}, fmt.Errorf(
					"%s entry %d pins %s to vpc %s/%s but the NetworkAttachmentDefinition names %s/%s",
					networksAnnotation, i, ifName, ens, ename, ns, name)
			}
		}
		if e.IP != "" {
			ip := net.ParseIP(e.IP)
			if ip == nil || ip.String() != e.IP {
				return attachment{}, fmt.Errorf("%s entry %d: ip %q is not an IP address in canonical form",
					networksAnnotation, i, e.IP)
			}
			a.IP = ip
		}
		if e.MAC != "" {
			mac, err := net.ParseMAC(e.MAC)
			if err != nil {
				return attachment{}, fmt.Errorf("%s entry %d: mac %q: %w", networksAnnotation, i, e.MAC, err)
			}
			if len(mac) != 6 {
				return attachment{}, fmt.Errorf("%s entry %d: mac %q is not a 6-byte address", networksAnnotation, i, e.MAC)
			}
			a.MAC = mac
		}
		break
	}
	return a, nil
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
// hostVethNameForDelegate names the host side of a MULTUS-delegated attachment.
//
// A LETTER where hostVethNameForIndex puts a digit, which is the whole point. The
// two paths delete independently — Multus calls the delegate's DEL separately from
// the primary's — and the primary's DEL finds its links by RECONSTRUCTING every
// name in its space rather than by consulting state. A shared space would let a
// primary DEL name, and destroy, a delegated interface. Disjoint spaces make that
// impossible by construction instead of by care.
//
// Same 14 characters as the indexed form and the same "cph" prefix, so datapath's
// rebuild scan and the masquerade RETURN rule keep matching.
func hostVethNameForDelegate(containerID, ifName string) (string, error) {
	if strings.HasPrefix(ifName, "pod") && isDelegatedIfName(ifName) {
		// KubeVirt names do not carry a NIC ordinal. Hash the complete sandbox and
		// interface identities so two NICs in one launcher pod stay distinct and
		// DEL reconstructs the exact same name. Six bytes plus the three-byte
		// prefix fit Linux IFNAMSIZ exactly.
		sum := sha256.Sum256([]byte(containerID + "\x00" + ifName))
		return fmt.Sprintf("%s%x", hostVethPrefix, sum[:6]), nil
	}
	n, err := delegateIndex(ifName)
	if err != nil {
		return "", err
	}
	if n > maxDelegates {
		return "", fmt.Errorf("delegated interface %q exceeds the %d supported per pod (host interface names)",
			ifName, maxDelegates)
	}
	id := containerID
	if len(id) > 10 {
		id = id[:10]
	}
	return hostVethPrefix + string(rune('a'+n)) + id, nil
}

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
