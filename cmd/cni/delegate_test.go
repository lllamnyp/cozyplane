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
	"strings"
	"testing"
)

func TestIsDelegatedIfName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"net1", true},
		{"net0", true},
		{"net12", true},
		{"pod4ef2736ef84", true},
		{"net", false},  // the bare prefix is not a NIC
		{"eth0", false}, // the annotation path's own names
		{"eth1", false},
		{"netx", false}, // Multus numbers; a name is not a number
		{"net1x", false},
		{"pod4ef2736ef8", false},   // digest is too short
		{"pod4ef2736ef84a", false}, // digest is too long
		{"pod4EF2736ef84", false},  // KubeVirt emits lowercase hex
		{"pod4ef2736ef8x", false},  // non-hex digest
		{"", false},
	} {
		if got := isDelegatedIfName(tc.name); got != tc.want {
			t.Errorf("isDelegatedIfName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The two host-veth name spaces must not overlap. The primary's DEL finds its
// links by RECONSTRUCTING every name in its space, so an overlap would let it
// name — and destroy — a delegated interface.
func TestHostVethNameSpacesAreDisjoint(t *testing.T) {
	const id = "abcdef0123456789abcdef"

	seen := map[string]string{}
	for i := range maxAttachments {
		n := hostVethNameForIndex(id, i)
		if prev, dup := seen[n]; dup {
			t.Fatalf("indexed name %q collides with %s", n, prev)
		}
		seen[n] = "index " + string(rune('0'+i))
	}
	for _, ifName := range []string{"net0", "net1", "net2", "net9", "net10", "net25", "pod4ef2736ef84", "poda4e193d72c1"} {
		n, err := hostVethNameForDelegate(id, ifName)
		if err != nil {
			t.Fatalf("hostVethNameForDelegate(%q): %v", ifName, err)
		}
		if prev, dup := seen[n]; dup {
			t.Errorf("delegate name for %s is %q, which collides with %s", ifName, n, prev)
		}
		seen[n] = "delegate " + ifName

		// IFNAMSIZ leaves 15 usable characters, and datapath's rebuild scan and
		// the masquerade RETURN rule both match on the prefix.
		if len(n) > 15 {
			t.Errorf("delegate name %q is %d characters, over the 15 IFNAMSIZ allows", n, len(n))
		}
		if !strings.HasPrefix(n, hostVethPrefix) {
			t.Errorf("delegate name %q lost the %q prefix", n, hostVethPrefix)
		}
	}
}

func TestHostVethNameForDelegateRefusals(t *testing.T) {
	const id = "abcdef0123456789"
	for _, ifName := range []string{"eth0", "net", "myiface", "net26", "pod4ef2736ef8x"} {
		if _, err := hostVethNameForDelegate(id, ifName); err == nil {
			t.Errorf("hostVethNameForDelegate(%q) succeeded; want an error", ifName)
		}
	}
}

// A netN entry is a pin for a NIC Multus will build, not a leg this invocation
// builds. Skipping it is what keeps the two paths from claiming one interface.
func TestParseAttachmentsSkipsDelegatedEntries(t *testing.T) {
	anno := `[{"vpc":"front"},{"name":"net1","vpc":"back","ip":"10.20.0.5"},{"vpc":"store"}]`
	atts, err := parseAttachments("", anno, "team-a")
	if err != nil {
		t.Fatalf("parseAttachments: %v", err)
	}
	if len(atts) != 2 {
		t.Fatalf("got %d attachments, want 2 (the netN entry is Multus's)", len(atts))
	}
	if atts[0].VPCName != "front" || atts[1].VPCName != "store" {
		t.Errorf("wrong VPCs kept: %q, %q", atts[0].VPCName, atts[1].VPCName)
	}
	// Indices run over the surviving entries: eth1, not eth2, and both distinct.
	if atts[0].Index != 0 || atts[1].Index != 1 {
		t.Errorf("indices = %d, %d; want 0, 1", atts[0].Index, atts[1].Index)
	}
	if atts[1].IfName != "eth1" {
		t.Errorf("second interface = %q, want eth1", atts[1].IfName)
	}
}

// Index 0 carries the fabric handle, the default route and status.podIP. A
// delegated entry listed first must not shift that onto a non-primary leg.
func TestParseAttachmentsDelegatedFirstStillLeavesAPrimary(t *testing.T) {
	atts, err := parseAttachments("", `[{"name":"net1","vpc":"back"},{"vpc":"front"}]`, "team-a")
	if err != nil {
		t.Fatalf("parseAttachments: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("got %d attachments, want 1", len(atts))
	}
	if !atts[0].Primary() {
		t.Error("the surviving entry is not primary: no leg would carry the fabric bridge")
	}
	if atts[0].IfName != contVethName {
		t.Errorf("primary interface = %q, want %q", atts[0].IfName, contVethName)
	}
}

// All-delegated is a legitimate shape: management on the default network, transit
// legs on VPCs through NADs. The caller falls through to the default network.
func TestParseAttachmentsAllDelegatedIsEmpty(t *testing.T) {
	atts, err := parseAttachments("", `[{"name":"net1","vpc":"back"},{"name":"net2","vpc":"front"}]`, "team-a")
	if err != nil {
		t.Fatalf("parseAttachments: %v", err)
	}
	if len(atts) != 0 {
		t.Fatalf("got %d attachments, want none", len(atts))
	}
}

func TestParseAttachmentsRefusesDuplicateDelegatedName(t *testing.T) {
	_, err := parseAttachments("", `[{"name":"net1","vpc":"a"},{"name":"net1","vpc":"b"}]`, "team-a")
	if err == nil {
		t.Fatal("two pins for net1 accepted; want an error")
	}
}

func TestDelegateAttachmentTakesPinnedAddress(t *testing.T) {
	anno := `[{"vpc":"front"},{"name":"net1","vpc":"team-a/back","ip":"10.20.0.5","mac":"02:00:00:00:20:05"}]`
	a, err := delegateAttachment("team-a/back", "net1", anno, "team-a")
	if err != nil {
		t.Fatalf("delegateAttachment: %v", err)
	}
	if a.IP == nil || a.IP.String() != "10.20.0.5" {
		t.Errorf("ip = %v, want 10.20.0.5", a.IP)
	}
	if a.MAC == nil || a.MAC.String() != "02:00:00:00:20:05" {
		t.Errorf("mac = %v, want the pinned one", a.MAC)
	}
	if a.IfName != "net1" {
		t.Errorf("ifname = %q, want net1", a.IfName)
	}
	if !a.Delegated {
		t.Error("attachment is not marked delegated")
	}
	// Whatever its index, a delegated attachment never owns the fabric handle.
	if a.Primary() {
		t.Error("a delegated attachment reported itself primary")
	}
}

// The NAD is what the VM references; a pin naming a different VPC means two
// sources disagree about which network the NIC is on.
func TestDelegateAttachmentRefusesVPCDisagreement(t *testing.T) {
	anno := `[{"name":"net1","vpc":"team-a/elsewhere","ip":"10.20.0.5"}]`
	_, err := delegateAttachment("team-a/back", "net1", anno, "team-a")
	if err == nil {
		t.Fatal("a pin naming another VPC was accepted")
	}
	if !strings.Contains(err.Error(), "NetworkAttachmentDefinition") {
		t.Errorf("error %q should name the NAD so the operator knows which side to fix", err)
	}
}

// A VM that just wants "a NIC on that VPC" should need no annotation at all.
func TestDelegateAttachmentWithoutAnnotationUsesIPAM(t *testing.T) {
	a, err := delegateAttachment("team-a/back", "net1", "", "team-a")
	if err != nil {
		t.Fatalf("delegateAttachment: %v", err)
	}
	if a.IP != nil || a.MAC != nil {
		t.Errorf("nothing was pinned, but got ip=%v mac=%v", a.IP, a.MAC)
	}
	if a.VPCNamespace != "team-a" || a.VPCName != "back" {
		t.Errorf("vpc = %s/%s, want team-a/back", a.VPCNamespace, a.VPCName)
	}
}

func TestDelegateAttachmentAcceptsKubeVirtInterfaceName(t *testing.T) {
	a, err := delegateAttachment("team-a/back", "pod4ef2736ef84", "", "team-a")
	if err != nil {
		t.Fatalf("delegateAttachment: %v", err)
	}
	if a.IfName != "pod4ef2736ef84" || !a.Delegated {
		t.Errorf("unexpected attachment: ifname=%q delegated=%v", a.IfName, a.Delegated)
	}
}

// A pin for a DIFFERENT interface must not leak onto this one.
func TestDelegateAttachmentIgnoresOtherInterfacesPins(t *testing.T) {
	anno := `[{"name":"net2","vpc":"team-a/back","ip":"10.20.0.9"}]`
	a, err := delegateAttachment("team-a/back", "net1", anno, "team-a")
	if err != nil {
		t.Fatalf("delegateAttachment: %v", err)
	}
	if a.IP != nil {
		t.Errorf("net1 picked up net2's pinned address %v", a.IP)
	}
}

func TestDelegateAttachmentRefusals(t *testing.T) {
	if _, err := delegateAttachment("", "net1", "", "team-a"); err == nil {
		t.Error("delegate mode without a vpc in the config was accepted")
	}
	if _, err := delegateAttachment("team-a/back", "eth0", "", "team-a"); err == nil {
		t.Error("a non-netN interface name was accepted in delegate mode")
	}
}

// The NIC identity that keys a persistent Port must be tellable apart between the
// two paths, or a VM with one NIC from each on one VPC selects the wrong Port and
// its interfaces swap addresses across restarts.
func TestNICIDSpacesAreDisjoint(t *testing.T) {
	annotated := attachment{Index: 1, IfName: "eth1"}
	delegated := attachment{Index: 1, IfName: "net1", Delegated: true}
	if annotated.NICID() == delegated.NICID() {
		t.Fatalf("both paths produced NIC id %q", annotated.NICID())
	}
	if annotated.NICID() != "1" {
		t.Errorf("annotated NICID = %q, want the decimal index", annotated.NICID())
	}
	if delegated.NICID() != "net1" {
		t.Errorf("delegated NICID = %q, want the interface name", delegated.NICID())
	}
}
