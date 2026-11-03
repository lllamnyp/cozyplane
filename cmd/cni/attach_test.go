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

// The single-VPC annotation is the common case and must keep meaning exactly
// what it meant: one attachment, on eth0, owning the pod's fabric handle.
func TestParseAttachmentsSingleAnnotationUnchanged(t *testing.T) {
	atts, err := parseAttachments("tenant-a/front", "", "team-a")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("got %d attachments, want 1", len(atts))
	}
	a := atts[0]
	if a.VPCNamespace != "tenant-a" || a.VPCName != "front" {
		t.Errorf("ref = %s/%s, want tenant-a/front", a.VPCNamespace, a.VPCName)
	}
	if a.IfName != "eth0" || !a.Primary() {
		t.Errorf("ifname=%q primary=%v, want eth0/true", a.IfName, a.Primary())
	}

	// A bare name defaults the owner namespace to the pod's.
	atts, err = parseAttachments("front", "", "team-a")
	if err != nil {
		t.Fatalf("parse bare: %v", err)
	}
	if atts[0].VPCNamespace != "team-a" {
		t.Errorf("bare ref namespace = %q, want team-a", atts[0].VPCNamespace)
	}
}

// No annotation at all is the default network, not an error.
func TestParseAttachmentsNoneIsDefaultNetwork(t *testing.T) {
	atts, err := parseAttachments("", "", "team-a")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(atts) != 0 {
		t.Fatalf("got %d attachments, want none", len(atts))
	}
}

func TestParseAttachmentsList(t *testing.T) {
	anno := `[{"vpc":"tenant-a/front","ip":"10.10.0.5"},
	          {"vpc":"back","mac":"02:00:00:00:00:01"},
	          {"vpc":"tenant-b/dmz","name":"wan0"}]`
	atts, err := parseAttachments("", anno, "team-a")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(atts) != 3 {
		t.Fatalf("got %d attachments, want 3", len(atts))
	}

	// Order is contract: only entry 0 is primary.
	if !atts[0].Primary() || atts[1].Primary() || atts[2].Primary() {
		t.Error("exactly the first entry must be primary")
	}
	if atts[0].IP == nil || atts[0].IP.String() != "10.10.0.5" {
		t.Errorf("entry 0 ip = %v, want 10.10.0.5", atts[0].IP)
	}
	if atts[1].VPCNamespace != "team-a" || atts[1].VPCName != "back" {
		t.Errorf("entry 1 ref = %s/%s, want team-a/back", atts[1].VPCNamespace, atts[1].VPCName)
	}
	if atts[1].MAC == nil || atts[1].MAC.String() != "02:00:00:00:00:01" {
		t.Errorf("entry 1 mac = %v", atts[1].MAC)
	}
	// Names default to eth<index>, and an explicit one wins.
	if atts[0].IfName != "eth0" || atts[1].IfName != "eth1" || atts[2].IfName != "wan0" {
		t.Errorf("ifnames = %q/%q/%q", atts[0].IfName, atts[1].IfName, atts[2].IfName)
	}
}

// Both annotations is a contradiction, and guessing which half the author meant
// is how a workload lands on a network nobody asked for.
func TestParseAttachmentsRefusesBothAnnotations(t *testing.T) {
	_, err := parseAttachments("tenant-a/front", `[{"vpc":"tenant-a/back"}]`, "team-a")
	if err == nil {
		t.Fatal("carrying both annotations must be refused")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should say why: %v", err)
	}
}

func TestParseAttachmentsRefusals(t *testing.T) {
	long := "["
	for i := range maxAttachments + 1 {
		if i > 0 {
			long += ","
		}
		long += `{"vpc":"v"}`
	}
	long += "]"

	cases := []struct{ name, anno string }{
		{"not JSON", `{"vpc":"a"}`},
		{"empty list", `[]`},
		{"entry with no vpc", `[{"ip":"10.0.0.1"}]`},
		{"ip is not an address", `[{"vpc":"a","ip":"the-web-vm"}]`},
		{"ip is a CIDR", `[{"vpc":"a","ip":"10.0.0.0/24"}]`},
		// Non-canonical would claim a different Port name for the same address.
		{"ip not canonical", `[{"vpc":"a","ip":"fd00:0a::0005"}]`},
		{"mac is nonsense", `[{"vpc":"a","mac":"not-a-mac"}]`},
		// Two entries on one interface: the second would silently replace the
		// first inside the pod.
		{"duplicate interface name", `[{"vpc":"a","name":"eth9"},{"vpc":"b","name":"eth9"}]`},
		{"implicit duplicate name", `[{"vpc":"a","name":"eth1"},{"vpc":"b"}]`},
		{"beyond the interface-name budget", long},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseAttachments("", c.anno, "team-a"); err == nil {
				t.Fatal("want rejected, got accepted")
			}
		})
	}
}

// The host veth name is the reason maxAttachments exists: IFNAMSIZ leaves 15
// usable characters. Index 0 must ALSO keep its exact historic name, or a DEL
// for a pod created before multi-attach reconstructs a name that does not exist
// and leaves its links and map entries behind.
func TestHostVethNameForIndex(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"

	if got, want := hostVethNameForIndex(id, 0), hostVethNameFor(id); got != want {
		t.Errorf("index 0 = %q, want the unindexed %q", got, want)
	}

	seen := map[string]bool{}
	for i := range maxAttachments {
		n := hostVethNameForIndex(id, i)
		if len(n) > 15 {
			t.Errorf("index %d gives %q (%d chars), over the 15 IFNAMSIZ allows", i, n, len(n))
		}
		if !strings.HasPrefix(n, hostVethPrefix) {
			t.Errorf("index %d gives %q, which the agent's rebuild scan would not match", i, n)
		}
		if seen[n] {
			t.Errorf("index %d reuses the name %q", i, n)
		}
		seen[n] = true
	}

	// Short container IDs must not panic or collide with the slicing.
	if n := hostVethNameForIndex("abc", 3); n == "" || len(n) > 15 {
		t.Errorf("short id gives %q", n)
	}
}

func TestDefaultIfName(t *testing.T) {
	if defaultIfName(0) != "eth0" || defaultIfName(1) != "eth1" || defaultIfName(9) != "eth9" {
		t.Errorf("defaultIfName: %q %q %q", defaultIfName(0), defaultIfName(1), defaultIfName(9))
	}
}
