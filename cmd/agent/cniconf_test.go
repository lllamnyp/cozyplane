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
	"os"
	"path/filepath"
	"testing"
)

// The runtime loads exactly one conf from /etc/cni/net.d — the one that sorts
// first — so writing ours unconditionally assumes we are alone on the node.
// Where the platform chains another CNI that assumption is false, and the file
// wins silently: no error, no log, just a node whose pod networking moved.
//
// cniConfOwner is the check that replaces the assumption. It is a plain
// directory read, so the decision is testable without a kernel, a runtime or a
// node.
func TestCNIConfOwner(t *testing.T) {
	cases := []struct {
		name    string
		present []string
		ours    string
		want    string
	}{{
		name: "an empty directory has no owner",
		ours: "10-cozyplane.conflist",
		want: "",
	}, {
		name:    "our own file does not block us",
		present: []string{"10-cozyplane.conflist"},
		ours:    "10-cozyplane.conflist",
		want:    "",
	}, {
		// The trap measured on the lab, and the limit of this check. The chart
		// asked for `00-cozyplane.conflist`, which sorts AHEAD of
		// `00-multus.conf` (m > c) — so nothing owns the directory ahead of us
		// and we would write, taking the node's pod networking from a chain that
		// worked and every VPC attachment with it.
		//
		// This check cannot save that configuration, and must not pretend to:
		// asking for a winning name IS asking to win. What fixes the chained
		// platform is the name it asks for (the chart's `cniConfName`); what this
		// check adds is that we never win by accident once someone else already
		// sorts first.
		name:    "a winning prefix wins, Multus present or not",
		present: []string{"00-multus.conf", "05-cilium.conflist"},
		ours:    "00-cozyplane.conflist",
		want:    "",
	}, {
		name:    "with a losing prefix the chain keeps ownership",
		present: []string{"00-multus.conf", "05-cilium.conflist"},
		ours:    "10-cozyplane.conflist",
		want:    "00-multus.conf",
	}, {
		// Winning on purpose stays allowed — that is what --cni-conf-name says.
		// The check only stops us from winning by accident.
		name:    "a neighbour that sorts after us owns nothing",
		present: []string{"99-other.conf"},
		ours:    "10-cozyplane.conflist",
		want:    "",
	}, {
		name:    "our atomic temporary is skipped",
		present: []string{".00-cozyplane.conflist.tmp"},
		ours:    "10-cozyplane.conflist",
		want:    "",
	}, {
		name:    "a file that is not a CNI conf is skipped",
		present: []string{"00-notes.md", "00-keep.txt"},
		ours:    "10-cozyplane.conflist",
		want:    "",
	}, {
		name:    "a .json conf counts like the others",
		present: []string{"00-legacy.json"},
		ours:    "10-cozyplane.conflist",
		want:    "00-legacy.json",
	}, {
		name:    "the first of several owners is the one named",
		present: []string{"05-cilium.conflist", "01-first.conf"},
		ours:    "10-cozyplane.conflist",
		want:    "01-first.conf",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range c.present {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644); err != nil {
					t.Fatalf("seed %s: %v", f, err)
				}
			}
			if got := cniConfOwner(dir, c.ours); got != c.want {
				t.Errorf("cniConfOwner = %q, want %q", got, c.want)
			}
		})
	}
}

// A missing directory is a node where nothing claims the CNI, so we write.
// Treating it as an error would stop cozyplane installing itself where it is
// alone — the ordinary case.
func TestCNIConfOwnerMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if got := cniConfOwner(missing, "10-cozyplane.conflist"); got != "" {
		t.Errorf("cniConfOwner = %q on a missing directory, want empty", got)
	}
}
