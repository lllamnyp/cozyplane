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

	"github.com/coreos/go-iptables/iptables"
)

// EnsureForwardRules accepts overlay traffic in the FORWARD chain ahead of
// kube-proxy's rules.
//
// Pod egress is encapsulated by an eBPF tc redirect, which bypasses conntrack.
// The decapsulated reply that returns on the Geneve device therefore has no
// matching conntrack entry and kube-proxy's "ctstate INVALID -j DROP" rule in
// KUBE-FORWARD discards it. Inserting an explicit ACCEPT for the Geneve device
// at the top of FORWARD lets decapsulated traffic through before that drop.
func EnsureForwardRules() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}

	for _, spec := range [][]string{
		{"-i", GeneveDevice, "-j", "ACCEPT"},
		{"-o", GeneveDevice, "-j", "ACCEPT"},
	} {
		if err := ipt.InsertUnique("filter", "FORWARD", 1, spec...); err != nil {
			return fmt.Errorf("insert FORWARD rule %v: %w", spec, err)
		}
	}

	return nil
}
