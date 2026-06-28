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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// We attach with tcx (BPF links), not classic clsact filters: tcx links are
// independent kernel objects that coexist with other tcx users (notably Cilium,
// whose tc reconciliation strips foreign *classic* tc filters but leaves tcx
// links alone). The links are pinned so they survive the short-lived CNI plugin
// process and agent restarts.

func linkPinPath(ifindex int, ingress bool) string {
	dir := "eg"
	if ingress {
		dir = "in"
	}
	return filepath.Join(PinRoot, "links", fmt.Sprintf("%s-%d", dir, ifindex))
}

// OpenPinnedProgram loads the classifier program from its bpffs pin.
func OpenPinnedProgram() (*ebpf.Program, error) {
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(PinRoot, progPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned program: %w", err)
	}
	return prog, nil
}

// AttachIngress attaches the classifier at the ingress of the given interface
// (a pod's host-side veth) via a pinned tcx link.
func AttachIngress(ifindex int, prog *ebpf.Program) error {
	return attachTCX(ifindex, prog, ebpf.AttachTCXIngress, true)
}

// AttachEgress attaches the classifier at the egress of the given interface
// (the node uplink) via a pinned tcx link.
func AttachEgress(ifindex int, prog *ebpf.Program) error {
	return attachTCX(ifindex, prog, ebpf.AttachTCXEgress, false)
}

func attachTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool) error {
	if err := os.MkdirAll(filepath.Join(PinRoot, "links"), 0o755); err != nil {
		return err
	}
	pin := linkPinPath(ifindex, ingress)
	// Replace any stale link (e.g. from a previous agent instance).
	_ = os.Remove(pin)

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attach,
	})
	if err != nil {
		return fmt.Errorf("attach tcx (ifindex %d): %w", ifindex, err)
	}
	if err := l.Pin(pin); err != nil {
		l.Close()
		return fmt.Errorf("pin tcx link: %w", err)
	}
	// Close our handle; the pin keeps the link (and attachment) alive.
	return l.Close()
}

// DetachVeth removes the pinned ingress link for an interface (used on CNI DEL).
// Removing the pin drops the last reference, detaching the program.
func DetachVeth(ifindex int) error {
	if err := os.Remove(linkPinPath(ifindex, true)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
