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

// OpenPinnedProgram loads the from-pod (egress) classifier from its bpffs pin.
func OpenPinnedProgram() (*ebpf.Program, error) {
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(PinRoot, progPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned from_pod program: %w", err)
	}
	return prog, nil
}

// OpenPinnedToPod loads the to-pod (ingress) classifier from its bpffs pin.
func OpenPinnedToPod() (*ebpf.Program, error) {
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(PinRoot, toPodPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned to_pod program: %w", err)
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

// ReattachIngress swaps an interface's ingress classifier to prog. Unlike
// AttachIngress (fresh attach points, where a remove-then-attach window is
// harmless because no traffic flows yet) this is for *live* veths: the new
// link is attached before the old pin is replaced, so the interface is never
// without a classifier — a VPC pod must not see an unfiltered window.
func ReattachIngress(ifindex int, prog *ebpf.Program) error {
	return reattachTCX(ifindex, prog, ebpf.AttachTCXIngress, true)
}

// ReattachEgress swaps an interface's egress classifier to prog (see
// ReattachIngress).
func ReattachEgress(ifindex int, prog *ebpf.Program) error {
	return reattachTCX(ifindex, prog, ebpf.AttachTCXEgress, false)
}

func reattachTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool) error {
	if err := os.MkdirAll(filepath.Join(PinRoot, "links"), 0o755); err != nil {
		return err
	}
	// tcx is a program *list*: the new link coexists with the old one (which
	// runs first — its terminal verdicts win until the swap) so ordering is
	// attach-new, then atomically rename the pin over the old link's. Losing
	// its pin drops the old link's last reference and detaches it.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attach,
	})
	if isExist(err) {
		// This exact program is already attached here — a pod ADDed after the
		// agent pinned the fresh programs (the CNI attaches the same pinned
		// object). Already the desired end state.
		return nil
	}
	if err != nil {
		return fmt.Errorf("attach tcx (ifindex %d): %w", ifindex, err)
	}
	pin := linkPinPath(ifindex, ingress)
	// bpffs rejects dentry names containing dots (EPERM), so the temp pin uses
	// a dash. Unique per (ifindex, direction), like the pin itself.
	tmp := pin + "-swap"
	_ = os.Remove(tmp)
	if err := l.Pin(tmp); err != nil {
		l.Close()
		return fmt.Errorf("pin tcx link: %w", err)
	}
	if err := os.Rename(tmp, pin); err != nil {
		_ = os.Remove(tmp)
		l.Close()
		return fmt.Errorf("swap tcx link pin: %w", err)
	}
	return l.Close()
}

// DetachVeth removes the pinned ingress (from_pod) and egress (to_pod) links for
// an interface (used on CNI DEL). Removing a pin drops the last reference,
// detaching the program.
func DetachVeth(ifindex int) error {
	for _, ingress := range []bool{true, false} {
		if err := os.Remove(linkPinPath(ifindex, ingress)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
