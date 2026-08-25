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
	"strings"

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
	return ensureTCX(ifindex, prog, attach, ingress)
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
	return ensureTCX(ifindex, prog, attach, ingress)
}

// DetachVeth removes the ingress (from_pod) and egress (to_pod) links for an
// interface (used on CNI DEL).
//
// It asks the kernel to detach rather than only unlinking the pin: a tcx link
// whose pin goes away is NOT reliably detached, so pin-removal alone left the
// program running on a veth the pod no longer owns.
func DetachVeth(ifindex int) error {
	for _, ingress := range []bool{true, false} {
		attach := ebpf.AttachTCXEgress
		if ingress {
			attach = ebpf.AttachTCXIngress
		}
		links, _, err := ourTCXLinks(ifindex, attach)
		if err == nil {
			for _, l := range links {
				if derr := detachLink(l); derr != nil && !errors.Is(derr, os.ErrNotExist) {
					return derr
				}
			}
		}
		if err := os.Remove(linkPinPath(ifindex, ingress)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// cozyplaneProgPrefix identifies our own classifiers among the tcx programs
// attached at a hook. The kernel truncates `bpf_prog_info.name` to 15 chars, so
// `cozyplane_from_pod` comes back as `cozyplane_from_`; match on the prefix, and
// never on an exact name. Foreign programs (Cilium's, notably) must be left
// strictly alone — tcx is a shared list and stripping someone else's link is
// the failure mode tcx exists to avoid.
const cozyplaneProgPrefix = "cozyplane"

// tcxState is what a hook looks like before we touch it: our links already
// attached there, split into the one carrying the program we want (if any) and
// the stale ones that do not.
//
// Kept as a plain value so the decision — adopt which, detach which — is
// testable without a kernel.
type tcxState struct {
	// current is the index in ours of a link already running wantID, or -1.
	current int
	// stale lists indexes in ours whose program is a different generation.
	stale []int
}

// planTCX decides what to do with the cozyplane links found at a hook.
//
// The rule is one link per hook: adopt the one that is already there (swapping
// its program if it belongs to an older generation) and detach any others. The
// alternative — attach another link and drop the old pin — is what produced the
// dev4 split-datapath outage: removing a tcx link's pin does NOT reliably
// detach it, so both generations stayed attached, the older one ran first, and
// it answered from maps nothing updated any more.
func planTCX(progIDs []ebpf.ProgramID, wantID ebpf.ProgramID) tcxState {
	st := tcxState{current: -1}
	for i, id := range progIDs {
		switch {
		case id == wantID && st.current < 0:
			st.current = i
		case i == 0 && st.current < 0:
			// Adopt the first of ours as the survivor; its program gets swapped.
			st.current = i
		default:
			st.stale = append(st.stale, i)
		}
	}
	return st
}

// ourTCXLinks returns the cozyplane links attached at (ifindex, attach), in
// kernel order — which is run order, so index 0 is the program that sees a
// packet first. Links we cannot open or identify are skipped rather than
// guessed at. The caller closes every returned link.
func ourTCXLinks(ifindex int, attach ebpf.AttachType) ([]link.Link, []ebpf.ProgramID, error) {
	q, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		// A kernel without BPF_PROG_QUERY for tcx, or an interface that just
		// went away: fall back to a plain attach rather than failing the load.
		return nil, nil, err
	}
	var (
		links []link.Link
		ids   []ebpf.ProgramID
	)
	for _, ap := range q.Programs {
		if !isCozyplaneProgram(ap.ID) {
			continue
		}
		lid, ok := ap.LinkID()
		if !ok {
			// Attached without a link (classic tc): not ours to manage.
			continue
		}
		l, err := link.NewFromID(lid)
		if err != nil {
			continue
		}
		links = append(links, l)
		ids = append(ids, ap.ID)
	}
	return links, ids, nil
}

// isCozyplaneProgram reports whether a loaded program is one of ours.
func isCozyplaneProgram(id ebpf.ProgramID) bool {
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return false
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil {
		return false
	}
	return strings.HasPrefix(info.Name, cozyplaneProgPrefix)
}

// pinLink pins l at path, replacing whatever is there, without ever leaving the
// path empty: pin to a sibling and rename over it. bpffs rejects dentry names
// containing dots (EPERM), hence the dash.
func pinLink(l link.Link, path string) error {
	tmp := path + "-swap"
	_ = os.Remove(tmp)
	if err := l.Pin(tmp); err != nil {
		return fmt.Errorf("pin tcx link: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("swap tcx link pin: %w", err)
	}
	return nil
}

// pinProgram pins p at path without ever leaving the path empty (see pinLink).
func pinProgram(p *ebpf.Program, path string) error {
	tmp := path + "-swap"
	_ = os.Remove(tmp)
	if err := p.Pin(tmp); err != nil {
		return fmt.Errorf("pin program: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("swap program pin: %w", err)
	}
	return nil
}

// detachLink removes a link from its hook for good. Dropping the pin is not
// enough (the dev4 lesson): ask the kernel to detach, and only then let the
// reference go.
func detachLink(l link.Link) error {
	_ = l.Unpin()
	err := l.Detach()
	if err != nil && !errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	return l.Close()
}

// ensureTCX makes prog THE cozyplane classifier at (ifindex, direction).
//
// Idempotent by construction: an existing cozyplane link is adopted and its
// program swapped in place (atomic, no unfiltered window), any further
// cozyplane links at the same hook are detached, and only a hook with none of
// ours gets a fresh attach. Foreign tcx links are never touched.
func ensureTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool) error {
	if err := os.MkdirAll(filepath.Join(PinRoot, "links"), 0o755); err != nil {
		return err
	}
	pin := linkPinPath(ifindex, ingress)

	wantID, err := programID(prog)
	if err != nil {
		return err
	}

	links, ids, qerr := ourTCXLinks(ifindex, attach)
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	if qerr == nil && len(links) > 0 {
		plan := planTCX(ids, wantID)
		keep := links[plan.current]
		if ids[plan.current] != wantID {
			if err := keep.Update(prog); err != nil {
				// No in-place swap on this kernel: fall back to detaching
				// everything of ours and attaching cleanly.
				for _, l := range links {
					_ = detachLink(l)
				}
				links = nil
				return freshAttachTCX(ifindex, prog, attach, pin)
			}
		}
		for _, i := range plan.stale {
			if err := detachLink(links[i]); err != nil {
				return fmt.Errorf("detach stale tcx link (ifindex %d): %w", ifindex, err)
			}
		}
		return pinLink(keep, pin)
	}

	return freshAttachTCX(ifindex, prog, attach, pin)
}

// freshAttachTCX attaches prog at a hook that carries none of our links.
func freshAttachTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, pin string) error {
	// No link of ours here, so a leftover pin is a dangling reference to a link
	// that is already gone; it must not shadow the one we are about to make.
	_ = os.Remove(pin)

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
	if err := pinLink(l, pin); err != nil {
		_ = detachLink(l)
		return err
	}
	// Close our handle; the pin keeps the link (and attachment) alive.
	return l.Close()
}

// programID returns prog's kernel id.
func programID(prog *ebpf.Program) (ebpf.ProgramID, error) {
	info, err := prog.Info()
	if err != nil {
		return 0, fmt.Errorf("program info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("program info: no id (kernel too old)")
	}
	return id, nil
}
