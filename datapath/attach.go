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
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// tcxMu serialises the writers of a hook's cozyplane link INSIDE the agent:
// ensureTCX (program reload) and the order reconciler. Without it the
// reconciler can detach a link that ensureTCX is adopting, which is the
// two-generations state both are written to avoid.
//
// withBridgeLock also serialises these writers against the separate CNI process.
var tcxMu sync.Mutex

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
	return withBridgeLock(func() error {
		tcxMu.Lock()
		defer tcxMu.Unlock()
		return detachVethLocked(ifindex)
	})
}

func detachVethLocked(ifindex int) error {
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
		if err := removeTCXGuard(linkPinPath(ifindex, ingress)); err != nil {
			return err
		}
		if err := os.Remove(linkPinPath(ifindex, ingress)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ReconcilePodTCXOrder puts our classifiers back at the position each local pod
// veth requires, and reports how many hooks it had to move.
//
// **Why a loop and not just an anchor at attach time.** A peer CNI sharing the
// interface programs its endpoint asynchronously, after CNI ADD has returned.
// Whatever order we established at attach time is therefore not the order that
// survives: the peer appends (or prepends) later, silently, and nothing fails.
// An anchor decides where we land; only a loop keeps us there.
//
// **Why it repairs by detaching, not by dropping the pin.** tcx offers no "move"
// operation: a link's position is fixed when it is created, so the repair is
// detach-then-attach-anchored. Doing that by removing the pin is what produced
// the dev4 split datapath — pin removal does NOT reliably detach, both
// generations stayed attached, and the older one ran first against maps nothing
// updated any more. detachLink asks the kernel, which is the difference.
//
// A pinned DROP guard covers detach/re-attach, including failures and process
// interruption. A successful replacement is published before the guard is removed.
//
// Foreign links are only ever counted, never touched: ourTCXLinks selects ours,
// and the peer's programs decide our target index without us moving them.
func (m *Manager) ReconcilePodTCXOrder() (int, error) {
	veths, err := ListLocalPortVeths()
	if err != nil {
		return 0, err
	}

	type podHook struct {
		name    string
		program *ebpf.Program
		attach  ebpf.AttachType
		ingress bool
		id      ebpf.ProgramID
	}
	hooks := []podHook{
		{name: "from_pod", program: m.objs.CozyplaneFromPod, attach: ebpf.AttachTCXIngress, ingress: true},
		{name: "to_pod", program: m.objs.CozyplaneToPod, attach: ebpf.AttachTCXEgress, ingress: false},
	}
	for i := range hooks {
		info, err := hooks[i].program.Info()
		if err != nil {
			return 0, fmt.Errorf("inspect %s program: %w", hooks[i].name, err)
		}
		programID, ok := info.ID()
		if !ok {
			return 0, fmt.Errorf("%s program has no ID", hooks[i].name)
		}
		hooks[i].id = programID
	}

	moved := 0
	var errs []error
	if _, err := pruneDetachedTCXPins(); err != nil {
		errs = append(errs, err)
	}
	for _, veth := range veths {
		// A non-zero network is a Cozyplane VPC leg. Net zero is the fabric
		// interface shared with Cilium.
		first := veth.Net != 0
		for _, hook := range hooks {
			err := withBridgeLock(func() error {
				tcxMu.Lock()
				defer tcxMu.Unlock()
				// The snapshot may race DEL or ifindex reuse; only mutate the
				// endpoint whose full alias was actually scanned.
				current := cozyVethByIndex(veth.Ifindex)
				if current == nil || current.Attrs().Alias != veth.Alias {
					return nil
				}
				result, err := link.QueryPrograms(link.QueryOptions{Target: veth.Ifindex, Attach: hook.attach})
				if err != nil {
					return fmt.Errorf("query %s tcx hook on ifindex %d: %w", hook.name, veth.Ifindex, err)
				}
				own := -1
				for i, attached := range result.Programs {
					if attached.ID == hook.id {
						own = i
						break
					}
				}
				pin := linkPinPath(veth.Ifindex, hook.ingress)
				if tcxOrderOK(own, len(result.Programs), first) {
					return removeTCXGuard(pin)
				}
				// Never detach an attached program whose link we do not own.
				if _, err := os.Stat(pin); err != nil && own >= 0 {
					if errors.Is(err, os.ErrNotExist) {
						return nil
					}
					return err
				}
				anchor := link.Tail()
				if first {
					anchor = link.Head()
				}
				if err := reanchorTCXLocked(veth.Ifindex, hook.program, hook.attach, hook.ingress, anchor); err != nil {
					return fmt.Errorf("reorder %s on ifindex %d: %w", hook.name, veth.Ifindex, err)
				}
				moved++
				return nil
			})
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return moved, errors.Join(errs...)
}

// reanchorTCXLocked keeps a pinned DROP guard until the replacement is live.
// The caller holds the host-file lock and tcxMu.
func reanchorTCXLocked(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool, anchor link.Anchor) error {
	if err := os.MkdirAll(filepath.Join(PinRoot, "links"), 0755); err != nil {
		return err
	}
	pin := linkPinPath(ifindex, ingress)
	links, _, err := ourTCXLinks(ifindex, attach)
	if err != nil {
		return err
	}
	defer func() {
		for _, current := range links {
			_ = current.Close()
		}
	}()
	if err := installTCXGuard(ifindex, attach, pin+"-guard"); err != nil {
		return err
	}
	if err := removeTCXPin(pin); err != nil {
		return err
	}
	for _, current := range links {
		if err := detachLink(current); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return freshAttachTCX(ifindex, prog, attach, pin, anchor)
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

// tcxOrderOK reports whether our program already runs at the position the
// interface requires, given its index among ALL programs at the hook (ours < 0
// when we are not attached) and how many there are.
//
// Kept a plain function, like planTCX: the rule is the whole point, and it must
// be readable and testable without a kernel, a veth or a peer CNI.
//
// wantFirst is a property of the interface, not a preference:
//
//   - A VPC leg needs us FIRST. Our verdicts are terminal, and they are what
//     stops a peer CNI from reading an overlapping tenant address as a fabric
//     identity; DNS answers are also rewritten before anyone can deliver them
//     to the hidden fabric address.
//   - The default network needs us LAST, so the peer's service load-balancing,
//     policy and connection tracking keep their ordinary semantics and see the
//     packet the way they expect.
//
// Alone at the hook, order is whatever we are — there is nothing to be before
// or after, so nothing to repair.
func tcxOrderOK(ours, n int, wantFirst bool) bool {
	if ours < 0 {
		// Not attached at all. Not an ordering question, but the reconciler is
		// the only loop that revisits a live veth, and Cilium has been seen to
		// leave a stale pin behind while it replaces a hook's program list. Say
		// "not OK" so that state gets repaired too.
		return false
	}
	if n <= 1 {
		return true
	}
	if wantFirst {
		return ours == 0
	}
	return ours == n-1
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
	return withBridgeLock(func() error { return ensureTCXLocked(ifindex, prog, attach, ingress) })
}

func ensureTCXLocked(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool) error {
	tcxMu.Lock()
	defer tcxMu.Unlock()

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
				if err := installTCXGuard(ifindex, attach, pin+"-guard"); err != nil {
					return err
				}
				for _, l := range links {
					if err := detachLink(l); err != nil {
						return err
					}
				}
				links = nil
				return freshAttachTCX(ifindex, prog, attach, pin, nil)
			}
		}
		for _, i := range plan.stale {
			if err := detachLink(links[i]); err != nil {
				return fmt.Errorf("detach stale tcx link (ifindex %d): %w", ifindex, err)
			}
		}
		if err := pinLink(keep, pin); err != nil {
			return err
		}
		return removeTCXGuard(pin)
	}

	return freshAttachTCX(ifindex, prog, attach, pin, nil)
}

// freshAttachTCX attaches prog at a hook that carries none of our links.
//
// anchor says WHERE in the hook's run order to land: link.Head() to run before
// everything already there, link.Tail() to run after, nil to take the kernel's
// default. Position matters only where another tcx user shares the interface —
// see ReconcilePodTCXOrder — so every ordinary caller passes nil and keeps the
// behaviour it had.
func freshAttachTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, pin string, anchor link.Anchor) error {
	// No link of ours here, so a leftover pin is a dangling reference to a link
	// that is already gone; it must not shadow the one we are about to make.
	_ = os.Remove(pin)

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attach,
		Anchor:    anchor,
	})
	if err != nil {
		return fmt.Errorf("attach tcx (ifindex %d): %w", ifindex, err)
	}
	if err := pinLink(l, pin); err != nil {
		_ = detachLink(l)
		return err
	}
	// Close our handle; the pin keeps the link (and attachment) alive.
	if err := l.Close(); err != nil {
		return err
	}
	return removeTCXGuard(pin)
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

func installTCXGuard(ifindex int, attach ebpf.AttachType, pin string) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "cp_tcx_guard", Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}, // TCX_DROP
	})
	if err != nil {
		return fmt.Errorf("load tcx guard: %w", err)
	}
	defer prog.Close()
	l, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: attach, Anchor: link.Head()})
	if err != nil {
		return fmt.Errorf("attach tcx guard: %w", err)
	}
	defer l.Close()
	return replaceTCXPin(l, pin)
}

func removeTCXGuard(pin string) error {
	for _, path := range []string{pin + "-guard", pin + "-guard-swap"} {
		if err := removeTCXPin(path); err != nil {
			return fmt.Errorf("remove tcx guard: %w", err)
		}
	}
	return nil
}

// Detach explicitly: dropping a pin alone defers kernel destruction and can
// leave the same program attached long enough to reject its immediate retry.
func removeTCXPin(pin string) error {
	l, err := link.LoadPinnedLink(pin, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer l.Close()
	if err := l.Detach(); err != nil {
		return err
	}
	return l.Unpin()
}

func replaceTCXPin(l link.Link, pin string) error {
	old, err := link.LoadPinnedLink(pin, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old != nil {
		defer old.Close()
	}
	// bpffs rejects dentry names containing dots (EPERM), so the temp pin uses
	// a dash. Unique per (ifindex, direction), like the pin itself.
	tmp := pin + "-swap"
	_ = os.Remove(tmp)
	if err := l.Pin(tmp); err != nil {
		return fmt.Errorf("pin tcx link: %w", err)
	}
	if err := os.Rename(tmp, pin); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("swap tcx link pin: %w", err)
	}
	if old != nil {
		return old.Detach()
	}
	return nil
}
