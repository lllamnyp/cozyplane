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
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// OpenPinnedProgram loads the classifier program from its bpffs pin. The CNI
// plugin uses this to attach the program to a freshly created host veth without
// re-loading the whole collection.
func OpenPinnedProgram() (*ebpf.Program, error) {
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(PinRoot, progPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned program: %w", err)
	}
	return prog, nil
}

// AttachIngress attaches the classifier at the ingress of the given interface
// (a pod's host-side veth) using a clsact qdisc + direct-action bpf filter.
// Classic tc holds a reference on the program, so the attachment survives the
// plugin process exiting and is removed automatically when the veth is deleted.
func AttachIngress(ifindex int, prog *ebpf.Program) error {
	return attachClsact(ifindex, prog, netlink.HANDLE_MIN_INGRESS)
}

// AttachEgress attaches the classifier at the egress of the given interface
// (the node uplink), so host-originated traffic to remote pod CIDRs is also
// encapsulated.
func AttachEgress(ifindex int, prog *ebpf.Program) error {
	return attachClsact(ifindex, prog, netlink.HANDLE_MIN_EGRESS)
}

func attachClsact(ifindex int, prog *ebpf.Program, parent uint32) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(0xffff, 0),
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "cozyplane_from_pod",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("add bpf filter: %w", err)
	}

	return nil
}
