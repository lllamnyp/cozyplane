// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/cell"
)

// Socket-LB program names in bpf_sock.o (built with the TCP+UDP socket-LB gates
// only, so getpeername/bind aren't present) mapped to their cgroup attach type.
// Mirrors pkg/socketlb attachTypes, trimmed to the seven core programs we ship.
var attachTypes = map[string]ebpf.AttachType{
	"cil_sock4_connect": ebpf.AttachCGroupInet4Connect,
	"cil_sock4_sendmsg": ebpf.AttachCGroupUDP4Sendmsg,
	"cil_sock4_recvmsg": ebpf.AttachCGroupUDP4Recvmsg,
	"cil_sock6_connect": ebpf.AttachCGroupInet6Connect,
	"cil_sock6_sendmsg": ebpf.AttachCGroupUDP6Sendmsg,
	"cil_sock6_recvmsg": ebpf.AttachCGroupUDP6Recvmsg,
	"cil_sock_release":  ebpf.AttachCgroupInetSockRelease,
}

// socketLBConfig is the small set of load/attach knobs. The cgroup v2 root is
// where socket-LB attaches (fires for every socket syscall cluster-wide); the
// bpffs map dir is where the LB reconciler pins the service/backend maps this
// object shares by name.
type socketLBConfig struct {
	CgroupRoot string
	BPFFSRoot  string
}

func defaultSocketLBConfig() socketLBConfig {
	return socketLBConfig{
		CgroupRoot: "/run/cilium/cgroupv2",
		BPFFSRoot:  "/sys/fs/bpf",
	}
}

// socketLBCell attaches the committed socket-LB object at the cgroup root. It
// runs after lbcell so the service/backend maps this object references by name
// already exist and are pinned; LoadCollection resolves them by pin path, so
// control plane and datapath join with no map-ABI coupling in our code.
var socketLBCell = cell.Module(
	"socketlb",
	"cozyplane socket load-balancer attach (committed bpf_sock.o)",
	cell.Invoke(func(lc cell.Lifecycle, logger *slog.Logger) {
		cfg := defaultSocketLBConfig()
		var coll *ebpf.Collection
		var links []link.Link
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				c, l, err := attachSocketLB(logger, cfg, bpfSockObject)
				if err != nil {
					return fmt.Errorf("attach socket-LB: %w", err)
				}
				coll, links = c, l
				return nil
			},
			OnStop: func(cell.HookContext) error {
				// Links are pinned, so the attachment survives us; closing the
				// fds here only releases our handles.
				for _, l := range links {
					_ = l.Close()
				}
				if coll != nil {
					coll.Close()
				}
				return nil
			},
		})
	}),
)

// attachSocketLB loads the embedded object (resolving the LB maps by their
// bpffs pin path) and attaches each cgroup program at the cgroup root, pinning
// the resulting links so the association outlives this process. Mirrors
// pkg/socketlb/cgroup.go attachCgroup.
func attachSocketLB(logger *slog.Logger, cfg socketLBConfig, obj []byte) (*ebpf.Collection, []link.Link, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}

	// Maps carrying LIBBPF_PIN_BY_NAME (the LB service/backend maps the
	// reconciler owns) resolve to their existing pins under the bpffs root;
	// object-private maps (e.g. cilium_ipcache_v2, cilium_metrics) are created
	// empty, which is acceptable for east-west (verified in the design draft).
	pinDir := filepath.Join(cfg.BPFFSRoot, "tc", "globals")
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("new collection (pin dir %s): %w", pinDir, err)
	}

	cg, err := os.Open(cfg.CgroupRoot)
	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("open cgroup root %s: %w", cfg.CgroupRoot, err)
	}
	defer cg.Close()

	linkDir := filepath.Join(cfg.BPFFSRoot, "cozyplane", "socketlb")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("mkdir link dir %s: %w", linkDir, err)
	}

	var links []link.Link
	for name, attach := range attachTypes {
		prog := coll.Programs[name]
		if prog == nil {
			coll.Close()
			return nil, nil, fmt.Errorf("program %s not in object", name)
		}
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  int(cg.Fd()),
			Program: prog,
			Attach:  attach,
		})
		if err != nil {
			coll.Close()
			return nil, nil, fmt.Errorf("attach %s: %w", name, err)
		}
		pin := filepath.Join(linkDir, name)
		_ = os.Remove(pin)
		if err := l.Pin(pin); err != nil {
			_ = l.Close()
			coll.Close()
			return nil, nil, fmt.Errorf("pin link %s: %w", pin, err)
		}
		logger.Info("attached socket-LB program", "name", name, "cgroup", cfg.CgroupRoot)
		links = append(links, l)
	}
	return coll, links, nil
}

func defaultLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

var _ = context.Background // reserved for a future readiness/health probe
