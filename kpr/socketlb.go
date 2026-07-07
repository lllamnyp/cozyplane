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
	c := socketLBConfig{
		CgroupRoot: "/run/cilium/cgroupv2",
		BPFFSRoot:  "/sys/fs/bpf",
	}
	// Env overrides for environments whose cgroup2/bpffs layout differs (kind
	// nodes mount cgroup2 at /sys/fs/cgroup). A flag-cell is the eventual home.
	if v := os.Getenv("KPR_CGROUP_ROOT"); v != "" {
		c.CgroupRoot = v
	}
	if v := os.Getenv("KPR_BPFFS_ROOT"); v != "" {
		c.BPFFSRoot = v
	}
	return c
}

// socketLBCell attaches the committed socket-LB object at the cgroup root. It
// runs after lbcell so the service/backend maps this object references by name
// already exist and are pinned; LoadCollection resolves them by pin path, so
// control plane and datapath join with no map-ABI coupling in our code.
var socketLBCell = cell.Module(
	"socketlb",
	"cozyplane socket load-balancer attach",
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

	// The LB service/backend maps are OWNED and pinned by lbcell's reconciler,
	// and it sizes them from its own config — so bpf_sock.o's compile-time
	// MaxEntries won't match. Adopt the existing pins via MapReplacements (the
	// loader then uses the reconciler's map fd verbatim, skipping the spec's
	// size/flags check); this is how the datapath joins the control plane by
	// pin path with no map-ABI coupling. Maps the object declares but the
	// reconciler didn't pin (object-private: cilium_ipcache_v2, cilium_metrics)
	// aren't found and fall through to be created+pinned empty — acceptable for
	// east-west (design draft).
	// For every map the reconciler already pinned, adopt its actual geometry
	// (MaxEntries/Flags) onto the spec so the loader opens the existing pin
	// instead of rejecting bpf_sock.o's compile-time sizing — the reconciler is
	// the owner and sizes these from its own config. The loader then opens the
	// pins by PinByName+PinPath; maps the object declares but the reconciler
	// didn't pin (object-private: cilium_ipcache_v2, cilium_metrics) fall
	// through and are created+pinned empty (acceptable east-west, design draft).
	pinDir := filepath.Join(cfg.BPFFSRoot, "tc", "globals")
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinByName {
			continue
		}
		pinned, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			continue // not pinned by the reconciler; created below
		}
		info, err := pinned.Info()
		if err == nil {
			m.MaxEntries = info.MaxEntries
			m.Flags = info.Flags
		}
		_ = pinned.Close()
	}
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
