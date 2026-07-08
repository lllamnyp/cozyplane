// SPDX-License-Identifier: Apache-2.0

// Command cozyplane-kpr is cozyplane's kube-proxy replacement: it imports
// Cilium's load-balancer control plane (pkg/loadbalancer/cell) to reconcile the
// service/backend BPF maps from Kubernetes Services + EndpointSlices, and
// attaches the committed socket-LB object (bpf_sock.o, built from the pinned
// Cilium tag) at the cgroup root so a pod's or host process's connect() to a
// ClusterIP is rewritten to a backend before it ever hits the wire.
//
// It is a DaemonSet distinct from cozyplane-agent (docs/kube-proxy-replacement.md,
// "Architecture") so Cilium's dependency tree never touches the agent module.
//
// Increment 1 (this file): assemble the LB control-plane hive — mirroring
// Cilium's pkg/loadbalancer/repl reference — and attach the committed object.
// The datapath and control plane meet only through the bpffs pin paths of the
// maps the reconciler creates (cilium_lb{4,6}_services_v2, _backends_v3, …), so
// there is no map-ABI coupling in cozyplane's own code.
//
// Do NOT run this alongside full Cilium: both claim the cgroup root and the
// /sys/fs/bpf pin namespace. It targets cozyplane-only clusters; the chart gates
// it off by default.
package main

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// bpfSockObject is the socket-LB datapath, committed and built from the pinned
// Cilium tag by the same workflow that builds datapath/overlay_bpfel.o (see
// kpr/build-bpf.sh). Every per-node knob in bpf_sock.c is a load-time constant
// (.rodata.config), so a single committed object configures at load — cozyplane
// never compiles BPF at runtime.
//
//go:embed bpf_sock.o
var bpfSockObject []byte

func main() {
	h := hive.New(
		// Control plane: Kubernetes client + the Services/EndpointSlices
		// resources and their StateDB tables the LB reconciler consumes.
		client.Cell,
		daemonk8s.ResourcesCell,
		daemonk8s.TablesCell,

		// Load-balancer subsystem support cells.
		maglev.Cell,
		node.LocalNodeStoreCell,
		metrics.Cell,
		lbipamconfig.Cell,
		nodeipamconfig.Cell,

		// loadbalancer.Config is provided by lbcell.Cell itself — do not declare
		// it here or its bpf-lb-* flags register twice.
		cell.Config(envoyCfg.SecretSyncConfig{}),
		cell.Provide(
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
			source.NewSources,
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			// A stubbed DaemonConfig suffices for the LB cell (the repl proves
			// it): the reconciler reads the family gates and little else.
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
			// KubeProxyReplacement forces socket-LB on, exactly as observed
			// live under Cilium KPR (docs/kube-proxy-replacement.md).
			func() kpr.KPRConfig {
				return kpr.KPRConfig{KubeProxyReplacement: true}
			},
		),

		// The load-balancer control plane: watches Services/EndpointSlices,
		// reconciles the pinned service/backend BPF maps via StateDB.
		lbcell.Cell,

		// cozyplane's own socket-LB attach of the committed object at the
		// cgroup root (increment 1). Joins the reconciler by map pin path.
		socketLBCell,
	)

	h.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	logger := defaultLogger()
	// KPR increment 3, Half A (docs/kube-proxy-replacement.md): feed net-0
	// ClusterIPs into the agent's pinned svc_vips map, for clients socket-LB
	// can't rewrite at connect() — a bridge-bound KubeVirt guest. Independent of
	// the LB hive (which drives socket-LB via Cilium's own maps); dies with the
	// process on shutdown.
	pinDir := filepath.Join(defaultSocketLBConfig().BPFFSRoot, "cozyplane")
	go func() {
		if err := runServiceVIPs(context.Background(), pinDir, logger); err != nil {
			logger.Error("svc_vips reconciler exited", "err", err)
		}
	}()

	if err := h.Run(logger); err != nil {
		os.Exit(1)
	}
}
