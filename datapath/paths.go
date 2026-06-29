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

import "net"

// OverlayMAC is the fixed MAC shared by every node's Geneve device. It must
// match OVERLAY_DMAC in bpf/overlay.c.
var OverlayMAC = net.HardwareAddr{0x02, 0xcf, 0xcf, 0xcf, 0xcf, 0xcf}

const (
	// PinRoot is the bpffs directory where the datapath program and maps are
	// pinned so the agent and the (short-lived) CNI plugin share them.
	PinRoot = "/sys/fs/bpf/cozyplane"

	// progPinName is the pinned name of the from-pod (egress) classifier.
	progPinName = "cozyplane_from_pod"

	// toPodPinName is the pinned name of the to-pod (ingress) classifier.
	toPodPinName = "cozyplane_to_pod"

	// GeneveDevice is the per-node collect_metadata Geneve device.
	GeneveDevice = "cozyplane0"

	// GenevePort is the Geneve UDP destination port (IANA default).
	GenevePort = 6081

	// AgentStateFile is where the agent publishes per-node parameters for the
	// CNI plugin to read (node pod CIDR, MTU, ...).
	AgentStateFile = "/run/cozyplane/agent.json"

	// config map indices — must match bpf/overlay.c.
	cfgGeneveIfindex = uint32(0)
	cfgVNI           = uint32(1)
)

// DefaultVNI is the VNI used for the default (flat) pod network in M0.
const DefaultVNI uint32 = 1

// QuarantineNet is a reserved network id assigned to a pod's ports-map entry to
// sever it: no VPC CIDR is ever programmed into the networks map with this id,
// so net_of() never returns it, and the from_pod/to_pod isolation check
// (srcnet != dstnet) drops the pod's traffic in both directions while its hooks
// stay attached. Used for live revocation (see SeverLocal).
const QuarantineNet uint32 = 0xFFFFFFFF
