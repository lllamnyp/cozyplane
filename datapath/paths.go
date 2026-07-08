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
	cfgUplinkIfindex = uint32(2)
	// cfgNodeIP is the node's v4 InternalIP (raw network-order bytes, native
	// read): the Geneve/DNS-steer node handle. Distinct from cfgMasqIP below.
	cfgNodeIP = uint32(3)
	// cfgResolverPort is the node-local split-horizon resolver's port (host
	// order); 0 disables VPC DNS steering. Set alongside SetClusterDNS.
	cfgResolverPort = uint32(4)
	// cfgMasqIP is the cluster-egress masquerade SNAT source — the default-route
	// link's own address, so a masqueraded packet is valid for the interface it
	// leaves by (which is not the InternalIP on a multi-NIC node). 0 disables the
	// bpf masquerade.
	cfgMasqIP = uint32(5)
	// cfgFloatIfindex is the floating uplink — the link whose subnet covers the
	// floating range when it differs from the default-route uplink (e.g. an OCI
	// L2 VLAN). Derived from the FIB per floating address (EnsureFloatingUplink);
	// 0 = floating rides the default uplink (single-NIC).
	cfgFloatIfindex = uint32(6)
	// cfgFloatNH is the v4 next-hop for floating egress out the floating uplink
	// (the L2 fabric's virtual router; raw network-order bytes, native read) —
	// the FIB would route off-subnet destinations via the *default* gateway,
	// whose neighbour is wrong for that link. 0 = resolve via the FIB.
	cfgFloatNH = uint32(7)
)

// ResolverPort is the port the split-horizon resolver binds on the node
// address. Deliberately below the masquerade range (16384+), the NodePort
// range (30000+), and the host ephemeral range (32768+), so no node-originated
// flow toward a pod's fabric IP can carry it as a source port by accident —
// dns_return in bpf/overlay.c keys the reply rewrite on it.
const ResolverPort = 15353

// DefaultVNI is the VNI used for the default (flat) pod network in M0.
const DefaultVNI uint32 = 1

// PortGatewayFlag marks a ports-map entry as a VPC egress-gateway leg: the
// datapath blesses traffic it forwards into the VPC (gateway mark) so the
// destination's anti-spoof admits off-VPC sources arriving through it. Must
// match PORT_F_GATEWAY in bpf/overlay.c.
const PortGatewayFlag uint32 = 1 << 31

// PortNet strips the gateway flag from a ports-map value, yielding the network
// id (the locals/remotes scope). Mirrors PORT_NET in bpf/overlay.c.
func PortNet(v uint32) uint32 { return v &^ PortGatewayFlag }

// QuarantineNet is a reserved network id assigned to a pod's ports-map entry to
// sever it: no VPC CIDR is ever programmed into the networks map with this id
// (so net_of() never returns it) and no peering pair ever includes it (VNIs
// come from VPC status), so the from_pod/to_pod isolation check drops the
// pod's traffic in both directions while its hooks stay attached. Used for
// live revocation (see SeverLocal).
const QuarantineNet uint32 = 0xFFFFFFFF
