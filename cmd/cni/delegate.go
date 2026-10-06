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

package main

import (
	"context"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lllamnyp/cozyplane/datapath"
)

// Multus-delegated attachment: one secondary NIC of a KubeVirt VM
// (docs/kubevirt-multi-nic.md).
//
// The annotation path gives a POD several VPCs. It cannot give a VM several
// VPCs: a guest only sees NICs KubeVirt put in its domain, KubeVirt only
// declares NICs named in spec.networks, and that field admits exactly `pod: {}`
// and `multus: {}`. So for a VM's secondary NIC cozyplane is invoked as a Multus
// delegate — once per NetworkAttachmentDefinition, with the NAD's config on
// stdin and the interface name in CNI_IFNAME.
//
// Nothing about the annotation path changes. What must not happen is the
// delegate falling into it: cmdAdd derives interface names from the annotation
// and rebuilds the WHOLE list, and cmdDel enumerates every index — a delegated
// DEL taking that path would tear down eth0.

// addDelegate realizes exactly one attachment, for the VPC the NAD names, on the
// interface Multus asked for. It is never primary: no fabric IP is claimed, no
// bridge is programmed and no default route is installed, because the pod's one
// fabric handle belongs to the pod network KubeVirt attached first.
func addDelegate(ctx context.Context, args *skel.CmdArgs, conf *NetConf,
	networksAnno, podNS, podName, podUID, vmName, podLabels string) (err error) {
	a, err := delegateAttachment(conf.VPC, args.IfName, networksAnno, podNS)
	if err != nil {
		return err
	}

	client, err := sdnClient()
	if err != nil {
		return fmt.Errorf("sdn client: %w", err)
	}
	state, err := datapath.LoadAgentState()
	if err != nil {
		return err
	}

	// Authorization is the SAME gate as the annotation path, and that is the
	// point: a NetworkAttachmentDefinition names a VPC, it does not grant one. A
	// hand-written NAD pointing at another tenant's VPC gets nothing, because the
	// VPCBinding in the POD's namespace still has to permit the attachment.
	forwarding, fwdCIDRs, err := requireVPCBinding(ctx, client, podNS, a.VPCNamespace, a.VPCName)
	if err != nil {
		return err
	}
	vpc, err := client.SdnV1alpha1().VPCs(a.VPCNamespace).Get(ctx, a.VPCName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get vpc %s/%s: %w", a.VPCNamespace, a.VPCName, err)
	}
	if vpc.Status.VNI == 0 {
		return fmt.Errorf("vpc %s/%s is not ready (no VNI assigned yet)", a.VPCNamespace, a.VPCName)
	}
	if len(vpc.Spec.CIDRs) == 0 {
		return fmt.Errorf("vpc %s/%s has no CIDR", a.VPCNamespace, a.VPCName)
	}
	_, cidr, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		return fmt.Errorf("vpc %s/%s CIDR: %w", a.VPCNamespace, a.VPCName, err)
	}
	r := resolvedAttachment{attachment: a, vpc: vpc, cidr: cidr, forwarding: forwarding, forwardingCIDRs: fwdCIDRs}

	hostVeth, err := hostVethNameForDelegate(args.ContainerID, args.IfName)
	if err != nil {
		return err
	}

	vpcIP, pinnedMAC, port, bound, err := attachPort(ctx, client, r, state, podNS, podName, podUID, vmName, podLabels)
	if err != nil {
		return err
	}
	defer func() {
		// A bound (persistent VM) Port outlives its pod by design and is never
		// ours to delete; one we claimed must not survive a failed ADD.
		if err != nil && !bound {
			cctx, ccancel := cleanupContext(ctx)
			defer ccancel()
			_ = client.SdnV1alpha1().Ports().Delete(cctx, port.Name, metav1.DeleteOptions{})
		}
	}()

	mtu := conf.MTU
	if mtu == 0 {
		mtu = int(vpc.Spec.MTU)
	}
	if mtu == 0 {
		mtu = state.MTU
	}

	netID := uint32(vpc.Status.VNI)
	if forwarding {
		netID |= datapath.PortForwardFlag
		if len(fwdCIDRs) > 0 {
			netID |= datapath.PortForwardScopedFlag
		}
	}
	podMAC, err := setupAttachment(args, r, hostVeth, vpcIP, pinnedMAC, mtu, netID)
	if err != nil {
		return err
	}

	// Staged locals (live-migration overlap window), same rule as the annotation
	// path: while the VM is still ACTIVE elsewhere, local delivery must keep
	// following the active location or a co-located client lands in the
	// not-yet-running VM.
	if bound && port.Spec.Node != "" && port.Spec.Node != state.NodeName {
		if err = datapath.DelLocal(uint32(vpc.Status.VNI), vpcIP); err != nil {
			return err
		}
	}

	// A delegate reports its OWN interface and address — Multus checks the name
	// and folds the result into the pod's network-status. The fabric IP is not
	// ours to report: it belongs to the primary invocation, which owns
	// status.podIP.
	result := &current.Result{
		CNIVersion: conf.CNIVersion,
		Interfaces: []*current.Interface{{
			Name: r.IfName, Sandbox: args.Netns, Mac: podMAC.String(),
		}},
		IPs: []*current.IPConfig{{
			Interface: current.Int(0),
			Address:   net.IPNet{IP: vpcIP, Mask: hostMask(vpcIP)},
		}},
	}
	return types.PrintResult(result, conf.CNIVersion)
}

// delDelegate tears down exactly one delegated attachment.
//
// Only its own interface and only its own Port. The annotation path's DEL
// enumerates a whole name space and releases the pod's FabricIP claims; running
// that for a secondary NIC would take the primary — and the pod's underlay
// identity — with it.
func delDelegate(ctx context.Context, args *skel.CmdArgs, conf *NetConf) error {
	hostVeth, err := hostVethNameForDelegate(args.ContainerID, args.IfName)
	if err != nil {
		// A DEL that cannot name its link has nothing to undo, and failing here
		// would wedge sandbox teardown. Report and let the pod go.
		return nil
	}

	if hv, e := netlink.LinkByName(hostVeth); e == nil {
		_ = datapath.DelPortNet(hv.Attrs().Index)
		_ = datapath.DetachVeth(hv.Attrs().Index)
		// Delete the pair, unlike the annotation path — there, the links go with
		// the pod netns kubelet is tearing down anyway. A delegate can be DELed
		// while the sandbox lives (Multus detaching one network, or an ADD retry
		// after a partial failure), and leaving the interface would make the
		// retry fail on a name that already exists.
		_ = netlink.LinkDel(hv)
	}

	podNS, podName, podUID, _ := podIdentity(args)
	if podUID == "" && (podNS == "" || podName == "") {
		return nil
	}
	client, e := sdnClient()
	if e != nil {
		return nil
	}

	// Select this pod's Port for THIS interface. By UID where we have it, so a
	// stale DEL cannot reap a newer pod's Port, and by interface name rather than
	// by VPC: a VM holding two NICs on one VPC has two Ports, and releasing the
	// wrong one would free an address whose interface is still up.
	selector := fmt.Sprintf("%s=%s,%s=%s", labelPodNS, podNS, labelPodName, podName)
	if podUID != "" {
		selector = labelPodUID + "=" + podUID
	}
	selector += "," + labelIfName + "=" + args.IfName
	list, e := client.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{LabelSelector: selector})
	if e != nil {
		return nil
	}
	for i := range list.Items {
		p := &list.Items[i]
		if net_, ok := netFromPortName(p.Name); ok {
			_ = datapath.DelLocal(net_, net.ParseIP(p.Spec.IP))
		}
		// A persistent (VM NIC) Port outlives its pod so the VPC IP + MAC survive
		// pod churn and live migration; the persistent-Port controller GCs it
		// once the VM is gone.
		if p.Labels[labelVMName] != "" {
			continue
		}
		_ = client.SdnV1alpha1().Ports().Delete(ctx, p.Name, metav1.DeleteOptions{})
	}
	return nil
}
