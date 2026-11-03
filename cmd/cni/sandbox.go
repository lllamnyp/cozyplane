package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"net"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

func recordPortSandbox(ctx context.Context, client sdnclientset.Interface, port *sdnv1alpha1.Port, containerID, ifName string, primary bool, node string) error {
	if port.Labels[labelVMName] != "" && port.Spec.Node != "" && port.Spec.Node != node {
		return nil // staged target: the active source keeps its identity until cutover
	}
	if port.Annotations[sdnv1alpha1.AnnotationContainerID] == containerID && port.Annotations[sdnv1alpha1.AnnotationCNIIfName] == ifName && port.Annotations[sdnv1alpha1.AnnotationCNIPrimary] == strconv.FormatBool(primary) {
		return nil
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"uid": port.UID, "resourceVersion": port.ResourceVersion, "annotations": map[string]string{sdnv1alpha1.AnnotationContainerID: containerID, sdnv1alpha1.AnnotationCNIIfName: ifName, sdnv1alpha1.AnnotationCNIPrimary: strconv.FormatBool(primary)}}})
	if err != nil {
		return err
	}
	updated, err := client.SdnV1alpha1().Ports().Patch(ctx, port.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err == nil {
		*port = *updated
	}
	return err
}

func portOwnedBySandbox(port *sdnv1alpha1.Port, containerID, ifName string) bool {
	return containerID != "" && ifName != "" && port.Annotations[sdnv1alpha1.AnnotationContainerID] == containerID && port.Annotations[sdnv1alpha1.AnnotationCNIIfName] == ifName
}

func sandboxPortAddress(port *sdnv1alpha1.Port, r resolvedAttachment, state *datapath.AgentState, podNS, podName, podUID string) (net.IP, net.HardwareAddr, error) {
	if !portOwnedBySandbox(port, r.containerID, r.cniIfName) || port.Labels[labelPodUID] != podUID || port.Labels[labelIfName] != r.IfName ||
		port.DeletionTimestamp != nil || port.Spec.Node != state.NodeName || port.Spec.PodNamespace != podNS || port.Spec.PodName != podName ||
		port.Spec.VPCRef.Namespace != r.VPCNamespace || port.Spec.VPCRef.Name != r.vpc.Name {
		return nil, nil, fmt.Errorf("existing sandbox Port %s has conflicting ownership", port.Name)
	}
	address := net.ParseIP(port.Spec.IP)
	if address == nil || ipam.IsPoolReserved(r.cidr, address) || !r.cidr.Contains(address) || (r.IP != nil && !r.IP.Equal(address)) || port.Name != portName(r.vpc.Status.VNI, address.String()) {
		return nil, nil, fmt.Errorf("existing sandbox Port %s has conflicting address", port.Name)
	}
	var mac net.HardwareAddr
	var err error
	if port.Spec.MAC != "" {
		mac, err = net.ParseMAC(port.Spec.MAC)
	}
	if err != nil || (r.MAC != nil && r.MAC.String() != mac.String()) {
		return nil, nil, fmt.Errorf("existing sandbox Port %s has conflicting MAC", port.Name)
	}
	return address, mac, nil
}

// An address can be re-bound during VM migration. Remove the local entry only
// when it still resolves to a veth of the sandbox being deleted.
func delSandboxLocal(netID uint32, ip net.IP, ownIfindices map[int]bool) {
	_ = datapath.DelLocalIfOwned(netID, ip, ownIfindices)
}

func deleteClaimedPort(ctx context.Context, client sdnclientset.Interface, port *sdnv1alpha1.Port) error {
	return client.SdnV1alpha1().Ports().Delete(ctx, port.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &port.UID, ResourceVersion: &port.ResourceVersion}})
}

func releaseSandboxPorts(ctx context.Context, client sdnclientset.Interface, selector, containerID, ifName string, cleanup func(*sdnv1alpha1.Port)) error {
	var owned []sdnv1alpha1.Port
	err := walkPortClaims(ctx, client, selector, func(port *sdnv1alpha1.Port) {
		if portOwnedBySandbox(port, containerID, ifName) {
			owned = append(owned, *port)
		}
	})
	if err != nil {
		return err
	}
	for i := range owned {
		port := &owned[i]
		cleanup(port)
		if port.Labels[labelVMName] != "" {
			continue
		}
		err := client.SdnV1alpha1().Ports().Delete(ctx, port.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &port.UID, ResourceVersion: &port.ResourceVersion}})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// Called inside the pod namespace. A retry may reuse only its actual peer,
// never an unrelated interface which happens to have the requested name.
func setupSandboxVeth(argsContainerID, argsIfName, podIfName, hostName string, mtu int, hostNS ns.NetNS) error {
	link, err := netlink.LinkByName(podIfName)
	if _, missing := err.(netlink.LinkNotFoundError); missing {
		_, _, err = ip.SetupVethWithName(podIfName, hostName, mtu, "", hostNS)
		return err
	}
	if err != nil {
		return err
	}
	veth, ok := link.(*netlink.Veth)
	if !ok {
		return fmt.Errorf("existing interface %s is not a veth", podIfName)
	}
	peer, err := netlink.VethPeerIndex(veth)
	if err != nil {
		return err
	}
	return hostNS.Do(func(ns.NetNS) error {
		host, err := netlink.LinkByName(hostName)
		if err != nil {
			return err
		}
		containerID, ifName := datapath.VethSandbox(host.Attrs().Alias)
		if host.Type() != "veth" || host.Attrs().Index != peer || containerID != argsContainerID || ifName != argsIfName || containerID == "" {
			return fmt.Errorf("existing veth %s does not belong to this sandbox", hostName)
		}
		return nil
	})
}

// The path of a namespace may have been reused since this DEL was queued.
// Prove the live host peer's full sandbox and namespace before deleting a link.
// Namespace-local indexes and interface names alone cannot establish ownership.
func deleteSandboxPodVeth(containerID, ifName, podName string, hostNS, podNS ns.NetNS) ([]*net.IPNet, error) {
	link, err := netlink.LinkByName(podName)
	if _, missing := err.(netlink.LinkNotFoundError); missing {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	veth, ok := link.(*netlink.Veth)
	if !ok || containerID == "" || ifName == "" {
		return nil, nil
	}
	peerIndex, err := netlink.VethPeerIndex(veth)
	if err != nil {
		return nil, err
	}
	owned := false
	err = hostNS.Do(func(ns.NetNS) error {
		peer, err := netlink.LinkByIndex(peerIndex)
		if _, missing := err.(netlink.LinkNotFoundError); missing {
			return nil
		}
		if err != nil {
			return err
		}
		cid, iface := datapath.VethSandbox(peer.Attrs().Alias)
		if peer.Type() != "veth" || cid != containerID || iface != ifName {
			return nil
		}
		nsid, err := netlink.GetNetNsIdByFd(int(podNS.Fd()))
		if err != nil {
			return err
		}
		owned = nsid >= 0 && peer.Attrs().NetNsID == nsid
		return nil
	})
	if err != nil || !owned {
		return nil, err
	}
	addresses, err := netlink.AddrList(veth, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	if err = netlink.LinkDel(veth); err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, address := range addresses {
		if address.IP.IsGlobalUnicast() {
			out = append(out, address.IPNet)
		}
	}
	return out, nil
}
