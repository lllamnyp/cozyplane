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

// Command cozyplane is the CNI plugin. A pod attaches to a VPC by annotation
// (sdn.cozystack.io/vpc), in any namespace; otherwise it joins the default
// (system) network. The default network uses host-local IPAM; a VPC pod claims
// an IP via a cluster-scoped Port (atomic by name). Either way the plugin sets
// up a Calico-style point-to-point veth and attaches the eBPF classifier.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

const (
	contVethName  = "eth0"
	ipamPlugin    = "host-local"
	vpcAnnotation = "sdn.cozystack.io/vpc"
	labelVPC      = "sdn.cozystack.io/vpc"
	labelPodNS    = "sdn.cozystack.io/pod-namespace"
	labelPodName  = "sdn.cozystack.io/pod-name"
	labelPodUID   = "sdn.cozystack.io/pod-uid"
)

// linkLocalGW is the on-link next hop installed in every pod, answered by the
// host-side veth via proxy_arp (Calico-style point-to-point veth).
var linkLocalGW = net.IPv4(169, 254, 1, 1)

// NetConf is the plugin configuration.
type NetConf struct {
	types.NetConf
	MTU int `json:"mtu,omitempty"`
}

// k8sArgs are the Kubernetes-specific CNI_ARGS passed by kubelet.
type k8sArgs struct {
	types.CommonArgs
	K8S_POD_NAMESPACE types.UnmarshallableString //nolint:revive,stylecheck
	K8S_POD_NAME      types.UnmarshallableString //nolint:revive,stylecheck
	K8S_POD_UID       types.UnmarshallableString //nolint:revive,stylecheck
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, "cozyplane CNI")
}

func loadConf(stdin []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, fmt.Errorf("parse network config: %w", err)
	}
	return conf, nil
}

func podIdentity(args *skel.CmdArgs) (namespace, name, uid string, err error) {
	k8s := k8sArgs{}
	if err := types.LoadArgs(args.Args, &k8s); err != nil {
		return "", "", "", err
	}
	return string(k8s.K8S_POD_NAMESPACE), string(k8s.K8S_POD_NAME), string(k8s.K8S_POD_UID), nil
}

func sdnClient() (sdnclientset.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", datapath.PluginKubeconfig)
	if err != nil {
		return nil, err
	}
	return sdnclientset.NewForConfig(cfg)
}

func coreClient() (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", datapath.PluginKubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	podNS, podName, podUID, err := podIdentity(args)
	if err != nil {
		return err
	}

	// Resolve VPC membership from the pod annotation (best-effort: if the API
	// is unreachable, fall back to the default network).
	vpcName := ""
	if core, e := coreClient(); e == nil && podNS != "" && podName != "" {
		if pod, e := core.CoreV1().Pods(podNS).Get(context.TODO(), podName, metav1.GetOptions{}); e == nil {
			vpcName = pod.Annotations[vpcAnnotation]
		}
	}

	if vpcName == "" {
		return addDefault(args, conf)
	}
	return addVPC(args, conf, vpcName, podNS, podName, podUID)
}

// addDefault attaches the pod to the default/system network with host-local IPAM.
func addDefault(args *skel.CmdArgs, conf *NetConf) error {
	state, err := datapath.LoadAgentState()
	if err != nil {
		return err
	}
	mtu := conf.MTU
	if mtu == 0 {
		mtu = state.MTU
	}

	ipamData, err := ipamStdin(args.StdinData, state.PodCIDR)
	if err != nil {
		return err
	}
	r, err := ipam.ExecAdd(ipamPlugin, ipamData)
	if err != nil {
		return fmt.Errorf("ipam add: %w", err)
	}
	defer func() {
		if err != nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}()

	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}
	if len(ipamResult.IPs) == 0 {
		return fmt.Errorf("ipam returned no addresses")
	}
	podIP := ipamResult.IPs[0].Address.IP

	result, err := setupVeth(args, conf.CNIVersion, podIP, mtu, 0)
	if err != nil {
		return err
	}
	result.IPs = ipamResult.IPs
	result.IPs[0].Interface = current.Int(0)
	return types.PrintResult(result, conf.CNIVersion)
}

// addVPC attaches the pod to a VPC using the dual-address bridge: the pod's
// interface gets the VPC (tenant) IP, while status.podIP is a unique fabric IP
// from the node pod CIDR that the bridge DNATs to the VPC IP.
func addVPC(args *skel.CmdArgs, conf *NetConf, vpcName, podNS, podName, podUID string) (err error) {
	client, err := sdnClient()
	if err != nil {
		return fmt.Errorf("sdn client: %w", err)
	}
	vpc, err := client.SdnV1alpha1().VPCs().Get(context.TODO(), vpcName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get vpc %q: %w", vpcName, err)
	}
	if vpc.Status.VNI == 0 {
		return fmt.Errorf("vpc %q is not ready (no VNI assigned yet)", vpcName)
	}
	if len(vpc.Spec.CIDRs) == 0 {
		return fmt.Errorf("vpc %q has no CIDR", vpcName)
	}

	state, err := datapath.LoadAgentState()
	if err != nil {
		return err
	}
	mtu := conf.MTU
	if mtu == 0 {
		mtu = int(vpc.Spec.MTU)
	}
	if mtu == 0 {
		mtu = state.MTU
	}

	// Fabric IP (status.podIP): host-local from the node pod CIDR, unique and
	// reachable on the default overlay.
	ipamData, err := ipamStdin(args.StdinData, state.PodCIDR)
	if err != nil {
		return err
	}
	r, err := ipam.ExecAdd(ipamPlugin, ipamData)
	if err != nil {
		return fmt.Errorf("fabric ipam add: %w", err)
	}
	defer func() {
		if err != nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}()
	fabricRes, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}
	if len(fabricRes.IPs) == 0 {
		return fmt.Errorf("fabric ipam returned no addresses")
	}
	fabricIP := fabricRes.IPs[0].Address.IP

	// VPC IP: atomic claim via a Port.
	vpcIP, port, err := claimIP(client, vpc, state, fabricIP.String(), podNS, podName, podUID)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = client.SdnV1alpha1().Ports().Delete(context.TODO(), port.Name, metav1.DeleteOptions{})
		}
	}()

	// The pod interface carries the VPC IP; tag the veth with the VPC net id.
	result, err := setupVeth(args, conf.CNIVersion, vpcIP, mtu, uint32(vpc.Status.VNI))
	if err != nil {
		return err
	}

	// Bridge: fabric IP -> VPC IP, source masqueraded to the gateway.
	if err = datapath.AddBridge(fabricIP.String(), vpcIP.String(), hostVethNameFor(args.ContainerID)); err != nil {
		return err
	}

	// Report the fabric IP as status.podIP.
	result.IPs = []*current.IPConfig{{
		Interface: current.Int(0),
		Address:   net.IPNet{IP: fabricIP, Mask: net.CIDRMask(32, 32)},
	}}
	return types.PrintResult(result, conf.CNIVersion)
}

// claimIP picks a free IP in the VPC CIDR and atomically claims it by creating a
// cluster-scoped Port named <vpc>.<ip-dashed>; concurrent claims collide on the
// name and retry.
func claimIP(client sdnclientset.Interface, vpc *sdnv1alpha1.VPC, state *datapath.AgentState, fabricIP, podNS, podName, podUID string) (net.IP, *sdnv1alpha1.Port, error) {
	_, ipnet, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse vpc CIDR: %w", err)
	}

	list, err := client.SdnV1alpha1().Ports().List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelVPC + "=" + vpc.Name,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list ports: %w", err)
	}
	used := map[string]bool{}
	for i := range list.Items {
		used[list.Items[i].Spec.IP] = true
	}

	// Start at network+2 (reserve .0 network and .1 for a future gateway).
	candidate := nextIP(nextIP(cloneIP(ipnet.IP)))
	for ipnet.Contains(candidate) {
		ipStr := candidate.String()
		if used[ipStr] {
			candidate = nextIP(candidate)
			continue
		}
		port := &sdnv1alpha1.Port{
			ObjectMeta: metav1.ObjectMeta{
				Name: portName(vpc.Name, ipStr),
				Labels: map[string]string{
					labelVPC:     vpc.Name,
					labelPodNS:   podNS,
					labelPodName: podName,
					labelPodUID:  podUID,
				},
			},
			Spec: sdnv1alpha1.PortSpec{
				VPC:          vpc.Name,
				IP:           ipStr,
				FabricIP:     fabricIP,
				Node:         state.NodeName,
				NodeIP:       state.NodeIP,
				PodNamespace: podNS,
				PodName:      podName,
			},
		}
		created, err := client.SdnV1alpha1().Ports().Create(context.TODO(), port, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			used[ipStr] = true
			candidate = nextIP(candidate)
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("create port: %w", err)
		}
		return candidate, created, nil
	}
	return nil, nil, fmt.Errorf("no free address in VPC %q (%s)", vpc.Name, vpc.Spec.CIDRs[0])
}

func portName(vpc, ip string) string {
	return vpc + "." + strings.ReplaceAll(ip, ".", "-")
}

// setupVeth creates the pod veth, configures the pod-side address and routes,
// configures the host side, and attaches the classifier with the given net id.
func setupVeth(args *skel.CmdArgs, cniVersion string, podIP net.IP, mtu int, netID uint32) (*current.Result, error) {
	hostNS, err := ns.GetCurrentNS()
	if err != nil {
		return nil, fmt.Errorf("get host netns: %w", err)
	}
	defer hostNS.Close()

	var hostVethName string
	if err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		hostVeth, _, e := ip.SetupVethWithName(contVethName, hostVethNameFor(args.ContainerID), mtu, "", hostNS)
		if e != nil {
			return e
		}
		hostVethName = hostVeth.Name
		return configurePodIface(podIP)
	}); err != nil {
		return nil, err
	}

	if err := configureHostVeth(hostVethName, podIP, netID); err != nil {
		return nil, err
	}

	return &current.Result{
		CNIVersion: cniVersion,
		Interfaces: []*current.Interface{{Name: contVethName, Sandbox: args.Netns}},
	}, nil
}

// ipamStdin rewrites the plugin config so host-local allocates from the node pod CIDR.
func ipamStdin(stdin []byte, podCIDR string) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(stdin, &raw); err != nil {
		return nil, err
	}
	raw["ipam"] = map[string]interface{}{
		"type":   ipamPlugin,
		"ranges": [][]map[string]string{{{"subnet": podCIDR}}},
	}
	return json.Marshal(raw)
}

// configurePodIface sets the pod's eth0 address, brings it up, and installs the
// link-local default route. Runs inside the pod netns.
func configurePodIface(podIP net.IP) error {
	link, err := netlink.LinkByName(contVethName)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)}}); err != nil {
		return fmt.Errorf("add pod address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: linkLocalGW, Mask: net.CIDRMask(32, 32)},
	}); err != nil {
		return fmt.Errorf("add gateway route: %w", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: linkLocalGW}); err != nil {
		return fmt.Errorf("add default route: %w", err)
	}
	return nil
}

// configureHostVeth brings up the host-side veth, enables proxy_arp and
// forwarding, installs the /32 route, attaches the classifier, and records the
// pod's network id.
func configureHostVeth(name string, podIP net.IP, netID uint32) error {
	hv, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(hv); err != nil {
		return err
	}
	for key, val := range map[string]string{
		fmt.Sprintf("net/ipv4/conf/%s/proxy_arp", name):  "1",
		fmt.Sprintf("net/ipv4/conf/%s/forwarding", name): "1",
		fmt.Sprintf("net/ipv4/conf/%s/rp_filter", name):  "0",
	} {
		if err := datapath.WriteProcSys(key, val); err != nil {
			return err
		}
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: hv.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)},
	}); err != nil {
		return fmt.Errorf("add pod /32 route: %w", err)
	}

	prog, err := datapath.OpenPinnedProgram()
	if err != nil {
		return err
	}
	defer prog.Close()
	if err := datapath.AttachIngress(hv.Attrs().Index, prog); err != nil {
		return err
	}
	return datapath.SetPortNet(hv.Attrs().Index, netID)
}

func cmdDel(args *skel.CmdArgs) error {
	// Clear the ports map entry; the host veth (and its tc filter) goes with the
	// pod veth deleted below.
	if hv, e := netlink.LinkByName(hostVethNameFor(args.ContainerID)); e == nil {
		_ = datapath.DelPortNet(hv.Attrs().Index)
		_ = datapath.DetachVeth(hv.Attrs().Index)
	}

	podNS, podName, podUID, _ := podIdentity(args)

	// Release a VPC Port if this pod had one. Prefer the pod UID (unique, never
	// reused) so a stale DEL can't delete a newer pod's Port that reuses a name.
	selector := fmt.Sprintf("%s=%s,%s=%s", labelPodNS, podNS, labelPodName, podName)
	if podUID != "" {
		selector = labelPodUID + "=" + podUID
	}
	if client, e := sdnClient(); e == nil && (podUID != "" || (podNS != "" && podName != "")) {
		if list, e := client.SdnV1alpha1().Ports().List(context.TODO(), metav1.ListOptions{
			LabelSelector: selector,
		}); e == nil {
			for i := range list.Items {
				p := &list.Items[i]
				if p.Spec.FabricIP != "" {
					_ = datapath.DelBridge(p.Spec.FabricIP, p.Spec.IP, hostVethNameFor(args.ContainerID))
				}
				_ = client.SdnV1alpha1().Ports().Delete(context.TODO(), p.Name, metav1.DeleteOptions{})
			}
		}
	}

	// Release default-network IPAM (no-op for VPC pods, which use no host-local).
	if state, e := datapath.LoadAgentState(); e == nil {
		if ipamData, e := ipamStdin(args.StdinData, state.PodCIDR); e == nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}

	if args.Netns == "" {
		return nil
	}
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		_, e := ip.DelLinkByNameAddr(contVethName)
		if e == ip.ErrLinkNotFound {
			return nil
		}
		return e
	})
}

func cmdCheck(args *skel.CmdArgs) error { return nil }

func hostVethNameFor(containerID string) string {
	id := containerID
	if len(id) > 11 {
		id = id[:11]
	}
	return "cph" + id
}

func cloneIP(in net.IP) net.IP {
	out := make(net.IP, len(in))
	copy(out, in)
	return out
}

// nextIP returns the IP after ip (IPv4), incrementing in place on a copy.
func nextIP(ip net.IP) net.IP {
	out := cloneIP(ip.To4())
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}
