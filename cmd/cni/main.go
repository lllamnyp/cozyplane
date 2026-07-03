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
// (sdn.cozystack.io/vpc = "[<owner-ns>/]<vpc>"), in any namespace; otherwise it
// joins the default (system) network. VPC attachment is default-deny: a
// VPCBinding in the pod's namespace must authorize the target VPC (the VPC's
// namespace is ownership; a VPCBinding is use). The default network uses
// host-local IPAM; a VPC pod claims an IP via a cluster-scoped Port (atomic by
// name, keyed by VNI). Either way the plugin sets up a Calico-style
// point-to-point veth and attaches the eBPF classifier.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

const (
	contVethName = "eth0"
	// gwVethName is the gateway pod's second interface, carrying the VPC's
	// reserved .1 address (gateway-attach).
	gwVethName = "eth1"
	ipamPlugin = "host-local"
)

// Annotation and label keys come from the API package so the CNI (writer) and
// the controller (reader/reaper) cannot drift.
const (
	vpcAnnotation     = sdnv1alpha1.AnnotationVPC
	gatewayAnnotation = sdnv1alpha1.AnnotationGatewayFor
	labelVPC          = sdnv1alpha1.LabelVPC
	labelVPCNamespace = sdnv1alpha1.LabelVPCNamespace
	labelPodNS        = sdnv1alpha1.LabelPodNamespace
	labelPodName      = sdnv1alpha1.LabelPodName
	labelPodUID       = sdnv1alpha1.LabelPodUID
)

// linkLocalGW is the on-link next hop installed in every pod, answered by the
// host-side veth via proxy_arp (Calico-style point-to-point veth). linkLocalGWv6
// is its IPv6 counterpart for v6 VPC pods, answered via proxy_ndp.
var (
	linkLocalGW   = net.IPv4(169, 254, 1, 1)
	linkLocalGWv6 = net.ParseIP("fe80::1")
)

// isV6 reports whether ip is an IPv6 address (not a v4 or v4-in-v6).
func isV6(ip net.IP) bool { return ip.To4() == nil }

// hostMask returns the host-route mask for ip's family (/32 or /128).
func hostMask(ip net.IP) net.IPMask {
	if isV6(ip) {
		return net.CIDRMask(128, 128)
	}
	return net.CIDRMask(32, 32)
}

// podGateway returns the on-link next hop for a pod IP of ip's family.
func podGateway(ip net.IP) net.IP {
	if isV6(ip) {
		return linkLocalGWv6
	}
	return linkLocalGW
}

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

	// Resolve VPC membership from the pod annotations (best-effort: if the API
	// is unreachable, fall back to the default network).
	vpcAnno, gwAnno := "", ""
	if core, e := coreClient(); e == nil && podNS != "" && podName != "" {
		if pod, e := core.CoreV1().Pods(podNS).Get(context.TODO(), podName, metav1.GetOptions{}); e == nil {
			vpcAnno = pod.Annotations[vpcAnnotation]
			gwAnno = pod.Annotations[gatewayAnnotation]
		}
	}

	if vpcAnno != "" {
		if gwAnno != "" {
			return fmt.Errorf("%s and %s are mutually exclusive: a gateway pod lives on the default network", vpcAnnotation, gatewayAnnotation)
		}
		vpcNS, vpcName := parseVPCRef(vpcAnno, podNS)
		return addVPC(args, conf, vpcNS, vpcName, podNS, podName, podUID)
	}
	result, err := addDefault(args, conf)
	if err != nil {
		return err
	}
	if gwAnno != "" {
		// A gateway pod is a default-network pod with a second leg into the VPC.
		vpcNS, vpcName := parseVPCRef(gwAnno, podNS)
		if err := addGatewayLeg(args, conf, vpcNS, vpcName, podNS, podName, podUID); err != nil {
			return err
		}
	}
	return types.PrintResult(result, conf.CNIVersion)
}

// parseVPCRef splits the vpc annotation value into (owner namespace, name). The
// value is "<vpc>" (owner namespace defaults to the pod's namespace) or
// "<owner-ns>/<vpc>" to reference a VPC owned by another namespace.
func parseVPCRef(anno, podNS string) (ns, name string) {
	if i := strings.IndexByte(anno, '/'); i >= 0 {
		return anno[:i], anno[i+1:]
	}
	return podNS, anno
}

// addDefault attaches the pod to the default/system network with host-local
// IPAM and returns the CNI result (the caller prints it — a gateway pod adds
// its VPC leg first).
func addDefault(args *skel.CmdArgs, conf *NetConf) (result *current.Result, err error) {
	state, err := datapath.LoadAgentState()
	if err != nil {
		return nil, err
	}
	mtu := conf.MTU
	if mtu == 0 {
		mtu = state.MTU
	}

	ipamData, err := ipamStdin(args.StdinData, state.PodCIDR)
	if err != nil {
		return nil, err
	}
	r, err := ipam.ExecAdd(ipamPlugin, ipamData)
	if err != nil {
		return nil, fmt.Errorf("ipam add: %w", err)
	}
	defer func() {
		if err != nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}()

	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return nil, err
	}
	if len(ipamResult.IPs) == 0 {
		return nil, fmt.Errorf("ipam returned no addresses")
	}
	podIP := ipamResult.IPs[0].Address.IP

	result, err = setupVeth(args, conf.CNIVersion, podIP, mtu, 0)
	if err != nil {
		return nil, err
	}
	result.IPs = ipamResult.IPs
	result.IPs[0].Interface = current.Int(0)
	return result, nil
}

// addVPC attaches the pod to a VPC using the dual-address bridge: the pod's
// interface gets the VPC (tenant) IP, while status.podIP is a unique fabric IP
// from the node pod CIDR that the bridge DNATs to the VPC IP.
func addVPC(args *skel.CmdArgs, conf *NetConf, vpcNS, vpcName, podNS, podName, podUID string) (err error) {
	client, err := sdnClient()
	if err != nil {
		return fmt.Errorf("sdn client: %w", err)
	}

	// Authorization (default-deny): a VPCBinding in the pod's namespace must
	// permit attaching to this VPC. Ownership (the VPC's namespace) is not
	// enough — use is granted by a binding even within the owner's namespace.
	if err := requireVPCBinding(client, podNS, vpcNS, vpcName); err != nil {
		return err
	}

	vpc, err := client.SdnV1alpha1().VPCs(vpcNS).Get(context.TODO(), vpcName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get vpc %s/%s: %w", vpcNS, vpcName, err)
	}
	if vpc.Status.VNI == 0 {
		return fmt.Errorf("vpc %s/%s is not ready (no VNI assigned yet)", vpcNS, vpcName)
	}
	if len(vpc.Spec.CIDRs) == 0 {
		return fmt.Errorf("vpc %s/%s has no CIDR", vpcNS, vpcName)
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
	vpcIP, port, err := claimIP(client, vpc, vpcNS, state, fabricIP.String(), podNS, podName, podUID)
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

	// Bridge: route the (unique) fabric IP to this veth and publish the
	// fabric -> {net, VPC IP} mapping; the eBPF datapath does the NAT. The bridge
	// is v4-only (its NAT rewrites IPv4 headers), so a v6 VPC pod skips it — v6
	// north-south is a later phase. Such a pod still gets a v4 fabric IP as its
	// identity/podIP, just no node->pod bridge until the v6 fabric bridge lands.
	if !isV6(vpcIP) {
		if err = datapath.AddBridge(fabricIP.String(), vpcIP.String(), hostVethNameFor(args.ContainerID), uint32(vpc.Status.VNI)); err != nil {
			return err
		}
	}

	// Report the fabric IP as status.podIP.
	result.IPs = []*current.IPConfig{{
		Interface: current.Int(0),
		Address:   net.IPNet{IP: fabricIP, Mask: net.CIDRMask(32, 32)},
	}}
	return types.PrintResult(result, conf.CNIVersion)
}

// addGatewayLeg gives a (default-network) gateway pod a second interface into
// the VPC, carrying the VPC's reserved .1 address. Authorization is by
// placement, not binding: the pod must live in the agent's own (system)
// namespace — where only the cozyplane controller creates pods — and the VPC
// owner must have opted in via spec.egress.natGateway. The .1 Port is claimed
// like any other (atomic by name), marked spec.gateway so agents route off-VPC
// traffic to it.
func addGatewayLeg(args *skel.CmdArgs, conf *NetConf, vpcNS, vpcName, podNS, podName, podUID string) (err error) {
	state, err := datapath.LoadAgentState()
	if err != nil {
		return err
	}
	if state.Namespace == "" || podNS != state.Namespace {
		return fmt.Errorf("gateway-attach is only honored for pods in the system namespace %q, not %q", state.Namespace, podNS)
	}

	client, err := sdnClient()
	if err != nil {
		return fmt.Errorf("sdn client: %w", err)
	}
	vpc, err := client.SdnV1alpha1().VPCs(vpcNS).Get(context.TODO(), vpcName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get vpc %s/%s: %w", vpcNS, vpcName, err)
	}
	if vpc.Spec.Egress == nil || !vpc.Spec.Egress.NATGateway {
		return fmt.Errorf("vpc %s/%s has no egress gateway enabled (spec.egress.natGateway)", vpcNS, vpcName)
	}
	if vpc.Status.VNI == 0 {
		return fmt.Errorf("vpc %s/%s is not ready (no VNI assigned yet)", vpcNS, vpcName)
	}
	if len(vpc.Spec.CIDRs) == 0 {
		return fmt.Errorf("vpc %s/%s has no CIDR", vpcNS, vpcName)
	}
	_, ipnet, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		return fmt.Errorf("parse vpc CIDR: %w", err)
	}
	gwIP := nextIP(cloneIP(ipnet.IP)) // the reserved .1

	// Claim the gateway Port. AlreadyExists means another gateway pod still
	// holds the .1 (e.g. its teardown hasn't run yet); kubelet retries ADD.
	port := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:       portName(vpc.Status.VNI, gwIP.String()),
			Finalizers: []string{sdnv1alpha1.FinalizerSever},
			Labels: map[string]string{
				labelVPCNamespace: vpcNS,
				labelVPC:          vpc.Name,
				labelPodNS:        podNS,
				labelPodName:      podName,
				labelPodUID:       podUID,
			},
		},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef:       sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpc.Name},
			IP:           gwIP.String(),
			Node:         state.NodeName,
			NodeIP:       state.NodeIP,
			PodNamespace: podNS,
			PodName:      podName,
			Gateway:      true,
		},
	}
	created, err := client.SdnV1alpha1().Ports().Create(context.TODO(), port, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("claim gateway port %s: %w", port.Name, err)
	}
	defer func() {
		if err != nil {
			_ = client.SdnV1alpha1().Ports().Delete(context.TODO(), created.Name, metav1.DeleteOptions{})
		}
	}()

	mtu := conf.MTU
	if mtu == 0 {
		mtu = int(vpc.Spec.MTU)
	}
	if mtu == 0 {
		mtu = state.MTU
	}

	hostNS, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("get host netns: %w", err)
	}
	defer hostNS.Close()

	var hostVethName string
	var podMAC net.HardwareAddr
	if err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		hostVeth, _, e := ip.SetupVethWithName(gwVethName, gwHostVethNameFor(args.ContainerID), mtu, "", hostNS)
		if e != nil {
			return e
		}
		hostVethName = hostVeth.Name
		link, e := netlink.LinkByName(gwVethName)
		if e != nil {
			return e
		}
		if e := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: gwIP, Mask: net.CIDRMask(32, 32)}}); e != nil {
			return fmt.Errorf("add gateway address: %w", e)
		}
		if e := netlink.LinkSetUp(link); e != nil {
			return e
		}
		podMAC = link.Attrs().HardwareAddr
		// Route the whole VPC CIDR out this leg via the proxy-arp'd link-local
		// hop (onlink: the hop needs no route of its own — eth0 already claims
		// a 169.254.1.1/32 link route).
		if e := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       ipnet,
			Gw:        linkLocalGW,
			Flags:     int(netlink.FLAG_ONLINK),
		}); e != nil {
			return fmt.Errorf("add VPC route: %w", e)
		}
		// The gateway forwards between its legs.
		for key, val := range map[string]string{
			"net/ipv4/ip_forward":             "1",
			"net/ipv4/conf/all/rp_filter":     "0",
			"net/ipv4/conf/default/rp_filter": "0",
		} {
			if e := datapath.WriteProcSys(key, val); e != nil {
				return fmt.Errorf("set %s in gateway netns: %w", key, e)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Host side is a normal VPC port, flagged as the gateway leg so the
	// datapath blesses the off-VPC sources it forwards inward.
	return configureHostVeth(hostVethName, gwIP, uint32(vpc.Status.VNI)|datapath.PortGatewayFlag, podMAC)
}

// requireVPCBinding implements default-deny attachment: a VPCBinding in the
// pod's namespace must reference the target VPC (owner namespace + name). The
// pod's namespace is trustworthy (kubelet supplies it via CNI_ARGS), so this is
// a pure data-plane check — no caller identity is involved here; the privileged
// decision was made when the binding was created.
func requireVPCBinding(client sdnclientset.Interface, podNS, vpcNS, vpcName string) error {
	list, err := client.SdnV1alpha1().VPCBindings(podNS).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list vpcbindings in %q: %w", podNS, err)
	}
	for i := range list.Items {
		ref := list.Items[i].Spec.VPCRef
		if ref.Namespace == vpcNS && ref.Name == vpcName {
			return nil
		}
	}
	return fmt.Errorf("no VPCBinding in namespace %q authorizes attaching to VPC %s/%s (default-deny)", podNS, vpcNS, vpcName)
}

// claimIP picks a free IP in the VPC CIDR and atomically claims it by creating a
// cluster-scoped Port named v<vni>.<ip-dashed>; concurrent claims collide on the
// name and retry. The VNI is globally unique, so the name is unique even though
// VPC names are only unique within a namespace.
func claimIP(client sdnclientset.Interface, vpc *sdnv1alpha1.VPC, vpcNS string, state *datapath.AgentState, fabricIP, podNS, podName, podUID string) (net.IP, *sdnv1alpha1.Port, error) {
	_, ipnet, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse vpc CIDR: %w", err)
	}

	list, err := client.SdnV1alpha1().Ports().List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelVPCNamespace + "=" + vpcNS + "," + labelVPC + "=" + vpc.Name,
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
				Name: portName(vpc.Status.VNI, ipStr),
				// The sever finalizer makes revocation replayable: deletion
				// completes only after the port's node agent acknowledges.
				Finalizers: []string{sdnv1alpha1.FinalizerSever},
				Labels: map[string]string{
					labelVPCNamespace: vpcNS,
					labelVPC:          vpc.Name,
					labelPodNS:        podNS,
					labelPodName:      podName,
					labelPodUID:       podUID,
				},
			},
			Spec: sdnv1alpha1.PortSpec{
				VPCRef:       sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpc.Name},
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

// portName builds the cluster-scoped Port name v<vni>.<ip-escaped>. Both the v4
// dot and the v6 colon are invalid in a Kubernetes object name, so both are
// escaped to '-' (e.g. 10.0.0.2 -> v5.10-0-0-2, fd00:10::2 -> v5.fd00-10--2).
// Only the VNI is parsed back out (netFromPortName); the address is carried in
// the Port spec, so the escaping need not be reversible, only unique per VNI.
func portName(vni int32, ip string) string {
	esc := strings.NewReplacer(".", "-", ":", "-").Replace(ip)
	return fmt.Sprintf("v%d.%s", vni, esc)
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
	var podMAC net.HardwareAddr
	if err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		hostVeth, _, e := ip.SetupVethWithName(contVethName, hostVethNameFor(args.ContainerID), mtu, "", hostNS)
		if e != nil {
			return e
		}
		hostVethName = hostVeth.Name
		mac, e := configurePodIface(podIP)
		podMAC = mac
		return e
	}); err != nil {
		return nil, err
	}

	if err := configureHostVeth(hostVethName, podIP, netID, podMAC); err != nil {
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
// link-local default route. Runs inside the pod netns. Returns the eth0 MAC so
// the host side can record it for same-node redirect delivery.
func configurePodIface(podIP net.IP) (net.HardwareAddr, error) {
	link, err := netlink.LinkByName(contVethName)
	if err != nil {
		return nil, err
	}
	gw := podGateway(podIP)
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: podIP, Mask: hostMask(podIP)}}
	if isV6(podIP) {
		// Ensure v6 is on inside the pod netns, and skip DAD on the /128: it is a
		// point-to-point veth with no possible duplicate, and DAD would leave the
		// address "tentative" (unusable) for ~1s, racing the pod's first packet.
		_ = datapath.WriteProcSys(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", contVethName), "0")
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, fmt.Errorf("add pod address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	mac := link.Attrs().HardwareAddr
	// A link-scope route to the gateway (its /32 or /128) makes it on-link, then a
	// default route through it. The gateway is never assigned anywhere; the host
	// veth answers for it (proxy_arp for v4, proxy_ndp for v6), Calico-style.
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: gw, Mask: hostMask(gw)},
	}); err != nil {
		return nil, fmt.Errorf("add gateway route: %w", err)
	}
	// A v6 default route through a link-local next hop must name the link.
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw}); err != nil {
		return nil, fmt.Errorf("add default route: %w", err)
	}
	return mac, nil
}

// configureHostVeth brings up the host-side veth, enables proxy_arp and
// forwarding, installs the /32 route (host->local-pod), attaches both classifier
// hooks (from_pod ingress, to_pod egress), and records the pod's network id and
// local endpoint.
func configureHostVeth(name string, podIP net.IP, netID uint32, podMAC net.HardwareAddr) error {
	hv, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(hv); err != nil {
		return err
	}
	sysctls := map[string]string{
		fmt.Sprintf("net/ipv4/conf/%s/proxy_arp", name):  "1",
		fmt.Sprintf("net/ipv4/conf/%s/forwarding", name): "1",
		fmt.Sprintf("net/ipv4/conf/%s/rp_filter", name):  "0",
	}
	if isV6(podIP) {
		// Enable v6 on the host veth so it can own the gateway address below.
		sysctls[fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", name)] = "0"
	}
	for key, val := range sysctls {
		if err := datapath.WriteProcSys(key, val); err != nil {
			return err
		}
	}
	// Give the host veth the pod's on-link gateway (fe80::1) so it answers the
	// pod's NDP natively. Linux NDP *proxy* (proxy_ndp) does not cover link-local
	// targets, so — unlike v4's proxy_arp for 169.254.1.1 — we assign the address
	// outright. It is a distinct link per veth pair, so fe80::1 never collides.
	if isV6(podIP) {
		if err := netlink.AddrAdd(hv, &netlink.Addr{
			IPNet: &net.IPNet{IP: linkLocalGWv6, Mask: net.CIDRMask(64, 64)},
			Flags: unix.IFA_F_NODAD,
		}); err != nil && !isExist(err) {
			return fmt.Errorf("add v6 gateway address on host veth: %w", err)
		}
	}
	// A default-network pod has a unique IP, reached by the host through this
	// main-table host route. VPC pods are delivered by eBPF (same-node redirect,
	// cross-node from_overlay) or, north-south, by the bridge's per-pod table —
	// never by a main-table VPC-IP route, which would collide under overlapping
	// CIDRs. So install the main-table route only for the default network.
	if netID == 0 {
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: hv.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &net.IPNet{IP: podIP, Mask: hostMask(podIP)},
		}); err != nil {
			return fmt.Errorf("add pod host route: %w", err)
		}
	}

	idx := hv.Attrs().Index

	fromPod, err := datapath.OpenPinnedProgram()
	if err != nil {
		return err
	}
	defer fromPod.Close()
	if err := datapath.AttachIngress(idx, fromPod); err != nil {
		return err
	}

	toPod, err := datapath.OpenPinnedToPod()
	if err != nil {
		return err
	}
	defer toPod.Close()
	if err := datapath.AttachEgress(idx, toPod); err != nil {
		return err
	}

	if err := datapath.SetPortNet(idx, netID); err != nil {
		return err
	}
	// Record the local endpoint (keyed by network id, so overlapping VPCs stay
	// distinct) for eBPF-redirect delivery through to_pod.
	return datapath.SetLocal(datapath.PortNet(netID), podIP, idx, podMAC)
}

func cmdDel(args *skel.CmdArgs) error {
	// Clear the ports map entries; the host veths (and their tc filters) go
	// with the pod veths deleted below.
	for _, name := range []string{hostVethNameFor(args.ContainerID), gwHostVethNameFor(args.ContainerID)} {
		if hv, e := netlink.LinkByName(name); e == nil {
			_ = datapath.DelPortNet(hv.Attrs().Index)
			_ = datapath.DetachVeth(hv.Attrs().Index)
		}
	}

	podNS, podName, podUID, _ := podIdentity(args)
	podCIDR := ""
	if state, e := datapath.LoadAgentState(); e == nil {
		podCIDR = state.PodCIDR
	}

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
				// The VPC/gateway-leg local entry is keyed by (net id, VPC IP);
				// net id is the VNI encoded in the Port name.
				if net_, ok := netFromPortName(p.Name); ok {
					_ = datapath.DelLocal(net_, net.ParseIP(p.Spec.IP))
				}
				if p.Spec.FabricIP != "" {
					_ = datapath.DelBridge(p.Spec.FabricIP, hostVethNameFor(args.ContainerID))
				}
				_ = client.SdnV1alpha1().Ports().Delete(context.TODO(), p.Name, metav1.DeleteOptions{})
			}
		}
	}

	// Release default-network IPAM (no-op for VPC pods, which use no host-local).
	if podCIDR != "" {
		if ipamData, e := ipamStdin(args.StdinData, podCIDR); e == nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}

	if args.Netns == "" {
		return nil
	}
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		// The gateway leg's VPC-IP local entry was cleared above via its Port.
		_, _ = ip.DelLinkByNameAddr(gwVethName)
		addrs, e := ip.DelLinkByNameAddr(contVethName)
		if e == ip.ErrLinkNotFound {
			return nil
		}
		// Release the default-network local entry (net 0). VPC/gateway addrs
		// live under their VNI scope and were cleared via their Ports; a net-0
		// delete of a VPC IP is a harmless miss.
		for _, a := range addrs {
			if a.IP != nil {
				_ = datapath.DelLocal(0, a.IP)
			}
		}
		return e
	})
}

// netFromPortName parses the VNI (network id) out of a Port name
// (v<vni>.<ip-dashed>). The name encodes the VNI by construction.
func netFromPortName(name string) (uint32, bool) {
	if len(name) < 2 || name[0] != 'v' {
		return 0, false
	}
	dot := strings.IndexByte(name, '.')
	if dot <= 1 {
		return 0, false
	}
	vni, err := strconv.ParseUint(name[1:dot], 10, 32)
	if err != nil || vni == 0 {
		return 0, false
	}
	return uint32(vni), true
}

func cmdCheck(args *skel.CmdArgs) error { return nil }

func hostVethNameFor(containerID string) string {
	id := containerID
	if len(id) > 11 {
		id = id[:11]
	}
	return "cph" + id
}

// gwHostVethNameFor names the host side of a gateway pod's VPC leg.
func gwHostVethNameFor(containerID string) string {
	id := containerID
	if len(id) > 11 {
		id = id[:11]
	}
	return "cpg" + id
}

func cloneIP(in net.IP) net.IP {
	out := make(net.IP, len(in))
	copy(out, in)
	return out
}

// isExist reports whether err is an "already exists" error (e.g. re-adding a
// proxy neighbour that survived a previous CNI ADD).
func isExist(err error) bool {
	return err != nil && errors.Is(err, syscall.EEXIST)
}

// nextIP returns the IP after ip, incrementing in place on a copy. It works in
// the address's own width — 4 bytes for v4, 16 for v6 — so IPAM walks a v6 CIDR
// the same way it walks a v4 one.
func nextIP(ip net.IP) net.IP {
	// Pick the native width first: To4() is non-nil only for v4. Cloning must
	// happen after the family choice — cloneIP(nil) yields a length-0 slice, not
	// nil, so a `cloneIP(To4())==nil` guard would wrongly keep the empty v4 form.
	base := ip.To4()
	if base == nil {
		base = ip.To16()
	}
	out := cloneIP(base)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}
