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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

const (
	contVethName = "eth0"
	// gwVethName is the gateway pod's second interface, carrying the VPC's
	// reserved .1 address (gateway-attach).
	gwVethName = "eth1"
)

// Annotation and label keys come from the API package so the CNI (writer) and
// the controller (reader/reaper) cannot drift.
const (
	vpcAnnotation      = sdnv1alpha1.AnnotationVPC
	networksAnnotation = sdnv1alpha1.AnnotationNetworks
	gatewayAnnotation  = sdnv1alpha1.AnnotationGatewayFor
	labelVPC           = sdnv1alpha1.LabelVPC
	labelVPCNamespace  = sdnv1alpha1.LabelVPCNamespace
	labelPodNS         = sdnv1alpha1.LabelPodNamespace
	labelPodName       = sdnv1alpha1.LabelPodName
	labelPodUID        = sdnv1alpha1.LabelPodUID
	labelVMName        = sdnv1alpha1.LabelVMName
	labelVMNIC         = sdnv1alpha1.LabelVMNIC
	labelIfName        = sdnv1alpha1.LabelIfName
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

// cidrIsV6 reports whether a CIDR string is IPv6.
func cidrIsV6(cidr string) (bool, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	return isV6(ip), nil
}

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

	// VPC, when set, means this invocation is a MULTUS DELEGATE: the value comes
	// from a NetworkAttachmentDefinition naming one VPC ("[<owner-ns>/]<name>"),
	// and cozyplane must realize exactly that one attachment on CNI_IFNAME rather
	// than reading the pod's annotation list (docs/kubevirt-multi-nic.md).
	//
	// The cluster conflist the agent writes never carries it, so the primary
	// invocation is unaffected. It is not a grant either — the VPCBinding in the
	// pod's namespace still decides whether the attachment is permitted.
	VPC string `json:"vpc,omitempty"`
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

// The plugin runs inside kubelet's pod-sandbox call, so every API round trip
// it makes is time the pod spends in ContainerCreating. Left unbounded — which
// is what context.TODO() and a default rest.Config mean — an unreachable or
// wedged apiserver hangs CNI ADD until the container runtime gives up on the
// whole sandbox, and the failure surfaces as an opaque runtime timeout rather
// than "cozyplane could not reach the API".
//
// Two bounds, because one is not enough: apiRequestTimeout caps a single round
// trip (rest.Config.Timeout, so it covers every client-go call, retries
// included), and opTimeout caps the whole ADD/DEL, so a long tail of
// individually-timely calls cannot add up past the runtime's patience either.
const (
	apiRequestTimeout = 10 * time.Second
	opTimeout         = 30 * time.Second
	cleanupTimeout    = 5 * time.Second
)

// operationContext bounds one CNI invocation's API work.
func operationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

// cleanupContext derives a short-lived context for rollback work — releasing a
// Port or a FabricIP claim after a failed ADD. It deliberately drops the
// parent's cancellation (context.WithoutCancel): the commonest reason we are
// rolling back is that the operation context EXPIRED, and reusing it would fail
// the release instantly and leak the very claim the rollback exists to return.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func sdnClient() (sdnclientset.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", datapath.PluginKubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.Timeout = apiRequestTimeout
	return sdnclientset.NewForConfig(cfg)
}

func coreClient() (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", datapath.PluginKubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.Timeout = apiRequestTimeout
	return kubernetes.NewForConfig(cfg)
}

func cmdAdd(args *skel.CmdArgs) error {
	ctx, cancel := operationContext()
	defer cancel()

	conf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	podNS, podName, podUID, err := podIdentity(args)
	if err != nil {
		return err
	}

	// Resolve VPC membership from the pod annotations (best-effort: if the API
	// is unreachable, fall back to the default network). A virt-launcher pod also
	// carries its VM name, which keys the persistent Port (VPC IP + MAC that
	// survive live migration).
	vpcAnno, networksAnno, gwAnno, vmName, podLabels := "", "", "", "", ""
	if core, e := coreClient(); e == nil && podNS != "" && podName != "" {
		if pod, e := core.CoreV1().Pods(podNS).Get(ctx, podName, metav1.GetOptions{}); e == nil {
			vpcAnno = pod.Annotations[vpcAnnotation]
			networksAnno = pod.Annotations[networksAnnotation]
			gwAnno = pod.Annotations[gatewayAnnotation]
			vmName = pod.Labels[sdnv1alpha1.KubeVirtLabelVMName]
			// Snapshot the pod's labels for SecurityGroup membership: the
			// controller resolves Port.status.groups from this claim-time copy.
			if len(pod.Labels) > 0 {
				if b, e := json.Marshal(pod.Labels); e == nil {
					podLabels = string(b)
				}
			}
		}
	}

	// A Multus delegate realizes ONE named VPC on CNI_IFNAME. It must not fall
	// into the annotation path, which derives its own interface names and builds
	// the whole list (docs/kubevirt-multi-nic.md).
	if conf.VPC != "" {
		if gwAnno != "" {
			return fmt.Errorf("%s and a delegated vpc are mutually exclusive: a gateway pod lives on the default network", gatewayAnnotation)
		}
		return addDelegate(ctx, args, conf, networksAnno, podNS, podName, podUID, vmName, podLabels)
	}

	atts, err := parseAttachments(vpcAnno, networksAnno, podNS)
	if err != nil {
		return err
	}
	if len(atts) > 0 {
		if gwAnno != "" {
			return fmt.Errorf("%s and %s are mutually exclusive: a gateway pod lives on the default network", vpcAnnotation, gatewayAnnotation)
		}
		return addVPCs(ctx, args, conf, atts, podNS, podName, podUID, vmName, podLabels)
	}
	result, err := addDefault(ctx, args, conf)
	if err != nil {
		return err
	}
	if gwAnno != "" {
		// A gateway pod is a default-network pod with a second leg into the VPC.
		vpcNS, vpcName := parseVPCRef(gwAnno, podNS)
		if err := addGatewayLeg(ctx, args, conf, vpcNS, vpcName, podNS, podName, podUID); err != nil {
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
func addDefault(ctx context.Context, args *skel.CmdArgs, conf *NetConf) (result *current.Result, err error) {
	state, err := datapath.LoadAgentState()
	if err != nil {
		return nil, err
	}
	mtu := conf.MTU
	if mtu == 0 {
		mtu = state.MTU
	}

	podNS, podName, podUID, err := podIdentity(args)
	if err != nil {
		return nil, err
	}
	lc, err := localClient()
	if err != nil {
		return nil, err
	}

	// Dual-stack: one address per pool (a v4 and, dual-stack, a v6), drawn from
	// the FLAT cluster-wide pool — a pod's address has nothing to do with which
	// node it landed on. The claim is a FabricIP object: atomic by name,
	// GC-able by the controller (docs/api-groups.md).
	podIPs, err := claimFabricIPs(ctx, lc, poolFor(state), state.NodeName, podNS, podName, podUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			// Surface a failed release in the ADD error itself: it becomes the
			// FailedCreatePodSandBox event, which is the only place an operator
			// would ever see that kubelet's retries are burning addresses.
			cctx, ccancel := cleanupContext(ctx)
			defer ccancel()
			if rerr := releaseFabricIPs(cctx, lc, podUID); rerr != nil {
				err = fmt.Errorf("%w (releasing the fabric IP claim also failed: %v — "+
					"the address leaks until the pod is deleted)", err, rerr)
			}
		}
	}()

	result, _, err = setupVeth(args, conf.CNIVersion, podIPs, nil, mtu, 0)
	if err != nil {
		return nil, err
	}
	result.IPs = make([]*current.IPConfig, 0, len(podIPs))
	for _, ip := range podIPs {
		result.IPs = append(result.IPs, &current.IPConfig{
			Address:   *hostIPNet(ip),
			Interface: current.Int(0),
		})
	}
	return result, nil
}

// hostIPNet is the /32 (or /128) form of an address — a pod's fabric address is
// a host route on the node, never a subnet, now that the pool is not carved up.
func hostIPNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// resolvedAttachment is an attachment with its VPC, its CIDR and its forwarding
// grant resolved — everything needed to realize it without another API read.
type resolvedAttachment struct {
	attachment
	vpc  *sdnv1alpha1.VPC
	cidr *net.IPNet
	// forwarding is the VPCBinding's allowForwarding grant. It becomes
	// PORT_F_FORWARD on this veth, which lifts from_pod's source RPF check —
	// see docs/multi-attach.md for why that is the VPC owner's call.
	forwarding bool
	// forwardingCIDRs bounds a SCOPED grant (issue #6): non-nil means the leg
	// admits a foreign source only within these prefixes (PORT_F_FWD_SCOPED +
	// the fwd_cidrs allowlist); nil means the legacy blanket grant.
	forwardingCIDRs []string
}

// addVPCs attaches the pod to every VPC it asked for, using the dual-address
// bridge: each interface gets a VPC (tenant) IP, while status.podIP is a unique
// fabric IP from the cluster pool that the bridge DNATs to the PRIMARY
// attachment's VPC IP (docs/multi-attach.md).
//
// One fabric handle per pod, not one per attachment: it is the underlay identity
// of the WORKLOAD, and kubelet probes exactly one address. Entry 0 owns it.
func addVPCs(ctx context.Context, args *skel.CmdArgs, conf *NetConf, atts []attachment,
	podNS, podName, podUID, vmName, podLabels string) (err error) {
	client, err := sdnClient()
	if err != nil {
		return fmt.Errorf("sdn client: %w", err)
	}
	state, err := datapath.LoadAgentState()
	if err != nil {
		return err
	}

	// Resolve EVERY attachment before realizing any of it. A pod naming two VPCs,
	// one of which it may not use, must fail with nothing built — not with one
	// interface up and a Port claimed.
	resolved := make([]resolvedAttachment, 0, len(atts))
	for _, a := range atts {
		// Authorization (default-deny): a VPCBinding in the POD's namespace must
		// permit attaching to this VPC. Ownership (the VPC's namespace) is not
		// enough — use is granted by a binding even within the owner's namespace.
		forwarding, fwdCIDRs, e := requireVPCBinding(ctx, client, podNS, a.VPCNamespace, a.VPCName)
		if e != nil {
			return e
		}
		vpc, e := client.SdnV1alpha1().VPCs(a.VPCNamespace).Get(ctx, a.VPCName, metav1.GetOptions{})
		if e != nil {
			return fmt.Errorf("get vpc %s/%s: %w", a.VPCNamespace, a.VPCName, e)
		}
		if vpc.Status.VNI == 0 {
			return fmt.Errorf("vpc %s/%s is not ready (no VNI assigned yet)", a.VPCNamespace, a.VPCName)
		}
		if len(vpc.Spec.CIDRs) == 0 {
			return fmt.Errorf("vpc %s/%s has no CIDR", a.VPCNamespace, a.VPCName)
		}
		_, cidr, e := net.ParseCIDR(vpc.Spec.CIDRs[0])
		if e != nil {
			return fmt.Errorf("vpc %s/%s CIDR: %w", a.VPCNamespace, a.VPCName, e)
		}
		resolved = append(resolved, resolvedAttachment{attachment: a, vpc: vpc, cidr: cidr, forwarding: forwarding, forwardingCIDRs: fwdCIDRs})
	}
	primary := resolved[0]

	mtu := conf.MTU
	if mtu == 0 {
		mtu = int(primary.vpc.Spec.MTU)
	}
	if mtu == 0 {
		mtu = state.MTU
	}

	// Fabric IP (status.podIP): the pod's underlay identity, claimed as a
	// FabricIP exactly like a default-network pod's — the underlay address is
	// the LOCAL layer's business, not the tenant plane's (docs/api-groups.md).
	// Its family follows the PRIMARY VPC's; poolOfFamily falls back to whichever
	// family the cluster has, since the fabric IP is only the underlay handle.
	wantV6, err := cidrIsV6(primary.vpc.Spec.CIDRs[0])
	if err != nil {
		return fmt.Errorf("vpc CIDR: %w", err)
	}
	lc, err := localClient()
	if err != nil {
		return err
	}
	fabricIPs, err := claimFabricIPs(ctx, lc, poolOfFamily(poolFor(state), wantV6),
		state.NodeName, podNS, podName, podUID)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			// Surface a failed release in the ADD error itself: it becomes the
			// FailedCreatePodSandBox event, which is the only place an operator
			// would ever see that kubelet's retries are burning addresses.
			cctx, ccancel := cleanupContext(ctx)
			defer ccancel()
			if rerr := releaseFabricIPs(cctx, lc, podUID); rerr != nil {
				err = fmt.Errorf("%w (releasing the fabric IP claim also failed: %v — "+
					"the address leaks until the pod is deleted)", err, rerr)
			}
		}
	}()
	fabricIP := fabricIPs[0]

	// Ports WE created, in order, so a failure half-way through releases exactly
	// what it claimed. A bound (persistent VM) Port is never ours to delete —
	// that is the whole point of it outliving the pod.
	var ours []string
	defer func() {
		if err != nil {
			cctx, ccancel := cleanupContext(ctx)
			defer ccancel()
			for _, name := range ours {
				_ = client.SdnV1alpha1().Ports().Delete(cctx, name, metav1.DeleteOptions{})
			}
		}
	}()

	result := &current.Result{CNIVersion: conf.CNIVersion}
	for _, r := range resolved {
		vpcIP, podMACPinned, port, bound, e := attachPort(ctx, client, r, state, podNS, podName, podUID, vmName, podLabels)
		if e != nil {
			err = e
			return err
		}
		if !bound {
			ours = append(ours, port.Name)
		}

		// The ports-map value carries the net id and, for a granted forwarding
		// leg, PORT_F_GATEWAY — the flag the datapath already uses for the VPC
		// egress gateway, and which is exactly the semantics a router needs.
		netID := uint32(r.vpc.Status.VNI)
		if r.forwarding {
			netID |= datapath.PortForwardFlag
			if len(r.forwardingCIDRs) > 0 {
				netID |= datapath.PortForwardScopedFlag
			}
		}
		hostVeth := hostVethNameForIndex(args.ContainerID, r.Index)
		podMAC, e := setupAttachment(args, r, hostVeth, vpcIP, podMACPinned, mtu, netID)
		if e != nil {
			err = e
			return err
		}
		result.Interfaces = append(result.Interfaces, &current.Interface{
			Name: r.IfName, Sandbox: args.Netns, Mac: podMAC.String(),
		})

		if r.Primary() {
			// R1 (docs/multitenancy.md): stamp the workload with the identity we
			// just gave it. A tenant cannot read the Port (cluster-scoped), and
			// status.podIP is the FABRIC IP — so without this it cannot discover
			// its own VPC address at all. Best-effort: a convenience projection,
			// not datapath state.
			stampVPCIdentity(ctx, podNS, podName, vpcIP, podMAC)

			// Bridge: route the (unique) fabric IP to this veth and publish the
			// fabric -> {net, VPC IP} mapping; the eBPF datapath does the NAT.
			// The pod MAC becomes the fabric IP's permanent neighbour: the pod's
			// interface carries only the VPC IP, so nothing would ever answer
			// ARP/NDP for the fabric address, and node-originated traffic
			// (kubelet probes, resolver replies) would die in FAILED resolution
			// before reaching to_pod's DNAT.
			if e := datapath.AddBridge(fabricIP.String(), vpcIP.String(), hostVeth, uint32(r.vpc.Status.VNI), podMAC); e != nil {
				err = e
				return err
			}
		}

		// Staged locals (live-migration overlap window): a migration target binds
		// the persistent Port while the VM is still ACTIVE on another node. Local
		// delivery must keep following the active location until cutover, or a
		// client co-located with the target would be delivered into the
		// not-yet-running VM. Everything else is staged now; the agent programs
		// locals from the veth's alias record when cutover re-points spec.node.
		if bound && port.Spec.Node != "" && port.Spec.Node != state.NodeName {
			if e := datapath.DelLocal(uint32(r.vpc.Status.VNI), vpcIP); e != nil {
				err = e
				return err
			}
		}
	}

	// Report the fabric IP as status.podIP (host mask for its family), against
	// the primary interface.
	result.IPs = []*current.IPConfig{{
		Interface: current.Int(0),
		Address:   net.IPNet{IP: fabricIP, Mask: hostMask(fabricIP)},
	}}
	return types.PrintResult(result, conf.CNIVersion)
}

// setupAttachment realizes one attachment: the veth pair, the pod-side address
// and routes, the host side and its classifier hooks. Returns the pod-interface
// MAC, which the caller records as the fabric IP's neighbour for the primary.
func setupAttachment(args *skel.CmdArgs, r resolvedAttachment, hostVethName string,
	vpcIP net.IP, pinnedMAC net.HardwareAddr, mtu int, netID uint32) (net.HardwareAddr, error) {
	hostNS, err := ns.GetCurrentNS()
	if err != nil {
		return nil, fmt.Errorf("get host netns: %w", err)
	}
	defer hostNS.Close()

	var podMAC net.HardwareAddr
	if err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		if _, _, e := ip.SetupVethWithName(r.IfName, hostVethName, mtu, "", hostNS); e != nil {
			return e
		}
		link, e := netlink.LinkByName(r.IfName)
		if e != nil {
			return e
		}
		if len(pinnedMAC) == 6 {
			if e := netlink.LinkSetHardwareAddr(link, pinnedMAC); e != nil {
				return fmt.Errorf("pin pod MAC %s: %w", pinnedMAC, e)
			}
		}
		if e := netlink.LinkSetUp(link); e != nil {
			return e
		}
		if e := addPodAddrRoute(link, vpcIP, r.Primary(), r.cidr); e != nil {
			return e
		}
		// netlink does not refresh the cached attrs after LinkSetHardwareAddr,
		// so reading it back would give the stale pre-pin MAC and the datapath
		// would deliver to the wrong address.
		if len(pinnedMAC) == 6 {
			podMAC = pinnedMAC
		} else {
			podMAC = link.Attrs().HardwareAddr
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return podMAC, configureHostVeth(hostVethName, []net.IP{vpcIP}, netID, podMAC, r.forwardingCIDRs)
}

// addGatewayLeg gives a (default-network) gateway pod a second interface into
// the VPC, carrying the VPC's reserved .1 address. Authorization is by
// placement, not binding: the pod must live in the agent's own (system)
// namespace — where only the cozyplane controller creates pods — and the VPC
// owner must have opted in via spec.egress.natGateway. The .1 Port is claimed
// like any other (atomic by name), marked spec.gateway so agents route off-VPC
// traffic to it.
func addGatewayLeg(ctx context.Context, args *skel.CmdArgs, conf *NetConf, vpcNS, vpcName, podNS, podName, podUID string) (err error) {
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
	vpc, err := client.SdnV1alpha1().VPCs(vpcNS).Get(ctx, vpcName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get vpc %s/%s: %w", vpcNS, vpcName, err)
	}
	// The VPC's owner must have opened a door: a VPCGateway naming this VPC, with
	// NAT enabled. Not a field on the VPC any more — the boundary is a separate,
	// grantable object (docs/north-south.md). The VPC's boundary is its OLDEST
	// gateway; a second one realizes nothing.
	gws, err := client.SdnV1alpha1().VPCGateways(vpcNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list vpcgateways in %s: %w", vpcNS, err)
	}
	gw := sdnv1alpha1.EffectiveGateway(gws.Items, vpcName)
	if gw == nil || !gw.Spec.NAT.Enabled {
		return fmt.Errorf("vpc %s/%s has no gateway with NAT enabled (create a VPCGateway)", vpcNS, vpcName)
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
	created, err := client.SdnV1alpha1().Ports().Create(ctx, port, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("claim gateway port %s: %w", port.Name, err)
	}
	defer func() {
		if err != nil {
			cctx, ccancel := cleanupContext(ctx)
			defer ccancel()
			_ = client.SdnV1alpha1().Ports().Delete(cctx, created.Name, metav1.DeleteOptions{})
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
		gwAddr := &netlink.Addr{IPNet: &net.IPNet{IP: gwIP, Mask: hostMask(gwIP)}}
		gwIsV6 := gwIP.To4() == nil
		if gwIsV6 {
			gwAddr.Flags = unix.IFA_F_NODAD
		}
		if e := netlink.AddrAdd(link, gwAddr); e != nil {
			return fmt.Errorf("add gateway address: %w", e)
		}
		if e := netlink.LinkSetUp(link); e != nil {
			return e
		}
		podMAC = link.Attrs().HardwareAddr
		// Route the whole VPC CIDR out this leg via the link-local hop the host
		// veth answers for (v4: proxy-arp'd 169.254.1.1; v6: fe80::1 assigned
		// outright). onlink: the hop needs no route of its own.
		hop := linkLocalGW
		if gwIsV6 {
			hop = linkLocalGWv6
		}
		if e := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       ipnet,
			Gw:        hop,
			Flags:     int(netlink.FLAG_ONLINK),
		}); e != nil {
			return fmt.Errorf("add VPC route: %w", e)
		}
		// The gateway forwards between its legs — both families; a v6 VPC's
		// gateway still egresses over its dual-stack default-network leg.
		for key, val := range map[string]string{
			"net/ipv4/ip_forward":             "1",
			"net/ipv4/conf/all/rp_filter":     "0",
			"net/ipv4/conf/default/rp_filter": "0",
			"net/ipv6/conf/all/forwarding":    "1",
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
	return configureHostVeth(hostVethName, []net.IP{gwIP}, uint32(vpc.Status.VNI)|datapath.PortGatewayFlag, podMAC, nil)
}

// requireVPCBinding implements default-deny attachment: a VPCBinding in the
// pod's namespace must reference the target VPC (owner namespace + name). The
// pod's namespace is trustworthy (kubelet supplies it via CNI_ARGS), so this is
// a pure data-plane check — no caller identity is involved here; the privileged
// decision was made when the binding was created.
// It also reports whether the grant carries allowForwarding — the right to emit
// packets sourced from an address that is not the pod's own, which a router or
// firewall bridging two VPCs needs and which lets its holder impersonate any
// member of the VPC (docs/multi-attach.md). Several bindings may authorize the
// same VPC; the grant is their UNION, because each was authored by someone
// holding `export` on the VPC and a later binding must not silently revoke an
// earlier grant.
// It also reports the forwarding scope (issue #6). fwdCIDRs is non-nil only when
// the grant is SCOPED — every binding that grants allowForwarding also named
// forwardingCIDRs, so the union of those CIDRs bounds the leg. A nil fwdCIDRs
// with allowForwarding=true is a BLANKET grant: at least one granting binding
// declared no CIDRs, and a blanket grant must not be silently narrowed by
// another's CIDRs (the union is the most permissive, as for allowForwarding).
func requireVPCBinding(ctx context.Context, client sdnclientset.Interface, podNS, vpcNS, vpcName string) (allowForwarding bool, fwdCIDRs []string, err error) {
	list, err := client.SdnV1alpha1().VPCBindings(podNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, nil, fmt.Errorf("list vpcbindings in %q: %w", podNS, err)
	}
	found := false
	blanket := false // a granting binding with no CIDRs
	scopedCIDRs := []string{}
	for i := range list.Items {
		ref := list.Items[i].Spec.VPCRef
		if ref.Namespace != vpcNS || ref.Name != vpcName {
			continue
		}
		found = true
		if !list.Items[i].Spec.AllowForwarding {
			continue
		}
		allowForwarding = true
		if len(list.Items[i].Spec.ForwardingCIDRs) == 0 {
			blanket = true
		} else {
			scopedCIDRs = append(scopedCIDRs, list.Items[i].Spec.ForwardingCIDRs...)
		}
	}
	if !found {
		return false, nil, fmt.Errorf("no VPCBinding in namespace %q authorizes attaching to VPC %s/%s (default-deny)", podNS, vpcNS, vpcName)
	}
	if allowForwarding && !blanket {
		return true, scopedCIDRs, nil
	}
	return allowForwarding, nil, nil
}

// rebindPodIdentity re-points a reused persistent Port at the pod binding it
// now: the identity labels the controller reverse-indexes on, the spec's
// pod name/namespace, and the pod-labels snapshot. A no-op when nothing moved.
func rebindPodIdentity(ctx context.Context, client sdnclientset.Interface, p *sdnv1alpha1.Port, podNS, podName, podUID, podLabels string) error {
	if p.Labels[sdnv1alpha1.LabelPodNamespace] == podNS &&
		p.Labels[sdnv1alpha1.LabelPodName] == podName &&
		p.Labels[sdnv1alpha1.LabelPodUID] == podUID &&
		(podLabels == "" || p.Annotations[sdnv1alpha1.AnnotationPodLabels] == podLabels) {
		return nil
	}
	patch := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]string{
				sdnv1alpha1.LabelPodNamespace: podNS,
				sdnv1alpha1.LabelPodName:      podName,
				sdnv1alpha1.LabelPodUID:       podUID,
			},
		},
		"spec": map[string]any{
			"podNamespace": podNS,
			"podName":      podName,
		},
	}
	if podLabels != "" {
		patch["metadata"].(map[string]any)["annotations"] = map[string]string{
			sdnv1alpha1.AnnotationPodLabels: podLabels,
		}
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	updated, err := client.SdnV1alpha1().Ports().Patch(ctx, p.Name,
		k8stypes.MergePatchType, raw, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	*p = *updated
	return nil
}

// attachPort obtains the Port realizing one attachment and returns its VPC IP,
// the pinned MAC (nil when the veth keeps its random one), the Port, and whether
// the Port pre-existed (bound => never ours to delete).
//
// Three paths, in this order:
//
//   - Virt-launcher pod: BIND the VM's persistent Port for THIS interface index
//     if one exists, reusing the pinned VPC IP + MAC so they survive live
//     migration. The index is load-bearing on a multi-NIC VM: without it the
//     selector matches every NIC's Port and the first returned is arbitrary, so
//     the interfaces would swap addresses across restarts.
//   - A requested address (attachment.ip): claim exactly it. AlreadyExists is a
//     hard error, not a cue to try the next one — the caller asked for one
//     address, and quietly handing back a different one is the failure this
//     field exists to remove.
//   - Otherwise: walk the CIDR and take the first free address, claiming it
//     atomically by Port name.
func attachPort(ctx context.Context, client sdnclientset.Interface, r resolvedAttachment,
	state *datapath.AgentState, podNS, podName, podUID, vmName, podLabels string) (net.IP, net.HardwareAddr, *sdnv1alpha1.Port, bool, error) {
	vpc, vpcNS := r.vpc, r.VPCNamespace
	ipnet := r.cidr

	if vmName != "" {
		sel := fmt.Sprintf("%s=%s,%s=%s,%s=%s,%s=%s", labelVPCNamespace, vpcNS, labelVPC, vpc.Name,
			labelVMName, vmName, labelVMNIC, r.NICID())
		existing, err := client.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("list persistent ports for vm %q: %w", vmName, err)
		}
		if len(existing.Items) > 0 {
			p := &existing.Items[0]
			ip := net.ParseIP(p.Spec.IP)
			if ip == nil {
				return nil, nil, nil, false, fmt.Errorf("persistent port %s has invalid IP %q", p.Name, p.Spec.IP)
			}
			mac, err := net.ParseMAC(p.Spec.MAC)
			if err != nil {
				return nil, nil, nil, false, fmt.Errorf("persistent port %s has invalid MAC %q: %w", p.Name, p.Spec.MAC, err)
			}
			// A pinned VM address that disagrees with the requested one is a
			// contradiction, not a preference: the persistent Port is the VM's
			// identity and cannot be re-pointed without breaking migration.
			if r.IP != nil && !r.IP.Equal(ip) {
				return nil, nil, nil, false, fmt.Errorf(
					"attachment %d requests ip %s but VM %q already holds pinned address %s on this interface",
					r.Index, r.IP, vmName, p.Spec.IP)
			}
			// Re-point the Port's pod identity at the pod binding it NOW. The
			// {IP, MAC} stay pinned — that is the whole point of a persistent
			// Port — but membership must follow the live launcher, or a migrated
			// VM's SecurityGroup membership would freeze at its original labels
			// (docs/security-groups.md § Membership). Best-effort.
			if err := rebindPodIdentity(ctx, client, p, podNS, podName, podUID, podLabels); err != nil {
				fmt.Fprintf(os.Stderr, "cozyplane: rebind pod identity on %s: %v\n", p.Name, err)
			}
			return ip, mac, p, true, nil
		}
	}

	// A persistent (VM) Port carries a stable pinned MAC; an ordinary Port has
	// none unless the attachment asked for one.
	mac := r.MAC
	if mac == nil && vmName != "" {
		mac = genMAC()
	}

	newPort := func(ipStr string) *sdnv1alpha1.Port {
		labels := map[string]string{
			labelVPCNamespace: vpcNS,
			labelVPC:          vpc.Name,
			labelPodNS:        podNS,
			labelPodName:      podName,
			labelPodUID:       podUID,
		}
		spec := sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpc.Name},
			IP:     ipStr,
			// No fabricIP: the underlay address is the pod's FabricIP claim,
			// not a copy on the tenant object (docs/api-groups.md).
			Node:         state.NodeName,
			NodeIP:       state.NodeIP,
			PodNamespace: podNS,
			PodName:      podName,
			// The forwarding grant, from the VPCBinding. Distinct from Gateway:
			// this port is not the VPC's door (docs/multi-attach.md).
			Forwarding: r.forwarding,
		}
		if mac != nil {
			spec.MAC = mac.String()
		}
		if vmName != "" {
			labels[labelVMName] = vmName
			labels[labelVMNIC] = r.NICID()
		}
		// Only delegated Ports carry it, and only they need it: the annotation
		// path's DEL releases every Port of the pod at once, while a delegated DEL
		// must find exactly its own.
		if r.Delegated {
			labels[labelIfName] = r.IfName
		}
		var annotations map[string]string
		if podLabels != "" {
			annotations = map[string]string{sdnv1alpha1.AnnotationPodLabels: podLabels}
		}
		return &sdnv1alpha1.Port{
			ObjectMeta: metav1.ObjectMeta{
				Name: portName(vpc.Status.VNI, ipStr),
				// The sever finalizer makes revocation replayable: deletion
				// completes only after the port's node agent acknowledges.
				Finalizers:  []string{sdnv1alpha1.FinalizerSever},
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: spec,
		}
	}

	// A requested address: claim exactly it, or fail saying so.
	if r.IP != nil {
		if !ipnet.Contains(r.IP) {
			return nil, nil, nil, false, fmt.Errorf("requested ip %s is outside VPC %q (%s)",
				r.IP, vpc.Name, vpc.Spec.CIDRs[0])
		}
		created, err := client.SdnV1alpha1().Ports().Create(ctx, newPort(r.IP.String()), metav1.CreateOptions{})
		// AlreadyExists: another Port holds the name. Conflict (409): the
		// registry's cross-kind check — a ServiceVIP holds the same address.
		if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
			return nil, nil, nil, false, fmt.Errorf("ip %s is already taken in VPC %q", r.IP, vpc.Name)
		}
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("create port: %w", err)
		}
		return r.IP, mac, created, false, nil
	}

	list, err := client.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{
		LabelSelector: labelVPCNamespace + "=" + vpcNS + "," + labelVPC + "=" + vpc.Name,
	})
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("list ports: %w", err)
	}
	used := map[string]bool{}
	for i := range list.Items {
		used[list.Items[i].Spec.IP] = true
	}
	// ServiceVIPs draw from the same per-VPC keyspace (they walk from the TOP
	// of the CIDR down; Ports walk up) — both allocators check the live union
	// of both kinds, so neither can hand out the other's address.
	vips, err := client.SdnV1alpha1().ServiceVIPs().List(ctx, metav1.ListOptions{
		LabelSelector: labelVPCNamespace + "=" + vpcNS + "," + labelVPC + "=" + vpc.Name,
	})
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("list servicevips: %w", err)
	}
	for i := range vips.Items {
		used[vips.Items[i].Spec.IP] = true
	}

	// Start at network+2 (reserve .0 network and .1 for a future gateway).
	candidate := nextIP(nextIP(cloneIP(ipnet.IP)))
	for ipnet.Contains(candidate) {
		ipStr := candidate.String()
		if used[ipStr] {
			candidate = nextIP(candidate)
			continue
		}
		created, err := client.SdnV1alpha1().Ports().Create(ctx, newPort(ipStr), metav1.CreateOptions{})
		// Either error means the address is taken; walk on.
		if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
			used[ipStr] = true
			candidate = nextIP(candidate)
			continue
		}
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("create port: %w", err)
		}
		return candidate, mac, created, false, nil
	}
	return nil, nil, nil, false, fmt.Errorf("no free address in VPC %q (%s)", vpc.Name, vpc.Spec.CIDRs[0])
}

// genMAC returns a random locally-administered unicast MAC (02:…). The Port pins
// it so a VM keeps the same MAC across pod churn and live migration.
func genMAC() net.HardwareAddr {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	b[0] = (b[0] | 0x02) &^ 0x01 // locally administered, unicast
	return net.HardwareAddr(b)
}

// portName builds the cluster-scoped Port name v<vni>.<ip-escaped> — the
// address claim, registry-validated to match spec.ip. Shared helper so the
// writer (here), the controller's ServiceVIP twin, and the registry check
// can never drift.
func portName(vni int32, ip string) string {
	return sdn.PortName(vni, ip)
}

// setupVeth creates the pod veth, configures the pod-side address and routes,
// configures the host side, and attaches the classifier with the given net id.
// It also returns the pod interface MAC (the pinned one for a VM) — the bridge
// records it as the fabric IP's permanent neighbour.
func setupVeth(args *skel.CmdArgs, cniVersion string, podIPs []net.IP, pinnedMAC net.HardwareAddr, mtu int, netID uint32) (*current.Result, net.HardwareAddr, error) {
	hostNS, err := ns.GetCurrentNS()
	if err != nil {
		return nil, nil, fmt.Errorf("get host netns: %w", err)
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
		mac, e := configurePodIface(podIPs, pinnedMAC)
		podMAC = mac
		return e
	}); err != nil {
		return nil, nil, err
	}

	if err := configureHostVeth(hostVethName, podIPs, netID, podMAC, nil); err != nil {
		return nil, nil, err
	}

	return &current.Result{
		CNIVersion: cniVersion,
		Interfaces: []*current.Interface{{Name: contVethName, Sandbox: args.Netns}},
	}, podMAC, nil
}

// configurePodIface sets the pod's eth0 address, brings it up, and installs the
// link-local default route. Runs inside the pod netns. When pinnedMAC is set (a
// VM NIC), it is applied to eth0 so the MAC survives migration — KubeVirt's
// bridge binding hands this MAC to the guest. Returns the eth0 MAC so the host
// side can record it for same-node redirect delivery.
func configurePodIface(podIPs []net.IP, pinnedMAC net.HardwareAddr) (net.HardwareAddr, error) {
	link, err := netlink.LinkByName(contVethName)
	if err != nil {
		return nil, err
	}
	if len(pinnedMAC) == 6 {
		if err := netlink.LinkSetHardwareAddr(link, pinnedMAC); err != nil {
			return nil, fmt.Errorf("pin pod MAC %s: %w", pinnedMAC, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	// One address per family (dual-stack default pods get a v4 and a v6), each
	// with its own on-link gateway + default route.
	for _, podIP := range podIPs {
		if err := addPodAddrRoute(link, podIP, true, nil); err != nil {
			return nil, err
		}
	}
	// Return the MAC the host side must record in `locals` for redirect delivery.
	// When pinned, it is the value we just set — netlink does not refresh the
	// cached link.Attrs() after LinkSetHardwareAddr, so reading it back would give
	// the stale pre-pin MAC and the datapath would deliver to the wrong address
	// (KubeVirt hands the *pinned* MAC to the guest).
	if len(pinnedMAC) == 6 {
		return pinnedMAC, nil
	}
	return link.Attrs().HardwareAddr, nil
}

// addPodAddrRoute adds one pod address and its on-link gateway + default route,
// inside the pod netns. The gateway (169.254.1.1 or fe80::1) is never assigned
// anywhere; the host veth answers for it (proxy_arp for v4, its own fe80::1 for
// v6), Calico-style.
// primary selects the routing shape. The primary interface gets the on-link hop
// plus a DEFAULT route through it, as it always has. A secondary attachment gets
// only a route to its own VPC CIDR via that hop, marked onlink — two reasons:
// N default routes would make the pod's untargeted egress pick an interface by
// whatever metric the kernel assigned, and an on-link /32 to 169.254.1.1 installed
// on two interfaces would leave the kernel choosing one of them for both. onlink
// needs no route to the hop at all, which is why the gateway leg already uses it.
func addPodAddrRoute(link netlink.Link, podIP net.IP, primary bool, vpcCIDR *net.IPNet) error {
	gw := podGateway(podIP)
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: podIP, Mask: hostMask(podIP)}}
	if isV6(podIP) {
		// Ensure v6 is on inside the pod netns, and skip DAD on the /128: it is a
		// point-to-point veth with no possible duplicate, and DAD would leave the
		// address "tentative" (unusable) for ~1s, racing the pod's first packet.
		_ = datapath.WriteProcSys(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", link.Attrs().Name), "0")
		addr.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrAdd(link, addr); err != nil && !isExist(err) {
		return fmt.Errorf("add pod address: %w", err)
	}
	if !primary {
		if vpcCIDR == nil {
			return fmt.Errorf("secondary attachment has no VPC CIDR to route")
		}
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       vpcCIDR,
			Gw:        gw,
			Flags:     int(netlink.FLAG_ONLINK),
		}); err != nil && !isExist(err) {
			return fmt.Errorf("add VPC route: %w", err)
		}
		return nil
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: gw, Mask: hostMask(gw)},
	}); err != nil && !isExist(err) {
		return fmt.Errorf("add gateway route: %w", err)
	}
	// A v6 default route through a link-local next hop must name the link.
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw}); err != nil && !isExist(err) {
		return fmt.Errorf("add default route: %w", err)
	}
	return nil
}

// configureHostVeth brings up the host-side veth, enables proxy_arp and
// forwarding, installs the /32 route (host->local-pod), attaches both classifier
// hooks (from_pod ingress, to_pod egress), and records the pod's network id and
// local endpoint.
func configureHostVeth(name string, podIPs []net.IP, netID uint32, podMAC net.HardwareAddr, fwdCIDRs []string) error {
	hv, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(hv); err != nil {
		return err
	}
	hasV6 := false
	for _, ip := range podIPs {
		if isV6(ip) {
			hasV6 = true
		}
	}
	sysctls := map[string]string{
		fmt.Sprintf("net/ipv4/conf/%s/proxy_arp", name):  "1",
		fmt.Sprintf("net/ipv4/conf/%s/forwarding", name): "1",
		fmt.Sprintf("net/ipv4/conf/%s/rp_filter", name):  "0",
	}
	if hasV6 {
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
	if hasV6 {
		// The mask must be 16 bytes for a 16-byte address: an 8-byte
		// CIDRMask(64, 64) here made netlink fall back to prefixlen 0, and the
		// kernel then installed `default dev <veth>` (the on-link route of a
		// /0 address) — at metric 256 that outranks a host's RA default and
		// hijacks node v6 egress. The agent's rebuild heals old veths.
		if err := netlink.AddrAdd(hv, &netlink.Addr{
			IPNet: &net.IPNet{IP: linkLocalGWv6, Mask: net.CIDRMask(64, 128)},
			Flags: unix.IFA_F_NODAD,
		}); err != nil && !isExist(err) {
			return fmt.Errorf("add v6 gateway address on host veth: %w", err)
		}
	}

	idx := hv.Attrs().Index

	// A default-network pod has a unique IP, reached by the host through a
	// main-table host route (one per family). VPC pods are delivered by eBPF
	// (same-node redirect, cross-node from_overlay) or, north-south, by the
	// bridge's per-pod table — never by a main-table VPC-IP route, which would
	// collide under overlapping CIDRs. So install the route only for net 0.
	if netID == 0 {
		for _, podIP := range podIPs {
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: idx,
				Scope:     netlink.SCOPE_LINK,
				Dst:       &net.IPNet{IP: podIP, Mask: hostMask(podIP)},
			}); err != nil && !isExist(err) {
				return fmt.Errorf("add pod host route: %w", err)
			}
		}
	}

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

	// Mirror the ports/locals payload onto the veth's link alias — the rebuild
	// record a restarted agent re-derives the maps from after a map-ABI
	// recreate, and the witness that keeps the entries below from being pruned
	// as stale (see datapath/rebuild.go). Written BEFORE the map entries so no
	// entry ever exists without its alias.
	if err := datapath.SetVethAlias(hv, netID, podIPs, podMAC); err != nil {
		return err
	}
	if err := datapath.SetPortNet(idx, netID); err != nil {
		return err
	}
	// A scoped forwarding leg (issue #6): program its foreign-source allowlist
	// keyed by this veth's ifindex. Clear first — an ifindex can be reused by a
	// later pod, and a stale entry would widen the new leg's grant. Only when
	// PORT_F_FWD_SCOPED is set; an unscoped/non-forwarding port consults nothing.
	if netID&datapath.PortForwardScopedFlag != 0 {
		if err := datapath.ClearFwdCidrs(uint32(idx)); err != nil {
			return err
		}
		for _, cidr := range fwdCIDRs {
			if err := datapath.SetFwdCidr(uint32(idx), cidr); err != nil {
				return fmt.Errorf("program forwarding CIDR %q: %w", cidr, err)
			}
		}
	} else {
		// Not (or no longer) scoped: clear any leftover from a reused ifindex.
		if err := datapath.ClearFwdCidrs(uint32(idx)); err != nil {
			return err
		}
	}
	// Record a local endpoint per address (keyed by network id, so overlapping
	// VPCs stay distinct) for eBPF-redirect delivery through to_pod.
	for _, podIP := range podIPs {
		if err := datapath.SetLocal(datapath.PortNet(netID), podIP, idx, podMAC); err != nil {
			return err
		}
	}
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	ctx, cancel := operationContext()
	defer cancel()

	conf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	// A delegated DEL removes only its own interface and Port. Falling through
	// would enumerate the whole primary name space and release the pod's FabricIP
	// claims — tearing down eth0 and the pod's underlay identity along with one
	// secondary NIC.
	if conf.VPC != "" {
		return delDelegate(ctx, args, conf)
	}

	// Clear the ports map entries; the host veths (and their tc filters) go
	// with the pod veths deleted below. Capture the VPC veth's net id first so the
	// local delivery entry can be cleaned by (net, VPC IP) below even when this
	// pod's Port cannot be consulted — a migration source whose persistent Port
	// has been re-pointed to the target pod, so a Port lookup by this pod misses.
	// Every attachment's host veth, not just the first: a multi-attach pod has
	// one per entry (docs/multi-attach.md). The names are deterministic, so
	// enumerating the index range finds them all without a link scan; absent
	// ones simply miss.
	vpcNet, haveVPCNet := uint32(0), false
	names := make([]string, 0, maxAttachments+1)
	for i := range maxAttachments {
		names = append(names, hostVethNameForIndex(args.ContainerID, i))
	}
	names = append(names, gwHostVethNameFor(args.ContainerID))
	for _, name := range names {
		if hv, e := netlink.LinkByName(name); e == nil {
			if name == hostVethNameFor(args.ContainerID) {
				if n, ok, e := datapath.GetPortNet(hv.Attrs().Index); e == nil && ok {
					vpcNet, haveVPCNet = n, true
				}
			}
			_ = datapath.DelPortNet(hv.Attrs().Index)
			_ = datapath.DetachVeth(hv.Attrs().Index)
		}
	}

	podNS, podName, podUID, _ := podIdentity(args)

	// Release a VPC Port if this pod had one. Prefer the pod UID (unique, never
	// reused) so a stale DEL can't delete a newer pod's Port that reuses a name.
	selector := fmt.Sprintf("%s=%s,%s=%s", labelPodNS, podNS, labelPodName, podName)
	if podUID != "" {
		selector = labelPodUID + "=" + podUID
	}
	if client, e := sdnClient(); e == nil && (podUID != "" || (podNS != "" && podName != "")) {
		if list, e := client.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{
			LabelSelector: selector,
		}); e == nil {
			for i := range list.Items {
				p := &list.Items[i]
				// The VPC/gateway-leg local entry is keyed by (net id, VPC IP);
				// net id is the VNI encoded in the Port name.
				if net_, ok := netFromPortName(p.Name); ok {
					_ = datapath.DelLocal(net_, net.ParseIP(p.Spec.IP))
				}
				// A persistent (VM NIC) Port outlives its pod so the VPC IP + MAC
				// survive pod churn / live migration: never delete it here — the
				// persistent-Port controller GCs it when the VM is gone.
				if p.Labels[labelVMName] != "" {
					continue
				}
				_ = client.SdnV1alpha1().Ports().Delete(ctx, p.Name, metav1.DeleteOptions{})
			}
		}
	}

	// The bridge is keyed by the pod's underlay address, which lives in its
	// FabricIP claim(s) — read them BEFORE releasing, since releasing is what
	// destroys them.
	if podUID != "" {
		if lc, e := localClient(); e == nil {
			if list, e2 := lc.LocalV1alpha1().FabricIPs().List(ctx, metav1.ListOptions{
				LabelSelector: labelFabricPodUID + "=" + podUID,
			}); e2 == nil {
				for i := range list.Items {
					_ = datapath.DelBridge(list.Items[i].Spec.Address, hostVethNameFor(args.ContainerID))
				}
			}
		}
	}

	// Release the underlay claim(s). Best-effort by design: if this DEL never
	// runs (the node died, kubelet was down when the pod went away), the
	// controller's GC reaps the FabricIP once the pod is gone. That is the whole
	// reason the address is an object and not a line in host-local's file store,
	// where a missed DEL leaked the address permanently (docs/api-groups.md).
	// Keyed on pod UID, so a reused pod name cannot reap the new pod's address.
	if podUID != "" {
		if lc, e := localClient(); e == nil {
			_ = releaseFabricIPs(ctx, lc, podUID)
		}
	}

	if args.Netns == "" {
		return nil
	}
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		// The gateway leg's VPC-IP local entry was cleared above via its Port.
		_, _ = ip.DelLinkByNameAddr(gwVethName)
		// Secondary attachments, by their default names. A custom `name` is not
		// reconstructible here and is skipped: the netns is being torn down by
		// the runtime anyway, and every attachment's locals entry was already
		// released above through its Port (listed by pod UID, so all of them).
		for i := 1; i < maxAttachments; i++ {
			_, _ = ip.DelLinkByNameAddr(defaultIfName(i))
		}
		addrs, e := ip.DelLinkByNameAddr(contVethName)
		if e == ip.ErrLinkNotFound {
			return nil
		}
		// Release the default-network local entry (net 0), and — for a VPC pod —
		// the VPC-net entry too, keyed by (captured net, VPC IP from the veth).
		// Doing it from the veth address makes cleanup independent of the Port,
		// so a migration source clears its own local delivery entry even though
		// its persistent Port now points at the target pod.
		for _, a := range addrs {
			if a.IP != nil {
				_ = datapath.DelLocal(0, a.IP)
				if haveVPCNet && vpcNet != 0 {
					_ = datapath.DelLocal(vpcNet, a.IP)
				}
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
	return hostVethPrefix + id
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

// stampVPCIdentity writes the pod's own VPC address and MAC onto the pod
// (docs/multitenancy.md R1) — the one place a tenant can read them.
//
// It is deliberately a pod annotation and not a namespaced object mirroring the
// Port: a second object holding a copy of the address is the stale-copy bug we
// removed when Port.spec.fabricIP was normalized away. An annotation on the pod
// cannot outlive, or drift from, the claim it describes.
func stampVPCIdentity(ctx context.Context, podNS, podName string, vpcIP net.IP, mac net.HardwareAddr) {
	if podNS == "" || podName == "" || vpcIP == nil {
		return
	}
	core, err := coreClient()
	if err != nil {
		return // best-effort: the pod works, it just cannot name its own address
	}
	patch := fmt.Appendf(nil, `{"metadata":{"annotations":{%q:%q,%q:%q}}}`,
		sdnv1alpha1.AnnotationVPCIP, vpcIP.String(),
		sdnv1alpha1.AnnotationVPCMAC, mac.String())
	_, _ = core.CoreV1().Pods(podNS).Patch(ctx, podName,
		k8stypes.MergePatchType, patch, metav1.PatchOptions{})
}
