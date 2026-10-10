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

package sdn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"k8s.io/utils/ptr"
	"math"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnidentity"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
)

// VPNGatewayConfig parameterizes the managed tunnel appliances the controller
// runs (issue #6, docs/vpn.md §3.2, §3.5).
type VPNGatewayConfig struct {
	// Image is the cozyplane image (the vpn-gateway binary ships in it). Empty
	// disables VPNGateway reconciliation.
	Image string
	// DefaultListenPort is the WireGuard UDP port used when a VPNGateway does not
	// pin one.
	DefaultListenPort int32

	// Guardrails (increment 6, docs/vpn.md §3.5): keep a heavy tunnel's blast
	// radius bounded to the gateway pool, never the cluster.

	// NodeSelector places appliances on a dedicated gateway node-pool. Empty runs
	// them anywhere.
	NodeSelector map[string]string
	// Tolerations let the appliance schedule onto a tainted gateway pool.
	Tolerations []corev1.Toleration
	// Resources are the appliance's requests/limits. A zero value is defaulted
	// (limits are mandatory — a crypto workload must never be able to starve the
	// node it shares).
	Resources corev1.ResourceRequirements
	// MaxGatewaysPerNamespace caps a tenant's tunnel gateways; zero defaults.
	MaxGatewaysPerNamespace int
	// MaxConnectionsPerGateway caps a gateway's peers; zero defaults.
	MaxConnectionsPerGateway int
	// HardenedAppliance replaces privileged mode with only the capabilities the
	// tunnel backends need. The cluster must allow the pod-level forwarding
	// sysctls; false preserves compatibility with clusters that do not.
	HardenedAppliance bool
	// InternalCIDRs are the cluster-internal networks (pod, service, node) a
	// remote CIDR must not overlap — the route-CIDR deny-set. A tenant declaring
	// one as a tunnel remote could otherwise redirect the VPC's own internal
	// traffic into the tunnel. Loopback/link-local/multicast are always refused
	// on top of these.
	InternalCIDRs []*net.IPNet
}

// reservedCIDRs are always-forbidden remote prefixes, independent of the
// cluster's pod/service/node networks: loopback, link-local, CGNAT, multicast,
// and their IPv6 equivalents. A tunnel that captured these would break or
// hijack host-local and control-plane traffic.
var reservedCIDRs = mustParseCIDRs(
	"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4",
	"::1/128", "fe80::/10", "ff00::/8",
)

func mustParseCIDRs(ss ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ss))
	for _, s := range ss {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// Guardrail defaults, applied when the config leaves a field zero.
const (
	defaultMaxGatewaysPerNamespace  = 8
	defaultMaxConnectionsPerGateway = 16
)

type vpnRoutingConfig struct {
	LocalASN       int64    `json:"localASN"`
	PeerASN        int64    `json:"peerASN"`
	PeerAddresses  []string `json:"peerAddresses"`
	AdvertiseCIDRs []string `json:"advertiseCIDRs"`
	BFD            bool     `json:"bfd,omitempty"`
}

// applianceResources returns the appliance's resource requirements, defaulting a
// zero config to modest requests and hard limits (the blast-radius bound).
func (r *VPNGatewayReconciler) applianceResources() corev1.ResourceRequirements {
	if len(r.Config.Resources.Limits) > 0 || len(r.Config.Resources.Requests) > 0 {
		return r.Config.Resources
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
}

func (r *VPNGatewayReconciler) maxGatewaysPerNamespace() int {
	if r.Config.MaxGatewaysPerNamespace > 0 {
		return r.Config.MaxGatewaysPerNamespace
	}
	return defaultMaxGatewaysPerNamespace
}

func (r *VPNGatewayReconciler) maxConnectionsPerGateway() int {
	if r.Config.MaxConnectionsPerGateway > 0 {
		return r.Config.MaxConnectionsPerGateway
	}
	return defaultMaxConnectionsPerGateway
}

// VPNGatewayReconciler realizes a VPNGateway (issue #6): it runs a WireGuard
// tunnel appliance attached to the VPC, grants that appliance a scoped
// forwarding right for the connections' remote CIDRs, gives it a FloatingIP
// endpoint a remote peer dials, and resolves its Port so the agent routes the
// remote CIDRs to it. The crypto lives in the appliance's netns; this controller
// only wires cozyplane's identity, delivery, policy and routing around it.
//
// It composes existing objects rather than reaching into the datapath: a
// VPCBinding (the scoped grant from increment 2), a FloatingIP (bidirectional
// ingress), and status.Routes the agent programs into vpc_routes (increment 1).
type VPNGatewayReconciler struct {
	client.Client
	// Reader is a non-cached client for the quota count — a stale informer read
	// would let a burst of concurrent creates each pass the cap before any lands
	// in cache. Optional; falls back to the cached client.
	Reader client.Reader
	Scheme *runtime.Scheme
	Config VPNGatewayConfig
	// HTTPClient reads the secret-free status endpoint in the selected appliance
	// pod. Optional; a short-timeout client is used in production.
	HTTPClient *http.Client
}

// quotaReader returns the live reader when wired, else the cached client.
func (r *VPNGatewayReconciler) quotaReader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// Labels/annotations on a VPNGateway's owned objects.
const (
	// vpnGatewayLabel links an owned object (Deployment, Secret, VPCBinding,
	// FloatingIP) back to its VPNGateway.
	vpnGatewayLabel = "sdn.cozystack.io/vpn-gateway"
	// vpnConfigChecksumAnnotation rolls the appliance when its peer set changes.
	vpnConfigChecksumAnnotation = "sdn.cozystack.io/vpn-config-checksum"
)

// tunnel backends. Exactly one is set on a gateway.
const (
	backendWireGuard = "wireguard"
	backendIPsec     = "ipsec"
)

// backendOf reports which tunnel backend a gateway declares (WireGuard default
// when neither is set, so an under-specified gateway still renders something
// coherent rather than wedging).
func backendOf(gw *sdnv1alpha1.VPNGateway) string {
	if gw.Spec.IPsec != nil {
		return backendIPsec
	}
	return backendWireGuard
}

func haMode(gw *sdnv1alpha1.VPNGateway) sdnv1alpha1.VPNGatewayHAMode {
	if gw.Spec.HA != nil {
		return gw.Spec.HA.Mode
	}
	if gw.Spec.HighAvailability {
		return sdnv1alpha1.VPNGatewayHAModeWarmStandby
	}
	return ""
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpngateways,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpngateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpnconnections,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpnconnections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=floatingips,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete

// Reconcile realizes the gateway's appliance, grant, endpoint and routes.
func (r *VPNGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &sdnv1alpha1.VPNGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if r.Config.Image == "" {
		return ctrl.Result{}, nil
	}
	if !gw.DeletionTimestamp.IsZero() {
		if slices.Contains(gw.Finalizers, wgClientFinalizer) {
			done, err := r.finalizeWGClientGateway(ctx, gw)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !done {
				return ctrl.Result{RequeueAfter: wgClientCleanupPoll}, nil
			}
			return ctrl.Result{}, nil
		}
		return r.reportUnready(ctx, gw, "GatewayTerminating", "VPNGateway is being deleted")
	}
	if problem := vpnGatewayInputProblem(gw); problem != "" {
		return r.reportUnready(ctx, gw, "InputLimitExceeded", problem)
	}

	// The served VPCs: the primary (spec.vpcRef) first, then the hub's additional
	// VPCs (docs/vpn.md §3.3). Every one must resolve — the routes and the
	// disjointness constraint below are computed over the whole set.
	servedVPCs, missing, err := r.servedVPCs(ctx, gw)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
	}
	if missing != "" {
		return r.reportUnready(ctx, gw, "VPCUnresolved",
			fmt.Sprintf("%s names no VPC in this namespace", missing))
	}
	vpc := servedVPCs[0]
	// Hub constraint (docs/vpn.md §3.3): routed traffic is delivered natively, so
	// one appliance cannot serve two owners of one prefix. Overlapping served
	// VPCs hold the gateway Pending rather than routing ambiguously.
	servedCIDRs, overlap := servedVPCCIDRs(servedVPCs)
	if overlap != "" {
		return r.reportUnready(ctx, gw, "VPCCIDRsOverlap", overlap)
	}

	// The connections this gateway terminates, and the remote prefixes they reach.
	conns, err := r.connectionsFor(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Per-tenant quota (increment 6): reject a gateway beyond the namespace cap or
	// a gateway with too many peers, before materializing anything — a tenant must
	// not be able to stand up unbounded crypto workloads. Under-quota gateways are
	// untouched; the offender is held Pending with a QuotaExceeded reason.
	if reason, err := r.overQuota(ctx, gw, conns); err != nil {
		return ctrl.Result{}, err
	} else if reason != "" {
		// An over-quota gateway must realize NOTHING — tear down anything a race
		// on the informer cache let a concurrent reconcile create, so the
		// forwarding grant, tunnel and public IP are actually revoked rather than
		// left running behind a cosmetic Pending status.
		return r.reportUnready(ctx, gw, "QuotaExceeded", reason)
	}
	if problem := vpnRouteInputProblem(conns); problem != "" {
		return r.reportUnready(ctx, gw, "InputLimitExceeded", problem)
	}
	for i := range conns {
		if problem := vpnConnectionReferenceProblem(&conns[i]); problem != "" {
			return r.reportUnready(ctx, gw, "InputLimitExceeded", problem)
		}
	}
	backend := backendOf(gw)
	if backend == backendIPsec {
		for i := range conns {
			if conns[i].Spec.IPsec == nil || conns[i].Spec.WireGuard != nil {
				return r.configurationFailure(ctx, gw, fmt.Errorf("IPsec gateways require IPsec connections"))
			}
		}
	}
	clientMode := isWGClientGateway(gw)
	if clientMode {
		if err := r.validateWGClientPools(ctx, gw, servedVPCs, servedCIDRs); err != nil {
			return r.configurationFailure(ctx, gw, err)
		}
		if err := r.ensureWGClientFinalizers(ctx, gw, nil); err != nil {
			return r.configurationFailure(ctx, gw, err)
		}
		if err := r.allocateWGClients(ctx, gw, servedVPCs, conns); err != nil {
			return r.configurationFailure(ctx, gw, err)
		}
		if err := r.ensureWGClientFinalizers(ctx, gw, conns); err != nil {
			return r.configurationFailure(ctx, gw, err)
		}
	} else {
		for i := range conns {
			if conns[i].Spec.WireGuard != nil && conns[i].Spec.WireGuard.Client != nil {
				return r.configurationFailure(ctx, gw, fmt.Errorf("WireGuard clients require a dedicated client gateway"))
			}
		}
	}
	if err := applyIPsecAddressPools(gw, conns); err != nil {
		return r.reportUnready(ctx, gw, "AddressPoolInvalid", err.Error())
	}
	if problem := vpnRouteInputProblem(conns); problem != "" {
		return r.reportUnready(ctx, gw, "InputLimitExceeded", problem)
	}
	// Strip forbidden prefixes before grants, routes or peer configuration consume them.
	rejectedCIDRs := r.filterForbiddenCIDRs(conns, servedCIDRs)
	fwdCIDRs := unionRemoteCIDRs(conns)
	if len(fwdCIDRs) > vpnlimits.RoutePrefixes/len(servedVPCs) {
		return r.reportUnready(ctx, gw, "InputLimitExceeded", "hub route prefixes exceed the combined VPC budget")
	}
	// Protect newly accepted intent before a credential/configuration failure
	// can leave it indistinguishable from an ordinary NAT route miss. An
	// unchanged prefix set performs no write and retains its active next hops.
	if err := r.protectRouteIntent(ctx, gw, conns); err != nil {
		return ctrl.Result{}, err
	}

	// The gateway's WireGuard identity: generated once, kept in a Secret; only the
	// public half is surfaced in status for the tenant to configure the peer.
	// IPsec authenticates by PSK — no keypair, no public key to surface.
	var privateKeys, publicKeys []string
	if backend == backendWireGuard {
		keyCount := 1
		if haMode(gw) == sdnv1alpha1.VPNGatewayHAModeActiveActive {
			keyCount = 2
		}
		privateKeys, publicKeys, err = r.ensureKeypairs(ctx, gw, keyCount)
		if err != nil {
			return r.configurationFailure(ctx, gw, err)
		}
	}

	// The peer set the appliance mounts. It carries secrets (WG private key / PSKs),
	// so it is a Secret; its checksum rolls the appliance when peers change.
	cfgJSON, err := r.buildConfig(ctx, gw, servedVPCs, backend, privateKeys, conns)
	if err != nil {
		// Invalid or removed credentials must not leave an old peer set active.
		return r.configurationFailure(ctx, gw, err)
	}
	checksum, err := r.ensureConfigSecret(ctx, gw, cfgJSON)
	if err != nil {
		return r.configurationFailure(ctx, gw, err)
	}
	clientConfigApplied := true
	if clientMode {
		clientConfigApplied, err = r.wgClientConfigApplied(ctx, gw, checksum, true)
		if err != nil {
			clientConfigApplied = false
		}
	}
	ipsecConfigApplied := true
	if backend == backendIPsec {
		ipsecConfigApplied, err = r.ipsecConfigApplied(ctx, gw, checksum)
		if err != nil {
			ipsecConfigApplied = false
		}
	}
	grantCIDRs := fwdCIDRs
	if !ipsecConfigApplied {
		grantCIDRs = nil
	}

	// The scoped forwarding grant (increment 2): the appliance may source the
	// remote CIDRs and nothing else. An empty union means no Ready connection yet
	// — the bindings still exist (attach authorization) but grant no forwarding.
	// One binding per served VPC (docs/vpn.md §3.3).
	if err := r.ensureBindings(ctx, gw, servedVPCs, grantCIDRs, conns); err != nil {
		return r.configurationFailure(ctx, gw, err)
	}

	// The appliance itself: a pod for ordinary/crash HA, or a KubeVirt VM whose
	// guest kernel carries the crypto state through planned live migration.
	if err := r.ensureApplianceWorkload(ctx, gw, backend, checksum); err != nil {
		return r.configurationFailure(ctx, gw, err)
	}

	// Resolve one selected leg for ordinary/warm-standby gateways and two for
	// active-active. Each active leg gets its own stable FloatingIP endpoint.
	wantAppliances := 1
	if haMode(gw) == sdnv1alpha1.VPNGatewayHAModeActiveActive {
		wantAppliances = 2
	}
	appliances := r.resolveAppliancePorts(ctx, gw, vpc, wantAppliances)
	var appliancePorts, addresses []string
	endpointNames := map[string]bool{}
	for i, appliance := range appliances {
		appliancePorts = append(appliancePorts, appliance.Port)
		name := gw.Name + "-vpn"
		if wantAppliances > 1 {
			name = fmt.Sprintf("%s-vpn-%d", gw.Name, i)
		}
		endpointNames[name] = true
		claimName := gw.Spec.ExternalAddress.AddressClaimName
		if wantAppliances > 1 {
			claimName = ""
			if i < len(gw.Spec.ExternalAddress.AddressClaimNames) {
				claimName = gw.Spec.ExternalAddress.AddressClaimNames[i]
			}
		}
		address, err := r.ensureFloatingIPNamed(ctx, gw, name, appliance.IP, claimName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if address != "" {
			addresses = append(addresses, address)
		}
	}
	if err := r.pruneFloatingIPs(ctx, gw, endpointNames); err != nil {
		return ctrl.Result{}, err
	}
	appliancePort, address := "", ""
	if len(appliancePorts) > 0 {
		appliancePort = appliancePorts[0]
	}
	if len(addresses) > 0 {
		address = addresses[0]
	}

	// The routes the agent programs into vpc_routes: each connection's remote
	// CIDRs toward the appliance Port. Keep unresolved accepted prefixes as
	// blackholes: removing them would permit ordinary cleartext NAT egress.
	var routes []sdnv1alpha1.VPCGatewayRouteStatus
	allLegsReady := true
	for i, served := range servedVPCs {
		legPorts := appliancePorts
		if i > 0 {
			legPorts = r.resolveVPCLegPorts(ctx, gw, served, appliances)
		}
		if len(legPorts) != wantAppliances {
			allLegsReady = false
			legPorts = nil
		}
		if (clientMode && !clientConfigApplied) || !ipsecConfigApplied {
			legPorts = nil
			allLegsReady = false
		}
		for _, route := range connectionRoutes(connectionsForVPC(conns, served.Name), legPorts) {
			route.VPCRef.Name = served.Name
			routes = append(routes, route)
		}
	}

	status := sdnv1alpha1.VPNGatewayStatus{
		Address:        address,
		Addresses:      append([]string(nil), addresses...),
		PublicKeys:     append([]string(nil), publicKeys...),
		AppliancePort:  appliancePort,
		AppliancePorts: append([]string(nil), appliancePorts...),
		Routes:         routes,
		Phase:          sdnv1alpha1.VPNGatewayPhasePending,
	}
	if len(publicKeys) > 0 {
		status.PublicKey = publicKeys[0]
	}
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionApplianceReady, appliancePort != "",
		"ApplianceReady", applianceReadyMessage(appliancePort))
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionAddressAssigned, address != "",
		"AddressAssigned", addressMessage(address))
	expectedRoutes := 0
	for _, served := range servedVPCs {
		expectedRoutes += len(nonEmptyRouteConns(connectionsForVPC(conns, served.Name)))
	}
	routesReady := allLegsReady && len(appliancePorts) == wantAppliances && len(routes) == expectedRoutes
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionRoutesProgrammed, routesReady,
		"RoutesProgrammed", routesMessage(routesReady, len(routes)))
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionRemoteCIDRsAccepted, len(rejectedCIDRs) == 0,
		remoteCIDRsReason(rejectedCIDRs), remoteCIDRsMessage(rejectedCIDRs))
	if len(appliancePorts) == wantAppliances && len(addresses) == wantAppliances && ipsecConfigApplied {
		status.Phase = sdnv1alpha1.VPNGatewayPhaseReady
	}

	if err := r.writeStatus(ctx, gw, status); err != nil {
		return ctrl.Result{}, err
	}
	var snapshots []*vpnstatus.Snapshot
	var snapshotErr error
	for _, appliance := range appliances {
		snapshot, readErr := r.readApplianceStatus(ctx, appliance.StatusIP, backend)
		if readErr != nil {
			snapshotErr = errors.Join(snapshotErr, readErr)
			continue
		}
		snapshots = append(snapshots, snapshot)
	}
	if len(snapshots) > 0 {
		// One live active-active member is sufficient to serve; the missing member
		// remains visible through pod readiness and the gateway conditions.
		snapshotErr = nil
	}
	snapshot := mergeVPNSnapshots(backend, snapshots)
	if snapshotErr != nil {
		logger.Info("VPN appliance status unavailable", "vpngateway", req.NamespacedName.String(), "err", snapshotErr)
	}
	if err := r.reflectConnectionStatus(ctx, conns, routesReady, snapshot, snapshotErr); err != nil {
		return ctrl.Result{}, err
	}
	if clientMode {
		if err := r.reflectWGClientConfig(ctx, gw, servedVPCs, conns, clientConfigApplied && routesReady); err != nil {
			return ctrl.Result{}, err
		}
		if clientConfigApplied {
			if err := r.releaseWGClientReservations(ctx, gw, conns, false); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{RequeueAfter: wgClientCleanupPoll}, nil
	}
	if !ipsecConfigApplied {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	logger.Info("VPNGateway reconciled", "vpngateway", req.NamespacedName.String(), "phase", status.Phase)
	return ctrl.Result{RequeueAfter: vpnStatusPollInterval(gw)}, nil
}

func vpnStatusPollInterval(gw *sdnv1alpha1.VPNGateway) time.Duration {
	if haMode(gw) != "" {
		return time.Second
	}
	return 15 * time.Second
}

// Names and labels are tenant-controlled; only the current owner's UID can
// authorize reuse or deletion of an appliance resource.
func requireVPNOwner(obj client.Object, owner client.Object) error {
	if owner.GetUID() == "" || obj.GetNamespace() != owner.GetNamespace() || !metav1.IsControlledBy(obj, owner) {
		return fmt.Errorf("resource %T %s/%s is not controlled by %s", obj, obj.GetNamespace(), obj.GetName(), owner.GetName())
	}
	return nil
}

func (r *VPNGatewayReconciler) deleteVPNOwned(ctx context.Context, owner client.Object, obj client.Object) error {
	if err := r.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return nil
		}
		return err
	}
	if requireVPNOwner(obj, owner) != nil {
		return nil // a name collision never authorizes deleting another object
	}
	uid, version := obj.GetUID(), obj.GetResourceVersion()
	err := r.Delete(ctx, obj, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}})
	return client.IgnoreNotFound(err)
}

// teardownOwned deletes the active resources a gateway owns — the tunnel
// Deployment, the forwarding-grant VPCBinding, and the FloatingIP endpoint — so
// a rejected gateway grants and serves nothing. The keypair/config Secrets are
// left (inert without the Deployment, and keeping the key stable if the gateway
// later comes back within quota). NotFound is success.
func (r *VPNGatewayReconciler) teardownOwned(ctx context.Context, gw *sdnv1alpha1.VPNGateway) error {
	name := gw.Name + "-vpn"
	objs := []client.Object{
		&sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name + "-headless", Namespace: gw.Namespace}},
		vpnVirtualMachineObject(gw.Namespace, name),
		&sdnv1alpha1.FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
		&sdnv1alpha1.FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: name + "-0", Namespace: gw.Namespace}},
		&sdnv1alpha1.FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: name + "-1", Namespace: gw.Namespace}},
	}
	for _, o := range objs {
		if err := r.deleteVPNOwned(ctx, gw, o); err != nil {
			return fmt.Errorf("teardown %T %q: %w", o, name, err)
		}
	}
	// The forwarding-grant bindings: one per served VPC, found by label rather
	// than by name (docs/vpn.md §3.3).
	return r.pruneVPCBindings(ctx, gw, nil)
}

// reportUnready writes a Pending status carrying a single blocking reason when
// the gateway cannot be realized, after draining its previously active grant.
func (r *VPNGatewayReconciler) reportUnready(ctx context.Context, gw *sdnv1alpha1.VPNGateway, reason, msg string) (ctrl.Result, error) {
	if isWGClientGateway(gw) || slices.Contains(gw.Finalizers, wgClientFinalizer) {
		if err := r.persistWGClientAppliances(ctx, gw); err != nil {
			return ctrl.Result{}, r.fenceWGClientStateFailure(ctx, gw, err)
		}
	}
	teardownErr := r.teardownOwned(ctx, gw)
	// Backend edits must not hide a peer's previous successful status. Publish
	// revocation even if draining an owned resource failed.
	teardownErr = errors.Join(teardownErr, r.invalidateGatewayConnectionStatuses(ctx, gw, reason, msg))
	if teardownErr != nil {
		return ctrl.Result{}, teardownErr
	}
	status := sdnv1alpha1.VPNGatewayStatus{Phase: sdnv1alpha1.VPNGatewayPhasePending}
	if reason != "GatewayTerminating" && (reason != "VPCUnresolved" || len(gw.Spec.AdditionalVPCRefs) > 0) {
		routes, err := blackholeVPNRoutes(gw.Status.Routes)
		if err != nil {
			return ctrl.Result{}, err // never erase an incomplete protected set
		}
		status.Routes = routes
	}
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionApplianceReady, false, reason, msg)
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionAddressAssigned, false, reason, msg)
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionRoutesProgrammed, false, reason, msg)
	return ctrl.Result{}, r.writeStatus(ctx, gw, status)
}

// connectionsFor returns all active peers when within quota, otherwise quota+1
// peers witnessing overflow. The caller must reject overflow before using them.
func (r *VPNGatewayReconciler) connectionsFor(ctx context.Context, gw *sdnv1alpha1.VPNGateway) ([]sdnv1alpha1.VPNConnection, error) {
	var list sdnv1alpha1.VPNConnectionList
	limit := int64(r.maxConnectionsPerGateway())
	if limit < math.MaxInt64 {
		limit++
	}
	// The index excludes terminating peers. Limiting a mixed active/deleting
	// list could silently omit live peers and publish a partial configuration.
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace), client.MatchingFields{vpnConnectionGatewayIndex: gw.Name}, client.Limit(limit)); err != nil {
		return nil, fmt.Errorf("list VPNConnections: %w", err)
	}
	var out []sdnv1alpha1.VPNConnection
	for i := range list.Items {
		if list.Items[i].Spec.GatewayRef.Name != gw.Name || !list.Items[i].DeletionTimestamp.IsZero() {
			return nil, fmt.Errorf("inconsistent active VPNConnection gateway index")
		}
		out = append(out, list.Items[i])
		// Never process an unbounded result if a reader ignores List Limit.
		if int64(len(out)) >= limit {
			break
		}
	}
	// Deterministic order so the config checksum and route status are stable.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// overQuota reports why this gateway exceeds a per-tenant guardrail, or "" when
// within limits. A namespace admits its N oldest gateways (oldest-wins, name
// breaking ties — the same total order everything else uses, so the verdict is
// stable); a gateway admits at most M peers.
func (r *VPNGatewayReconciler) overQuota(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	conns []sdnv1alpha1.VPNConnection) (string, error) {
	if maxConns := r.maxConnectionsPerGateway(); len(conns) > maxConns {
		return fmt.Sprintf("gateway has at least %d connections, over the per-gateway limit of %d", len(conns), maxConns), nil
	}
	return r.gatewayQuota(ctx, gw)
}

// filterForbiddenCIDRs strips every cluster-internal / reserved remote CIDR from
// the connections in place (the route-CIDR deny-set), so a forbidden prefix
// never reaches the forwarding grant, the route table, or the tunnel peer
// config. It returns the rejected prefixes (with a reason) for the status
// condition. conns is a local copy — reassigning each RemoteCIDRs to a fresh
// slice never touches the informer cache.
func (r *VPNGatewayReconciler) filterForbiddenCIDRs(conns []sdnv1alpha1.VPNConnection, servedCIDRs []*net.IPNet) []string {
	var rejected []string
	rejectedCount := 0
	for i := range conns {
		allowed := make([]string, 0, len(conns[i].Spec.RemoteCIDRs))
		for _, c := range conns[i].Spec.RemoteCIDRs {
			if reason := r.forbiddenRemoteCIDR(c, servedCIDRs); reason != "" {
				rejectedCount++
				if len(rejected) < 32 {
					rejected = append(rejected, fmt.Sprintf("%.64s (%s)", c, reason))
				}
				continue
			}
			allowed = append(allowed, c)
		}
		conns[i].Spec.RemoteCIDRs = allowed
	}
	if rejectedCount > len(rejected) {
		rejected = append(rejected, fmt.Sprintf("%d additional rejected CIDRs omitted", rejectedCount-len(rejected)))
	}
	return rejected
}

func vpnRouteInputProblem(conns []sdnv1alpha1.VPNConnection) string {
	prefixes := 0
	for i := range conns {
		if len(conns[i].Spec.RemoteCIDRs) > vpnlimits.RoutePrefixes-prefixes {
			return "VPN route prefix candidates exceed 4096"
		}
		prefixes += len(conns[i].Spec.RemoteCIDRs)
	}
	return ""
}

// forbiddenRemoteCIDR returns why a remote CIDR is refused, or "" when allowed.
func (r *VPNGatewayReconciler) forbiddenRemoteCIDR(cidr string, servedCIDRs []*net.IPNet) string {
	if reason := forbiddenRouteCIDR(cidr, r.Config.InternalCIDRs); reason != "" {
		return reason
	}
	_, prefix, _ := net.ParseCIDR(cidr)
	for _, served := range servedCIDRs {
		if cidrsOverlap(prefix, served) {
			return "served VPC"
		}
	}
	return ""
}

func forbiddenRouteCIDR(cidr string, internalCIDRs []*net.IPNet) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return "not a CIDR"
	}
	for _, f := range reservedCIDRs {
		if cidrsOverlap(n, f) {
			return "reserved"
		}
	}
	for _, f := range internalCIDRs {
		if cidrsOverlap(n, f) {
			return "cluster-internal"
		}
	}

	return ""
}

// cidrsOverlap reports whether two prefixes intersect (either contains the
// other's network address) — conservative for the large internal ranges the
// deny-set guards.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// unionRemoteCIDRs collects every connection's remote CIDRs, de-duplicated and
// sorted — the scoped forwarding allowlist.
func unionRemoteCIDRs(conns []sdnv1alpha1.VPNConnection) []string {
	seen := map[string]bool{}
	for i := range conns {
		for _, c := range conns[i].Spec.RemoteCIDRs {
			seen[c] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// unionVPCCIDRs collects every served VPC's CIDRs, de-duplicated and sorted —
// what an active-active hub advertises over BGP.
func unionVPCCIDRs(vpcs []*sdnv1alpha1.VPC) []string {
	seen := map[string]bool{}
	for _, vpc := range vpcs {
		for _, c := range vpc.Spec.CIDRs {
			seen[c] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// servedVPCs resolves the gateway's primary VPC followed by its additional VPCs
// (hub, docs/vpn.md §3.3), all in the gateway's namespace. missing names the
// first reference that resolves to no VPC, as `<field> "<name>"`.
func (r *VPNGatewayReconciler) servedVPCs(ctx context.Context, gw *sdnv1alpha1.VPNGateway) (vpcs []*sdnv1alpha1.VPC, missing string, err error) {
	type ref struct{ field, name string }
	refs := []ref{{"spec.vpcRef", gw.Spec.VPCRef.Name}}
	for i, a := range gw.Spec.AdditionalVPCRefs {
		refs = append(refs, ref{fmt.Sprintf("spec.additionalVPCRefs[%d]", i), a.Name})
	}
	for _, rf := range refs {
		if rf.name != "" {
			vpc := &sdnv1alpha1.VPC{}
			err := r.quotaReader().Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: rf.name}, vpc)
			if err == nil && vpc.DeletionTimestamp.IsZero() && sdnv1alpha1.ValidateVPCCIDRs(vpc.Spec.CIDRs) == nil {
				vpcs = append(vpcs, vpc)
				continue
			}
			if err != nil && !apierrors.IsNotFound(err) {
				return nil, "", err
			}
		}
		return nil, fmt.Sprintf("%s %q", rf.field, rf.name), nil
	}
	return vpcs, "", nil
}

// servedVPCCIDRs parses every served VPC's CIDRs and reports the first pair of
// VPCs whose prefixes overlap — the hub constraint (docs/vpn.md §3.3) — or ""
// when the set is disjoint. A single served VPC is trivially disjoint.
func servedVPCCIDRs(vpcs []*sdnv1alpha1.VPC) (cidrs []*net.IPNet, overlap string) {
	type owned struct {
		vpc string
		net *net.IPNet
	}
	var all []owned
	for _, vpc := range vpcs {
		for _, c := range vpc.Spec.CIDRs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				continue // a malformed VPC CIDR is the VPC's own validation failure
			}
			for _, o := range all {
				if o.vpc != vpc.Name && cidrsOverlap(o.net, n) {
					return nil, fmt.Sprintf("served VPCs %q (%s) and %q (%s) have overlapping CIDRs",
						o.vpc, o.net, vpc.Name, n)
				}
			}
			all = append(all, owned{vpc: vpc.Name, net: n})
			cidrs = append(cidrs, n)
		}
	}
	return cidrs, ""
}

// connectionRoutes renders one route entry per connection with remote CIDRs,
// all toward the given leg Port(s) of one served VPC.
func connectionRoutes(conns []sdnv1alpha1.VPNConnection, vpcPorts []string) []sdnv1alpha1.VPCGatewayRouteStatus {
	var routes []sdnv1alpha1.VPCGatewayRouteStatus
	for i := range conns {
		c := &conns[i]
		if len(c.Spec.RemoteCIDRs) == 0 {
			continue
		}
		routes = append(routes, sdnv1alpha1.VPCGatewayRouteStatus{
			CIDRs: append([]string(nil), c.Spec.RemoteCIDRs...),
			Port:  firstPort(vpcPorts),
			Ports: append([]string(nil), vpcPorts...),
		})
	}
	return routes
}

func firstPort(ports []string) string {
	if len(ports) == 0 {
		return ""
	}
	return ports[0]
}

// applyIPsecAddressPools adds a selected roadwarrior pool CIDR to the local
// connection copy. From this point on pools follow the exact same scoped route
// and forwarding path as site-to-site remote CIDRs.
func applyIPsecAddressPools(gw *sdnv1alpha1.VPNGateway, conns []sdnv1alpha1.VPNConnection) error {
	if gw.Spec.IPsec == nil {
		return nil
	}
	pools := make(map[string]string, len(gw.Spec.IPsec.AddressPools))
	for _, pool := range gw.Spec.IPsec.AddressPools {
		if problem := vpnlimits.IPsecPoolNameProblem(pool.Name, true); problem != "" {
			return fmt.Errorf("%s", problem)
		}
		pools[pool.Name] = pool.CIDR
	}
	for i := range conns {
		if conns[i].Spec.IPsec == nil || conns[i].Spec.IPsec.AddressPool == "" {
			continue
		}
		if problem := vpnlimits.IPsecPoolNameProblem(conns[i].Spec.IPsec.AddressPool, false); problem != "" {
			return fmt.Errorf("%s", problem)
		}
		cidr, ok := pools[conns[i].Spec.IPsec.AddressPool]
		if !ok {
			return fmt.Errorf("VPNConnection %q selects an unknown IPsec address pool", conns[i].Name)
		}
		if !slices.Contains(conns[i].Spec.RemoteCIDRs, cidr) {
			conns[i].Spec.RemoteCIDRs = append(append([]string(nil), conns[i].Spec.RemoteCIDRs...), cidr)
		}
	}
	return nil
}

func nonEmptyRouteConns(conns []sdnv1alpha1.VPNConnection) []sdnv1alpha1.VPNConnection {
	var out []sdnv1alpha1.VPNConnection
	for i := range conns {
		if len(conns[i].Spec.RemoteCIDRs) > 0 {
			out = append(out, conns[i])
		}
	}
	return out
}

// ensureKeypairs persists one stable identity per active endpoint. The legacy
// unnumbered keys are aliases for identity zero so existing gateways retain
// their public key when active-active is enabled.
func (r *VPNGatewayReconciler) ensureKeypairs(ctx context.Context, gw *sdnv1alpha1.VPNGateway, count int) (privates, publics []string, err error) {
	name := gw.Name + "-wg-keys"
	sec := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, sec)
	if getErr != nil && !apierrors.IsNotFound(getErr) {
		return nil, nil, fmt.Errorf("get keypair secret: %w", getErr)
	}
	if getErr == nil {
		if err := requireVPNOwner(sec, gw); err != nil {
			return nil, nil, err
		}
	}
	if count < 1 {
		count = 1
	}
	data := map[string][]byte{}
	if getErr == nil {
		for key, value := range sec.Data {
			data[key] = append([]byte(nil), value...)
		}
	}
	for i := 0; i < count; i++ {
		privateName, publicName := fmt.Sprintf("privateKey%d", i), fmt.Sprintf("publicKey%d", i)
		private := string(data[privateName])
		public := string(data[publicName])
		if i == 0 && private == "" {
			private, public = string(data["privateKey"]), string(data["publicKey"])
		}
		if private != "" {
			var valid bool
			private, valid = vpnlimits.WireGuardSecretKey(private)
			if !valid {
				return nil, nil, fmt.Errorf("stored WireGuard private key %d has an invalid encoding", i)
			}
		}
		if public != "" {
			var valid bool
			public, valid = vpnlimits.WireGuardSecretKey(public)
			if !valid {
				return nil, nil, fmt.Errorf("stored WireGuard public key %d has an invalid encoding", i)
			}
		}
		if private != "" && public == "" {
			parsed, parseErr := wgtypes.ParseKey(private)
			if parseErr != nil {
				return nil, nil, fmt.Errorf("parse stored wireguard key %d: %w", i, parseErr)
			}
			public = parsed.PublicKey().String()
		}
		if private == "" {
			key, generateErr := wgtypes.GeneratePrivateKey()
			if generateErr != nil {
				return nil, nil, fmt.Errorf("generate wireguard key %d: %w", i, generateErr)
			}
			private, public = key.String(), key.PublicKey().String()
		}
		data[privateName], data[publicName] = []byte(private), []byte(public)
		privates, publics = append(privates, private), append(publics, public)
	}
	data["privateKey"], data["publicKey"] = data["privateKey0"], data["publicKey0"]
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return nil, nil, err
	}
	if getErr == nil {
		if equality.Semantic.DeepEqual(sec.Data, desired.Data) {
			return privates, publics, nil
		}
		sec.Data = desired.Data
		if err := r.Update(ctx, sec); err != nil {
			return nil, nil, fmt.Errorf("update keypair secret: %w", err)
		}
		return privates, publics, nil
	}
	if err := r.Create(ctx, desired); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, nil, fmt.Errorf("keypair secret was created concurrently")
		}
		return nil, nil, fmt.Errorf("create keypair secret: %w", err)
	}
	return privates, publics, nil
}

// buildConfig renders the appliance's tunnel config JSON, dispatching on the
// gateway's backend. Its bytes go into a Secret the appliance mounts.
// The MTU budget follows the PRIMARY served VPC: its leg carries the default
// route, hence the encapsulated tunnel traffic.
func (r *VPNGatewayReconciler) buildConfig(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	servedVPCs []*sdnv1alpha1.VPC, backend string, privateKeys []string, conns []sdnv1alpha1.VPNConnection) ([]byte, error) {
	mtu := tunnelMTU(servedVPCs[0].Spec.MTU, backend)
	if isWGClientGateway(gw) {
		mtu = wgClientTunnelMTU(servedVPCs)
	}
	if backend == backendIPsec {
		return r.buildIPsecConfig(ctx, gw, servedVPCs, conns, mtu)
	}
	return r.buildWGConfig(ctx, gw, servedVPCs, privateKeys, conns, mtu)
}

// tunnelMTU reserves worst-case outer overhead so the kernel can emit PMTU
// feedback before Geneve + tunnel encapsulation exceeds the VPC leg's MTU.
func tunnelMTU(vpcMTU int32, backend string) int {
	if vpcMTU <= 0 {
		return 0
	}
	overhead := int32(80) // WireGuard over an IPv6 outer path.
	if backend == backendIPsec {
		overhead = 128 // conservative IKEv2 ESP-in-UDP allowance.
	}
	if vpcMTU <= overhead {
		return 0
	}
	return int(vpcMTU - overhead)
}

// buildWGConfig renders the WireGuard appliance config — the private key, the
// listen port, and one peer per connection (reading each connection's optional
// preshared-key Secret).
func (r *VPNGatewayReconciler) buildWGConfig(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	servedVPCs []*sdnv1alpha1.VPC, privateKeys []string, conns []sdnv1alpha1.VPNConnection, mtu int) ([]byte, error) {
	if len(privateKeys) == 0 || len(privateKeys) > 2 {
		return nil, fmt.Errorf("WireGuard requires one or two private keys")
	}
	for _, key := range privateKeys {
		if !vpnlimits.WireGuardKey(key) {
			return nil, fmt.Errorf("WireGuard private key has an invalid encoding")
		}
	}
	for i := range conns {
		wg := conns[i].Spec.WireGuard
		if wg == nil {
			continue
		}
		if problem := vpnlimits.WireGuardPeerProblem(vpnlimits.WireGuardPeer{
			PublicKey: wg.PeerPublicKey, PublicKeys: wg.PeerPublicKeys,
			Endpoint: wg.PeerEndpoint, Endpoints: wg.PeerEndpoints, Keepalive: int64(wg.PersistentKeepalive),
		}); problem != "" {
			return nil, fmt.Errorf("WireGuard peer %d: %s", i, problem)
		}
	}
	type peer struct {
		Name                    string   `json:"name,omitempty"`
		PublicKey               string   `json:"publicKey"`
		Endpoint                string   `json:"endpoint,omitempty"`
		AllowedIPs              []string `json:"allowedIPs"`
		PresharedKey            string   `json:"presharedKey,omitempty"`
		Keepalive               int      `json:"keepalive,omitempty"`
		AllowedDestinationCIDRs []string `json:"allowedDestinationCIDRs,omitempty"`
	}
	cfg := struct {
		PrivateKey    string            `json:"privateKey"`
		PrivateKeys   []string          `json:"privateKeys,omitempty"`
		ListenPort    int               `json:"listenPort,omitempty"`
		MTU           int               `json:"mtu,omitempty"`
		Peers         []peer            `json:"peers"`
		PeerInstances [][]peer          `json:"peerInstances,omitempty"`
		Routing       *vpnRoutingConfig `json:"routing,omitempty"`
		ClientMode    bool              `json:"clientMode,omitempty"`
	}{
		PrivateKeys: append([]string(nil), privateKeys...),
		ListenPort:  int(r.listenPort(gw)),
		MTU:         mtu,
		Routing:     routingConfigFor(gw, servedVPCs),
		ClientMode:  isWGClientGateway(gw),
	}
	if len(privateKeys) > 0 {
		cfg.PrivateKey = privateKeys[0]
	}
	instanceCount := max(1, len(privateKeys))
	peerInstances := make([][]peer, instanceCount)
	for i := range conns {
		c := &conns[i]
		if c.Spec.WireGuard == nil {
			continue
		}
		if keys := c.Spec.WireGuard.PeerPublicKeys; len(keys) > 0 && len(keys) != instanceCount {
			return nil, fmt.Errorf("VPNConnection %q has %d WireGuard peer keys, expected %d", c.Name, len(keys), instanceCount)
		}
		if endpoints := c.Spec.WireGuard.PeerEndpoints; len(endpoints) > 0 && len(endpoints) != instanceCount {
			return nil, fmt.Errorf("VPNConnection %q has %d WireGuard peer endpoints, expected %d", c.Name, len(endpoints), instanceCount)
		}
		psk := ""
		if ref := c.Spec.WireGuard.PresharedKeySecretRef; ref != "" {
			var err error
			psk, err = r.readPSK(ctx, gw.Namespace, ref)
			if err != nil {
				return nil, err
			}
			var valid bool
			psk, valid = vpnlimits.WireGuardSecretKey(psk)
			if !valid {
				return nil, fmt.Errorf("WireGuard peer %d preshared key has an invalid encoding", i)
			}
		}
		for instance := range peerInstances {
			publicKey, endpoint := c.Spec.WireGuard.PeerPublicKey, c.Spec.WireGuard.PeerEndpoint
			if len(c.Spec.WireGuard.PeerPublicKeys) > 0 {
				publicKey = c.Spec.WireGuard.PeerPublicKeys[instance]
			}
			if len(c.Spec.WireGuard.PeerEndpoints) > 0 {
				endpoint = c.Spec.WireGuard.PeerEndpoints[instance]
			}
			peerInstances[instance] = append(peerInstances[instance], peer{
				Name: c.Name, PublicKey: publicKey, Endpoint: endpoint,
				AllowedIPs:   append([]string(nil), c.Spec.RemoteCIDRs...),
				PresharedKey: psk, Keepalive: int(c.Spec.WireGuard.PersistentKeepalive),
				AllowedDestinationCIDRs: func() []string {
					if c.Spec.WireGuard.Client != nil {
						return clientDestinationCIDRs(c, servedVPCs)
					}
					return nil
				}(),
			})
		}
	}
	cfg.Peers = peerInstances[0]
	if len(peerInstances) > 1 {
		cfg.PeerInstances = peerInstances
	}
	// #nosec G117 -- Appliance credentials are deliberately serialized into a Kubernetes Secret, mounted read-only with mode 0600; never an API response or log.
	return json.Marshal(cfg)
}

// buildIPsecConfig renders the strongSwan appliance config — one peer per IPsec
// connection, each with its PSK (read from the referenced Secret), remote CIDRs,
// proposals (connection override or gateway default), and a stable xfrm if_id
// derived from the connection name so the route-based tunnel binds to its own
// interface.
func (r *VPNGatewayReconciler) buildIPsecConfig(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	servedVPCs []*sdnv1alpha1.VPC, conns []sdnv1alpha1.VPNConnection, mtu int) ([]byte, error) {
	if gw.Spec.IPsec != nil {
		if problem := vpnlimits.IPsecScalarProblem("", gw.Spec.IPsec.LocalIdentity); problem != "" {
			return nil, fmt.Errorf("%s", problem)
		}
		if problem := vpnlimits.IPsecProposalProblem(gw.Spec.IPsec.Proposals); problem != "" {
			return nil, fmt.Errorf("%s", problem)
		}
		if len(gw.Spec.IPsec.AddressPools) > vpnlimits.AddressPools {
			return nil, fmt.Errorf("IPsec address pools exceed 128")
		}
		for _, pool := range gw.Spec.IPsec.AddressPools {
			if problem := vpnlimits.IPsecPoolNameProblem(pool.Name, true); problem != "" {
				return nil, fmt.Errorf("%s", problem)
			}
		}
	}
	for i := range conns {
		if ipsec := conns[i].Spec.IPsec; ipsec != nil {
			certificate, eap := "", ""
			if ipsec.AddressPool != "" && ipsec.Auth.Certificate == nil && ipsec.Auth.EAP == nil {
				return nil, fmt.Errorf("IPsec address pools require certificate or EAP authentication")
			}
			if ipsec.Auth.EAP != nil && ipsec.AddressPool == "" {
				return nil, fmt.Errorf("IPsec EAP authentication requires an address pool")
			}
			if ipsec.AddressPool != "" && ipsec.StartAction == sdnv1alpha1.VPNIPsecStartActionStart {
				return nil, fmt.Errorf("pooled IPsec connections must remain responder-only")
			}
			if problem := vpnlimits.IPsecPoolNameProblem(ipsec.AddressPool, false); problem != "" {
				return nil, fmt.Errorf("%s", problem)
			}
			if ipsec.Auth.Certificate != nil {
				certificate = ipsec.Auth.Certificate.RemoteIdentity
			}
			if ipsec.Auth.EAP != nil {
				eap = ipsec.Auth.EAP.Identity
			}
			if problem := vpnlimits.IPsecScalarProblem(ipsec.PeerAddress, ipsec.RemoteIdentity, certificate, eap); problem != "" {
				return nil, fmt.Errorf("%s", problem)
			}
			if problem := vpnlimits.IPsecProposalProblem(ipsec.Proposals); problem != "" {
				return nil, fmt.Errorf("%s", problem)
			}
		}
	}
	type credentials struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privateKey"`
		CA          string `json:"ca,omitempty"`
		LocalID     string `json:"localIdentity,omitempty"`
	}
	type addressPool struct {
		Name string   `json:"name"`
		CIDR string   `json:"cidr"`
		DNS  []string `json:"dns,omitempty"`
	}
	type peer struct {
		Name        string   `json:"name"`
		LocalCIDRs  []string `json:"localCIDRs"`
		PeerAddress string   `json:"peerAddress,omitempty"`
		StartAction string   `json:"startAction,omitempty"`
		PSK         string   `json:"psk,omitempty"`
		RemoteCIDRs []string `json:"remoteCIDRs"`
		Proposals   []string `json:"proposals,omitempty"`
		DPDDelay    int      `json:"dpdDelay,omitempty"`
		IfID        uint32   `json:"ifId"`
		AuthMode    string   `json:"authMode,omitempty"`
		RemoteID    string   `json:"remoteIdentity,omitempty"`
		EAPIdentity string   `json:"eapIdentity,omitempty"`
		EAPPassword string   `json:"eapPassword,omitempty"`
		AddressPool string   `json:"addressPool,omitempty"`
	}
	var defProposals []string
	if gw.Spec.IPsec != nil {
		defProposals = gw.Spec.IPsec.Proposals
	}
	cfg := struct {
		MTU         int               `json:"mtu,omitempty"`
		LocalID     string            `json:"localIdentity,omitempty"`
		Credentials *credentials      `json:"credentials,omitempty"`
		Pools       []addressPool     `json:"pools,omitempty"`
		Peers       []peer            `json:"peers"`
		Routing     *vpnRoutingConfig `json:"routing,omitempty"`
	}{MTU: mtu, Routing: routingConfigFor(gw, servedVPCs)}
	if gw.Spec.IPsec != nil {
		cfg.LocalID = gw.Spec.IPsec.LocalIdentity
		for _, pool := range gw.Spec.IPsec.AddressPools {
			cfg.Pools = append(cfg.Pools, addressPool{Name: pool.Name, CIDR: pool.CIDR, DNS: append([]string(nil), pool.DNS...)})
		}
		if ref := gw.Spec.IPsec.CredentialSecretRef; ref != "" {
			cert, key, embeddedCA, err := r.readTLSCredential(ctx, gw.Namespace, ref)
			if err != nil {
				return nil, err
			}
			ca := embeddedCA
			if caRef := gw.Spec.IPsec.TrustedCASecretRef; caRef != "" {
				ca, err = r.readSecretValue(ctx, gw.Namespace, caRef, "ca.crt")
				if err != nil {
					return nil, err
				}
			}
			cfg.Credentials = &credentials{Certificate: cert, PrivateKey: key, CA: ca, LocalID: gw.Spec.IPsec.LocalIdentity}
		}
	}
	needsCredential, needsCA := false, false
	for i := range conns {
		if conns[i].Spec.IPsec == nil {
			continue
		}
		if conns[i].Spec.IPsec.Auth.Certificate != nil {
			needsCredential, needsCA = true, true
		}
		if conns[i].Spec.IPsec.Auth.EAP != nil {
			needsCredential = true
		}
	}
	if needsCredential && cfg.Credentials == nil {
		return nil, fmt.Errorf("certificate/EAP authentication requires spec.ipsec.credentialSecretRef")
	}
	if needsCA && cfg.Credentials.CA == "" {
		return nil, fmt.Errorf("certificate authentication requires ca.crt in the credential Secret or spec.ipsec.trustedCASecretRef")
	}
	identities := map[string]string{}
	ifIDs := map[uint32]string{}
	for i := range conns {
		c := &conns[i]
		if c.Spec.IPsec == nil {
			continue
		}
		proposals := c.Spec.IPsec.Proposals
		if len(proposals) == 0 {
			proposals = defProposals
		}
		p := peer{
			Name:        c.Name,
			LocalCIDRs:  unionVPCCIDRs(servedVPCs),
			PeerAddress: c.Spec.IPsec.PeerAddress,
			StartAction: ipsecStartAction(c.Spec.IPsec),
			RemoteCIDRs: append([]string(nil), c.Spec.RemoteCIDRs...),
			Proposals:   proposals,
			DPDDelay:    int(c.Spec.IPsec.DPDDelay),
			IfID:        ipsecIfID(c.Name),
			AddressPool: c.Spec.IPsec.AddressPool,
		}
		interfaceOwner := "peer:" + c.Name
		if p.AddressPool != "" {
			// The pool's return route is shared. Separate interfaces would let
			// the last peer replace every other client's route to this pool.
			interfaceOwner = "pool:" + p.AddressPool
			p.IfID = ipsecIfID(interfaceOwner)
		}
		if previous, exists := ifIDs[p.IfID]; exists && previous != interfaceOwner {
			return nil, fmt.Errorf("IPsec interface ID collision between %s and %s", previous, c.Name)
		}
		ifIDs[p.IfID] = interfaceOwner
		if ref := c.Spec.IPsec.Auth.PSKSecretRef; ref != "" {
			p.RemoteID = c.Spec.IPsec.RemoteIdentity
			if p.RemoteID == "" {
				if ip := net.ParseIP(p.PeerAddress); ip != nil {
					p.RemoteID = ip.String()
				}
			}
			if !exactIKEIdentity(p.RemoteID) {
				return nil, fmt.Errorf("PSK peer %s requires an exact remoteIdentity or IP peerAddress", c.Name)
			}
			psk, err := r.readPSK(ctx, gw.Namespace, ref)
			if err != nil {
				return nil, err
			}
			p.PSK = psk
		}
		if auth := c.Spec.IPsec.Auth.Certificate; auth != nil {
			p.AuthMode = "certificate"
			p.RemoteID = auth.RemoteIdentity
		}
		if auth := c.Spec.IPsec.Auth.EAP; auth != nil {
			password, err := r.readSecretValueBounded(ctx, gw.Namespace, auth.SecretRef, vpnlimits.IPsecAuthBytes, "password", "eap")
			if err != nil {
				return nil, err
			}
			p.AuthMode = "eap"
			p.EAPIdentity = auth.Identity
			p.EAPPassword = password
		}
		authMethods := 0
		if p.PSK != "" {
			authMethods++
		}
		if c.Spec.IPsec.Auth.Certificate != nil {
			authMethods++
		}
		if c.Spec.IPsec.Auth.EAP != nil {
			authMethods++
		}
		if authMethods != 1 {
			return nil, fmt.Errorf("IPsec peer %s requires exactly one authentication method", c.Name)
		}
		identity := p.RemoteID
		if p.AuthMode == "eap" {
			identity = p.EAPIdentity
		}
		if !exactIKEIdentity(identity) {
			return nil, fmt.Errorf("IPsec peer %s requires an exact identity", c.Name)
		}
		if identity != "" {
			key := vpnidentity.Key(identity)
			if previous, exists := identities[key]; exists {
				return nil, fmt.Errorf("IPsec identity reused by %s and %s", previous, c.Name)
			}
			identities[key] = c.Name
		}
		cfg.Peers = append(cfg.Peers, p)
	}
	return json.Marshal(cfg)
}

func exactIKEIdentity(identity string) bool {
	return vpnidentity.Exact(identity)
}

// routingConfigFor renders the active-active BGP contract; a hub advertises
// every served VPC's CIDRs (docs/vpn.md §3.3).
func routingConfigFor(gw *sdnv1alpha1.VPNGateway, servedVPCs []*sdnv1alpha1.VPC) *vpnRoutingConfig {
	if haMode(gw) != sdnv1alpha1.VPNGatewayHAModeActiveActive || gw.Spec.HA == nil || gw.Spec.HA.ActiveActive == nil {
		return nil
	}
	aa := gw.Spec.HA.ActiveActive
	return &vpnRoutingConfig{
		LocalASN:       aa.LocalASN,
		PeerASN:        aa.PeerASN,
		PeerAddresses:  append([]string(nil), aa.PeerAddresses...),
		AdvertiseCIDRs: unionVPCCIDRs(servedVPCs),
		BFD:            aa.BFD,
	}
}

func (r *VPNGatewayReconciler) readTLSCredential(ctx context.Context, ns, name string) (cert, key, ca string, err error) {
	if !vpnlimits.ObjectName(name) {
		return "", "", "", fmt.Errorf("invalid TLS credential Secret reference")
	}
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, sec); err != nil {
		return "", "", "", fmt.Errorf("read TLS credential Secret %q: %w", name, err)
	}
	for _, field := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, "ca.crt"} {
		if len(sec.Data[field]) > vpnlimits.IPsecTLSBytes {
			return "", "", "", fmt.Errorf("TLS credential exceeds VICI byte limit")
		}
	}
	cert = string(sec.Data[corev1.TLSCertKey])
	key = string(sec.Data[corev1.TLSPrivateKeyKey])
	ca = string(sec.Data["ca.crt"])
	if cert == "" || key == "" {
		return "", "", "", fmt.Errorf("TLS credential Secret %q must contain %q and %q",
			name, corev1.TLSCertKey, corev1.TLSPrivateKeyKey)
	}
	return cert, key, ca, nil
}

func (r *VPNGatewayReconciler) readSecretValue(ctx context.Context, ns, name string, keys ...string) (string, error) {
	return r.readSecretValueBounded(ctx, ns, name, vpnlimits.IPsecTLSBytes, keys...)
}

func (r *VPNGatewayReconciler) readSecretValueBounded(ctx context.Context, ns, name string, maxBytes int, keys ...string) (string, error) {
	if !vpnlimits.ObjectName(name) {
		return "", fmt.Errorf("invalid Secret reference")
	}
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, sec); err != nil {
		return "", fmt.Errorf("read Secret %q: %w", name, err)
	}
	for _, key := range keys {
		if value := sec.Data[key]; len(value) != 0 {
			if len(value) > maxBytes {
				return "", fmt.Errorf("Secret credential exceeds byte limit")
			}
			return string(value), nil
		}
	}
	if len(sec.Data) == 1 {
		for _, value := range sec.Data {
			if len(value) > 0 {
				if len(value) > maxBytes {
					return "", fmt.Errorf("Secret credential exceeds byte limit")
				}
				return string(value), nil
			}
		}
	}
	return "", fmt.Errorf("Secret %q contains none of the required keys %v", name, keys)
}

func ipsecStartAction(spec *sdnv1alpha1.VPNConnectionIPsec) string {
	if spec.AddressPool != "" {
		return "none"
	}
	if spec.StartAction == sdnv1alpha1.VPNIPsecStartActionNone {
		return "none"
	}
	if spec.StartAction == sdnv1alpha1.VPNIPsecStartActionStart || spec.PeerAddress != "" {
		return "start"
	}
	return "none"
}

// ipsecIfID maps a connection name to a stable, non-zero 32-bit xfrm if_id (the
// SA ⇄ xfrm-interface binding). A hash keeps it stable across reconciles; a
// collisions are rejected before the configuration is installed.
func ipsecIfID(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	id := h.Sum32()
	if id == 0 {
		id = 1
	}
	return id
}

// readPSK reads a preshared key from a Secret in the gateway's namespace. The
// key is taken from the conventional "psk" or "presharedKey" data key, or the
// Secret's sole entry when it has exactly one.
func (r *VPNGatewayReconciler) readPSK(ctx context.Context, ns, name string) (string, error) {
	value, err := r.readSecretValueBounded(ctx, ns, name, vpnlimits.IPsecAuthBytes, "psk", "presharedKey")
	if err != nil {
		return "", fmt.Errorf("read preshared-key %w", err)
	}
	return value, nil
}

func (r *VPNGatewayReconciler) listenPort(gw *sdnv1alpha1.VPNGateway) int32 {
	if gw.Spec.WireGuard != nil && gw.Spec.WireGuard.ListenPort > 0 {
		return gw.Spec.WireGuard.ListenPort
	}
	if r.Config.DefaultListenPort > 0 {
		return r.Config.DefaultListenPort
	}
	return 51820
}

// ensureConfigSecret writes the tunnel config Secret and returns its content
// checksum (which the appliance pod template carries so a peer change rolls it).
func (r *VPNGatewayReconciler) ensureConfigSecret(ctx context.Context, gw *sdnv1alpha1.VPNGateway, cfgJSON []byte) (string, error) {
	sum := sha256.Sum256(cfgJSON)
	checksum := hex.EncodeToString(sum[:])
	name := gw.Name + "-wg-config"
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"config.json": cfgJSON},
	}
	if haMode(gw) == sdnv1alpha1.VPNGatewayHAModeLiveMigration && gw.Spec.HA != nil &&
		gw.Spec.HA.VirtualMachine != nil && gw.Spec.HA.VirtualMachine.CloudInitSecretRef == "" {
		desired.Data["userdata"] = []byte(vpnCloudInit(backendOf(gw), cfgJSON))
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return "", err
	}
	existing := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return "", fmt.Errorf("create config secret: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("get config secret: %w", err)
	default:
		if err := requireVPNOwner(existing, gw); err != nil {
			return "", err
		}
		if !equality.Semantic.DeepEqual(existing.Data, desired.Data) {
			existing.Data = desired.Data
			if err := r.Update(ctx, existing); err != nil {
				return "", fmt.Errorf("update config secret: %w", err)
			}
		}
	}
	return checksum, nil
}

func vpnCloudInit(backend string, cfgJSON []byte) string {
	return fmt.Sprintf(`#cloud-config
write_files:
- path: /etc/cozyplane-vpn/config.json
  owner: root:root
  permissions: '0600'
  encoding: b64
  content: %s
- path: /etc/cozyplane-vpn/backend
  owner: root:root
  permissions: '0600'
  content: |
    VPN_BACKEND=%s
    VPN_CONFIG_CHECKSUM=%x
runcmd:
- [systemctl, enable, --now, cozyplane-vpn-appliance.service]
- [systemctl, restart, cozyplane-vpn-appliance.service]
`, base64.StdEncoding.EncodeToString(cfgJSON), backend, sha256.Sum256(cfgJSON))
}

// ensureBindings reconciles one VPCBinding per served VPC: each authorizes the
// appliance to attach to that VPC and grants its scoped forwarding right (the
// union of the connections' remote CIDRs). Same namespace as the gateway; the
// controller holds the authority a tenant would not. Bindings for VPCs no
// longer served are pruned by label (docs/vpn.md §3.3).
func (r *VPNGatewayReconciler) ensureBindings(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	servedVPCs []*sdnv1alpha1.VPC, fwdCIDRs []string, clientConns ...[]sdnv1alpha1.VPNConnection) error {
	keep := map[string]bool{}
	for i, vpc := range servedVPCs {
		name := vpnBindingName(gw.Name, vpc.Name, i == 0)
		keep[name] = true
		legCIDRs := fwdCIDRs
		if isWGClientGateway(gw) {
			if len(clientConns) != 1 {
				return fmt.Errorf("WireGuard bindings require the complete allocated client snapshot")
			}
			legCIDRs = unionRemoteCIDRs(connectionsForVPC(clientConns[0], vpc.Name))
		}
		desired := &sdnv1alpha1.VPCBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: gw.Namespace,
				Labels:    map[string]string{vpnGatewayLabel: gw.Name},
			},
			Spec: sdnv1alpha1.VPCBindingSpec{
				VPCRef:          sdnv1alpha1.VPCRef{Namespace: gw.Namespace, Name: vpc.Name},
				AllowForwarding: len(legCIDRs) > 0,
				ForwardingCIDRs: legCIDRs,
			},
		}
		if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
			return err
		}
		existing := &sdnv1alpha1.VPCBinding{}
		err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
		switch {
		case apierrors.IsNotFound(err):
			if err := r.Create(ctx, desired); err != nil {
				return fmt.Errorf("create VPCBinding: %w", err)
			}
		case err != nil:
			return fmt.Errorf("get VPCBinding: %w", err)
		default:
			if err := requireVPNOwner(existing, gw); err != nil {
				return err
			}
			if !equality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
				existing.Spec = desired.Spec
				if err := r.Update(ctx, existing); err != nil {
					return fmt.Errorf("update VPCBinding: %w", err)
				}
			}
		}
	}
	return r.pruneVPCBindings(ctx, gw, keep)
}

// vpnBindingName names the forwarding-grant binding for one served VPC. The
// primary keeps the historical `<gw>-vpn` so existing gateways are untouched;
// an additional VPC gets `<gw>-vpn-<vpc>`, hashed down when that would exceed
// the 63-character object-name limit.
func vpnBindingName(gateway, vpc string, primary bool) string {
	if primary {
		return gateway + "-vpn"
	}
	name := gateway + "-vpn-" + vpc
	if len(name) <= 63 {
		return name
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%s-%08x", name[:63-9], h.Sum32())
}

// pruneVPCBindings deletes this gateway's bindings not named in keep (all of
// them when keep is nil), so a VPC removed from the served set loses its grant.
func (r *VPNGatewayReconciler) pruneVPCBindings(ctx context.Context, gw *sdnv1alpha1.VPNGateway, keep map[string]bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	continuation := ""
	for {
		var list sdnv1alpha1.VPCBindingList
		if err := r.quotaReader().List(ctx, &list, client.InNamespace(gw.Namespace), client.MatchingLabels{vpnGatewayLabel: gw.Name}, client.Limit(200), client.Continue(continuation)); err != nil {
			return fmt.Errorf("list VPN forwarding-grant VPCBindings: %w", err)
		}
		for i := range list.Items {
			if keep[list.Items[i].Name] {
				continue
			}
			if err := r.deleteVPNOwned(ctx, gw, &list.Items[i]); err != nil {
				return fmt.Errorf("delete stale VPN binding: %w", err)
			}
		}
		if list.Continue == "" {
			return nil
		}
		continuation = list.Continue
	}
}

// vpnAttachmentAnnotations requests the appliance's VPC leg(s). A single-VPC
// gateway keeps the original AnnotationVPC (existing pods are untouched); a hub
// asks for one leg per served VPC through AnnotationNetworks, primary first —
// entry 0 carries the fabric handle and the default route. The two annotations
// are never both set: the CNI rejects that.
func vpnAttachmentAnnotations(gw *sdnv1alpha1.VPNGateway) map[string]string {
	if len(gw.Spec.AdditionalVPCRefs) == 0 {
		return map[string]string{sdnv1alpha1.AnnotationVPC: gw.Spec.VPCRef.Name}
	}
	type entry struct {
		VPC string `json:"vpc"`
	}
	entries := []entry{{VPC: gw.Spec.VPCRef.Name}}
	for _, ref := range gw.Spec.AdditionalVPCRefs {
		entries = append(entries, entry{VPC: ref.Name})
	}
	raw, _ := json.Marshal(entries)
	return map[string]string{sdnv1alpha1.AnnotationNetworks: string(raw)}
}

// ensureDeployment reconciles the tunnel appliance — a VPC-attached pod running
// cozyplane-vpn-gateway, mounting the config Secret. Recreate strategy: it
// claims a Port in the VPC and a rolling replacement would race it.
func (r *VPNGatewayReconciler) ensureApplianceWorkload(ctx context.Context, gw *sdnv1alpha1.VPNGateway, backend, checksum string) error {
	if haMode(gw) == sdnv1alpha1.VPNGatewayHAModeLiveMigration {
		if err := r.deletePodAppliance(ctx, gw); err != nil {
			return err
		}
		return r.ensureVirtualMachine(ctx, gw, backend, checksum)
	}
	vm := vpnVirtualMachineObject(gw.Namespace, gw.Name+"-vpn")
	if err := r.deleteVPNOwned(ctx, gw, vm); err != nil {
		return fmt.Errorf("delete VM appliance before pod mode: %w", err)
	}
	if haMode(gw) == sdnv1alpha1.VPNGatewayHAModeActiveActive {
		deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace}}
		if err := r.deleteVPNOwned(ctx, gw, deployment); err != nil {
			return fmt.Errorf("delete deployment before active-active mode: %w", err)
		}
		if err := r.ensureHeadlessService(ctx, gw); err != nil {
			return err
		}
		return r.ensureStatefulSet(ctx, gw, backend, checksum)
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace}}
	if err := r.deleteVPNOwned(ctx, gw, statefulSet); err != nil {
		return fmt.Errorf("delete active-active appliance before deployment mode: %w", err)
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn-headless", Namespace: gw.Namespace}}
	if err := r.deleteVPNOwned(ctx, gw, service); err != nil {
		return fmt.Errorf("delete active-active headless service: %w", err)
	}
	return r.ensureDeployment(ctx, gw, backend, checksum)
}

func (r *VPNGatewayReconciler) deletePodAppliance(ctx context.Context, gw *sdnv1alpha1.VPNGateway) error {
	objects := []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn-headless", Namespace: gw.Namespace}},
	}
	for _, object := range objects {
		if err := r.deleteVPNOwned(ctx, gw, object); err != nil {
			return fmt.Errorf("delete pod appliance %s: %w", object.GetName(), err)
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) ensureVirtualMachine(ctx context.Context, gw *sdnv1alpha1.VPNGateway, backend, checksum string) error {
	if gw.Spec.HA == nil || gw.Spec.HA.VirtualMachine == nil {
		return errors.New("LiveMigration requires virtualMachine configuration")
	}
	desired := r.virtualMachine(gw, checksum)
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return err
	}
	existing := vpnVirtualMachineObject(gw.Namespace, desired.GetName())
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create KubeVirt VPN appliance: %w", err)
		}
	case err != nil:
		return fmt.Errorf("get KubeVirt VPN appliance: %w", err)
	default:
		if err := requireVPNOwner(existing, gw); err != nil {
			return err
		}
		if !equality.Semantic.DeepEqual(existing.Object["spec"], desired.Object["spec"]) ||
			!equality.Semantic.DeepEqual(existing.GetLabels(), desired.GetLabels()) ||
			!equality.Semantic.DeepEqual(existing.GetOwnerReferences(), desired.GetOwnerReferences()) {
			existing.Object["spec"] = desired.Object["spec"]
			existing.SetLabels(desired.GetLabels())
			existing.SetOwnerReferences(desired.GetOwnerReferences())
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update KubeVirt VPN appliance: %w", err)
			}
			// KubeVirt applies template changes to the next VMI, not the running
			// guest. Recreate that guest so a rotated peer/credential is actually
			// consumed from cloud-init; the persistent Port remains stable.
			vmi := vpnVirtualMachineInstanceObject(gw.Namespace, desired.GetName())
			if err := r.deleteVPNOwned(ctx, existing, vmi); err != nil {
				return fmt.Errorf("restart KubeVirt VPN appliance after config update: %w", err)
			}
		}
	}
	_ = backend // encoded in controller-owned cloud-init; retained for call-site clarity.
	return nil
}

func (r *VPNGatewayReconciler) virtualMachine(gw *sdnv1alpha1.VPNGateway, checksum string) *unstructured.Unstructured {
	vmSpec := gw.Spec.HA.VirtualMachine
	cloudInitSecret := vmSpec.CloudInitSecretRef
	if cloudInitSecret == "" {
		cloudInitSecret = gw.Name + "-wg-config"
	}
	desired := vpnVirtualMachineObject(gw.Namespace, gw.Name+"-vpn")
	desired.SetLabels(map[string]string{"app": "cozyplane-vpn-gateway", vpnGatewayLabel: gw.Name})
	desired.Object["spec"] = map[string]any{
		"runStrategy": "Always",
		"template": map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{"app": "cozyplane-vpn-gateway", vpnGatewayLabel: gw.Name},
				"annotations": map[string]any{
					sdnv1alpha1.AnnotationVPC:                             gw.Spec.VPCRef.Name,
					vpnConfigChecksumAnnotation:                           checksum,
					"kubevirt.io/allow-pod-bridge-network-live-migration": "",
				},
			},
			"spec": map[string]any{
				"evictionStrategy": "LiveMigrate",
				"domain": map[string]any{
					"cpu":       map[string]any{"cores": int64(2)},
					"resources": map[string]any{"requests": map[string]any{"memory": "1Gi"}},
					"devices": map[string]any{
						"disks": []any{
							map[string]any{"name": "rootdisk", "disk": map[string]any{"bus": "virtio"}},
							map[string]any{"name": "state", "disk": map[string]any{"bus": "virtio"}},
							map[string]any{"name": "cloudinit", "disk": map[string]any{"bus": "virtio"}},
						},
						"interfaces": []any{map[string]any{"name": "default", "bridge": map[string]any{}}},
					},
				},
				"networks": []any{map[string]any{"name": "default", "pod": map[string]any{}}},
				"volumes": []any{
					map[string]any{"name": "rootdisk", "containerDisk": map[string]any{"image": vmSpec.Image}},
					map[string]any{"name": "state", "persistentVolumeClaim": map[string]any{"claimName": vmSpec.StateClaimName}},
					map[string]any{"name": "cloudinit", "cloudInitNoCloud": map[string]any{"secretRef": map[string]any{"name": cloudInitSecret}}},
				},
			},
		},
	}
	return desired
}

func vpnVirtualMachineObject(namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("kubevirt.io/v1")
	obj.SetKind("VirtualMachine")
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

func vpnVirtualMachineInstanceObject(namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("kubevirt.io/v1")
	obj.SetKind("VirtualMachineInstance")
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

func (r *VPNGatewayReconciler) ensureDeployment(ctx context.Context, gw *sdnv1alpha1.VPNGateway, backend, checksum string) error {
	desired := r.deployment(gw, backend, checksum)
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return err
	}
	existing := &appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create appliance deployment: %w", err)
		}
	case err != nil:
		return fmt.Errorf("get appliance deployment: %w", err)
	default:
		if err := requireVPNOwner(existing, gw); err != nil {
			return err
		}
		if !equality.Semantic.DeepDerivative(desired.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
			!equality.Semantic.DeepDerivative(desired.Spec.Template.Annotations, existing.Spec.Template.Annotations) ||
			!equality.Semantic.DeepEqual(desired.Spec.Replicas, existing.Spec.Replicas) ||
			!equality.Semantic.DeepEqual(desired.Spec.Template.Spec.Affinity, existing.Spec.Template.Spec.Affinity) ||
			!equality.Semantic.DeepEqual(desired.Spec.Template.Spec.NodeSelector, existing.Spec.Template.Spec.NodeSelector) {
			existing.Spec = desired.Spec
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update appliance deployment: %w", err)
			}
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) ensureHeadlessService(ctx context.Context, gw *sdnv1alpha1.VPNGateway) error {
	labels := map[string]string{"app": "cozyplane-vpn-gateway", vpnGatewayLabel: gw.Name}
	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn-headless", Namespace: gw.Namespace, Labels: labels},
		Spec: corev1.ServiceSpec{
			ClusterIP:                corev1.ClusterIPNone,
			PublishNotReadyAddresses: true,
			Selector:                 labels,
		},
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return err
	}
	existing := &corev1.Service{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create active-active headless service: %w", err)
		}
	case err != nil:
		return fmt.Errorf("get active-active headless service: %w", err)
	default:
		if err := requireVPNOwner(existing, gw); err != nil {
			return err
		}
		if !equality.Semantic.DeepEqual(existing.Spec.Selector, desired.Spec.Selector) ||
			existing.Spec.PublishNotReadyAddresses != desired.Spec.PublishNotReadyAddresses {
			existing.Spec.Selector = desired.Spec.Selector
			existing.Spec.PublishNotReadyAddresses = desired.Spec.PublishNotReadyAddresses
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update active-active headless service: %w", err)
			}
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) ensureStatefulSet(ctx context.Context, gw *sdnv1alpha1.VPNGateway, backend, checksum string) error {
	desired := r.statefulSet(gw, backend, checksum)
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return err
	}
	existing := &appsv1.StatefulSet{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create active-active appliance StatefulSet: %w", err)
		}
	case err != nil:
		return fmt.Errorf("get active-active appliance StatefulSet: %w", err)
	default:
		if err := requireVPNOwner(existing, gw); err != nil {
			return err
		}
		if !equality.Semantic.DeepEqual(existing.Spec.Replicas, desired.Spec.Replicas) ||
			!equality.Semantic.DeepEqual(existing.Spec.Template, desired.Spec.Template) ||
			existing.Spec.ServiceName != desired.Spec.ServiceName ||
			existing.Spec.PodManagementPolicy != desired.Spec.PodManagementPolicy {
			existing.Spec.Replicas = desired.Spec.Replicas
			existing.Spec.Template = desired.Spec.Template
			existing.Spec.ServiceName = desired.Spec.ServiceName
			existing.Spec.PodManagementPolicy = desired.Spec.PodManagementPolicy
			existing.Spec.UpdateStrategy = desired.Spec.UpdateStrategy
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update active-active appliance StatefulSet: %w", err)
			}
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) statefulSet(gw *sdnv1alpha1.VPNGateway, backend, checksum string) *appsv1.StatefulSet {
	deployment := r.deployment(gw, backend, checksum)
	return &appsv1.StatefulSet{
		ObjectMeta: deployment.ObjectMeta,
		Spec: appsv1.StatefulSetSpec{
			ServiceName:         gw.Name + "-vpn-headless",
			Replicas:            new(int32(2)),
			PodManagementPolicy: appsv1.ParallelPodManagement,
			Selector:            deployment.Spec.Selector,
			Template:            deployment.Spec.Template,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
		},
	}
}

func (r *VPNGatewayReconciler) deployment(gw *sdnv1alpha1.VPNGateway, backend, checksum string) *appsv1.Deployment {
	labels := map[string]string{
		"app":           "cozyplane-vpn-gateway",
		vpnGatewayLabel: gw.Name,
	}
	command := "/usr/local/bin/cozyplane-vpn-gateway"
	if backend == backendIPsec {
		command = "/usr/local/bin/cozyplane-vpn-gateway-ipsec"
	}

	// HA warm standby (increment 6, docs/vpn.md §3.5 tier 2): two same-identity
	// replicas anti-affined across nodes. The two share the config Secret (same
	// WG key / IPsec PSK), so either can serve the FloatingIP; the controller's
	// oldest-wins resolution re-targets it to the survivor on a node loss.
	// Per-connection metrics are served on :9410 for both backends: WireGuard
	// reads kernel peer state and IPsec reads live IKE/CHILD SA state over VICI.
	podAnnotations := vpnAttachmentAnnotations(gw)
	podAnnotations[vpnConfigChecksumAnnotation] = checksum
	ports := []corev1.ContainerPort{{Name: "vpn-metrics", ContainerPort: 9410, Protocol: corev1.ProtocolTCP}}
	podAnnotations["prometheus.io/scrape"] = "true"
	podAnnotations["prometheus.io/port"] = "9410"
	podAnnotations["prometheus.io/path"] = "/metrics"

	replicas := int32(1)
	var affinity *corev1.Affinity
	if mode := haMode(gw); mode == sdnv1alpha1.VPNGatewayHAModeWarmStandby || mode == sdnv1alpha1.VPNGatewayHAModeActiveActive {
		replicas = 2
		affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight: 100,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{vpnGatewayLabel: gw.Name}},
					TopologyKey:   "kubernetes.io/hostname",
				},
			}},
		}}
	}
	securityContext := &corev1.SecurityContext{Privileged: new(true)}
	var podSecurityContext *corev1.PodSecurityContext
	if r.Config.HardenedAppliance {
		securityContext = &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE"},
			},
		}
		podSecurityContext = &corev1.PodSecurityContext{Sysctls: []corev1.Sysctl{
			{Name: "net.ipv4.ip_forward", Value: "1"},
			{Name: "net.ipv6.conf.all.forwarding", Value: "1"},
		}}
		if backend == backendIPsec || isWGClientGateway(gw) {
			securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "BPF")
		}
	}
	containers := []corev1.Container{{
		Name:            "vpn-gateway",
		Image:           r.Config.Image,
		Command:         []string{command},
		SecurityContext: securityContext,
		Resources:       r.applianceResources(),
		Ports:           ports,
		Env: []corev1.EnvVar{{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
			FieldPath: "metadata.name",
		}}}},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Path: "/readyz", Port: intstr.FromString("vpn-metrics"), Scheme: corev1.URISchemeHTTP,
			}},
			InitialDelaySeconds: 1,
			PeriodSeconds:       1,
			TimeoutSeconds:      1,
			FailureThreshold:    2,
		},
		VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/etc/cozyplane-vpn", ReadOnly: true}},
	}}
	if haMode(gw) == sdnv1alpha1.VPNGatewayHAModeActiveActive {
		containers = append(containers, corev1.Container{
			Name:    "vpn-routing",
			Image:   r.Config.Image,
			Command: []string{"/usr/local/bin/cozyplane-vpn-routing"},
			Env: []corev1.EnvVar{{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "status.podIP",
			}}}},
			SecurityContext: securityContext,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler:        corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/usr/bin/test", "-S", "/run/frr/zserv.api"}}},
				InitialDelaySeconds: 2, PeriodSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 3,
			},
			VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/etc/cozyplane-vpn", ReadOnly: true}, {Name: "frr-run", MountPath: "/run/frr"}},
		})
	}
	if backend == backendIPsec || isWGClientGateway(gw) {
		containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "VPN_CONFIG_CHECKSUM", Value: checksum})
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gw.Name + "-vpn",
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(replicas),
			// RollingUpdate keeps a replica up across a config roll (each pod owns
			// a distinct VPC Port, so replacements never race on an identity).
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: ptrIntStr(0),
					MaxSurge:       ptrIntStr(1),
				},
			},
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					// AnnotationVPC attaches the appliance to the VPC as an ordinary
					// member — it gets a Port, and the route table (not the .1 door)
					// steers the remote CIDRs to it. Scrape annotations for either
					// tunnel backend sit
					// alongside.
					Annotations: podAnnotations,
				},
				Spec: corev1.PodSpec{
					SecurityContext: podSecurityContext,
					// Guardrails (increment 6): dedicated gateway node-pool placement
					// and mandatory resource bounds keep a heavy tunnel off the
					// tenant workloads' nodes and its blast radius bounded.
					NodeSelector: r.Config.NodeSelector,
					Tolerations:  r.Config.Tolerations,
					Affinity:     affinity,
					Containers:   containers,
					Volumes: []corev1.Volume{{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: gw.Name + "-wg-config", DefaultMode: ptr.To[int32](0o600)},
						},
					}, {Name: "frr-run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
				},
			},
		},
	}
}

// ptrIntStr returns a pointer to an IntOrString wrapping an int — for the
// rolling-update surge/unavailable knobs.
func ptrIntStr(i int32) *intstr.IntOrString {
	v := intstr.FromInt32(i)
	return &v
}

// resolveAppliancePort finds the appliance's Port in the VPC (oldest-wins, name
// breaking the tie — the same total order the appliance door uses). Returns the
// Port name, its tenant IP, and the selected pod's management PodIP. Values are
// empty until the CNI has minted the Port.
func (r *VPNGatewayReconciler) resolveAppliancePort(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	vpc *sdnv1alpha1.VPC) (portName, ip, statusIP string) {
	choices := r.resolveAppliancePorts(ctx, gw, vpc, 1)
	if len(choices) == 0 {
		return "", "", ""
	}
	return choices[0].Port, choices[0].IP, choices[0].StatusIP
}

// Follow the expected workload chain to the current gateway; matching labels
// alone must not let another pod become a tunnel endpoint.
func (r *VPNGatewayReconciler) appliancePodOwned(ctx context.Context, gw *sdnv1alpha1.VPNGateway, pod *corev1.Pod) bool {
	ref := metav1.GetControllerOf(pod)
	if ref == nil || ref.UID == "" {
		return false
	}
	var workload client.Object
	switch haMode(gw) {
	case sdnv1alpha1.VPNGatewayHAModeActiveActive:
		if ref.Kind != "StatefulSet" || ref.APIVersion != "apps/v1" {
			return false
		}
		workload = &appsv1.StatefulSet{}
	case sdnv1alpha1.VPNGatewayHAModeLiveMigration:
		if ref.Kind != "VirtualMachineInstance" || ref.APIVersion != "kubevirt.io/v1" {
			return false
		}
		vmi := vpnVirtualMachineInstanceObject(gw.Namespace, ref.Name)
		if err := r.Get(ctx, client.ObjectKeyFromObject(vmi), vmi); err != nil || vmi.GetUID() != ref.UID || vmi.GetDeletionTimestamp() != nil {
			return false
		}
		ref = metav1.GetControllerOf(vmi)
		if ref == nil || ref.Kind != "VirtualMachine" || ref.APIVersion != "kubevirt.io/v1" {
			return false
		}
		workload = vpnVirtualMachineObject(gw.Namespace, ref.Name)
	default:
		if ref.Kind != "ReplicaSet" || ref.APIVersion != "apps/v1" {
			return false
		}
		rs := &appsv1.ReplicaSet{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: ref.Name}, rs); err != nil || rs.UID != ref.UID || rs.DeletionTimestamp != nil {
			return false
		}
		ref = metav1.GetControllerOf(rs)
		if ref == nil || ref.Kind != "Deployment" || ref.APIVersion != "apps/v1" {
			return false
		}
		workload = &appsv1.Deployment{}
	}
	if ref.UID == "" || ref.Name != gw.Name+"-vpn" {
		return false
	}
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: ref.Name}, workload); err != nil {
		return false
	}
	return workload.GetUID() == ref.UID && workload.GetDeletionTimestamp() == nil && requireVPNOwner(workload, gw) == nil
}

type applianceResolution struct {
	Port      string
	IP        string
	StatusIP  string
	PodName   string
	PodUID    types.UID
	CreatedAt metav1.Time
}

func (r *VPNGatewayReconciler) resolveAppliancePorts(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	vpc *sdnv1alpha1.VPC, limit int) []applianceResolution {
	if limit <= 0 || ctx.Err() != nil {
		return nil
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace),
		client.MatchingLabels{vpnGatewayLabel: gw.Name}); err != nil {
		return nil
	}
	live := map[string]*corev1.Pod{}
	for i := range pods.Items {
		if pods.Items[i].DeletionTimestamp == nil && podReady(&pods.Items[i]) && r.appliancePodOwned(ctx, gw, &pods.Items[i]) {
			live[pods.Items[i].Namespace+"/"+pods.Items[i].Name] = &pods.Items[i]
		}
	}
	var out []applianceResolution
	sandboxes := podSandboxSnapshot{}
	for key, pod := range live {
		if ctx.Err() != nil {
			return nil
		}
		sandbox, err := sandboxes.forPod(ctx, r.Client, pod)
		if err != nil {
			return nil
		}
		var ports sdnv1alpha1.PortList
		if err := r.List(ctx, &ports, client.MatchingFields{vpnAppliancePodIndex: key}, client.MatchingLabels{
			sdnv1alpha1.LabelVPCNamespace: gw.Namespace,
			sdnv1alpha1.LabelVPC:          vpc.Name,
		}); err != nil {
			return nil
		}
		for i := range ports.Items {
			port := &ports.Items[i]
			if port.Spec.PodNamespace != pod.Namespace || port.Spec.PodName != pod.Name ||
				!currentNextHopClaim(port, vpc, pod) || !nextHopSandboxMatches(port, sandbox) || pod.Status.PodIP == "" {
				continue
			}
			out = append(out, applianceResolution{
				Port: port.Name, IP: port.Spec.IP, StatusIP: pod.Status.PodIP,
				PodName: port.Spec.PodName, PodUID: pod.UID, CreatedAt: port.CreationTimestamp,
			})
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	sortApplianceResolutions(out, haMode(gw) == sdnv1alpha1.VPNGatewayHAModeActiveActive)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortApplianceResolutions(out []applianceResolution, stableOrdinal bool) {
	sort.Slice(out, func(i, j int) bool {
		if stableOrdinal && out[i].PodName != out[j].PodName {
			return out[i].PodName < out[j].PodName
		}
		if !out[i].CreatedAt.Equal(&out[j].CreatedAt) {
			return out[i].CreatedAt.Before(&out[j].CreatedAt)
		}
		return out[i].Port < out[j].Port
	})
}

// resolveVPCLegPorts returns, for one additional served VPC, the leg Ports of
// exactly the appliances selected in the primary VPC, in the same order (so an
// active-active ordinal keeps its slot). A leg not yet minted leaves a gap, and
// the caller treats a short result as "not ready" (docs/vpn.md §3.3).
func (r *VPNGatewayReconciler) resolveVPCLegPorts(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	vpc *sdnv1alpha1.VPC, appliances []applianceResolution) []string {
	var out []string
	sandboxes := podSandboxSnapshot{}
	for _, a := range appliances {
		pod := &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: a.PodName}, pod); err != nil ||
			pod.UID != a.PodUID || !pod.DeletionTimestamp.IsZero() || !podReady(pod) || !r.appliancePodOwned(ctx, gw, pod) {
			return nil
		}
		sandbox, err := sandboxes.forPod(ctx, r.Client, pod)
		if err != nil {
			return nil
		}
		var ports sdnv1alpha1.PortList
		if err := r.List(ctx, &ports, client.MatchingFields{vpnAppliancePodIndex: gw.Namespace + "/" + pod.Name},
			client.MatchingLabels{sdnv1alpha1.LabelVPCNamespace: gw.Namespace, sdnv1alpha1.LabelVPC: vpc.Name}); err != nil {
			return nil
		}
		var candidates []applianceResolution
		for i := range ports.Items {
			port := &ports.Items[i]
			if port.Spec.PodNamespace == pod.Namespace && port.Spec.PodName == pod.Name &&
				currentNextHopClaim(port, vpc, pod) && nextHopSandboxMatches(port, sandbox) {
				candidates = append(candidates, applianceResolution{Port: port.Name, CreatedAt: port.CreationTimestamp})
			}
		}
		if len(candidates) == 0 {
			return nil
		}
		sortApplianceResolutions(candidates, false)
		out = append(out, candidates[0].Port)
	}
	return out
}

// All running members must acknowledge the same configuration before granting
// remote sources or publishing usable return routes. Keep endpoint selection
// independent, so a pending rollout does not recreate its FloatingIP.
func (r *VPNGatewayReconciler) ipsecConfigApplied(ctx context.Context, gw *sdnv1alpha1.VPNGateway, checksum string) (bool, error) {
	const podScanBudget = 4096
	var pods corev1.PodList
	if err := r.quotaReader().List(ctx, &pods, client.InNamespace(gw.Namespace), client.Limit(podScanBudget+1)); err != nil {
		return false, err
	}
	if pods.Continue != "" || len(pods.Items) > podScanBudget {
		return false, fmt.Errorf("IPsec ownership scan exceeds budget")
	}
	count := 0
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		owned := r.appliancePodOwned(ctx, gw, p)
		if !owned && p.Labels[vpnGatewayLabel] != gw.Name {
			continue
		}
		if !owned || !p.DeletionTimestamp.IsZero() || !podReady(p) || p.Annotations[vpnConfigChecksumAnnotation] != checksum {
			return false, nil
		}
		count++
		snapshot, err := r.readApplianceStatus(ctx, p.Status.PodIP, backendIPsec)
		if err != nil {
			return false, err
		}
		if snapshot.ConfigChecksum != checksum {
			return false, nil
		}
	}
	expected := 1
	if mode := haMode(gw); mode == sdnv1alpha1.VPNGatewayHAModeWarmStandby || mode == sdnv1alpha1.VPNGatewayHAModeActiveActive {
		expected = 2
	}
	return count == expected, nil
}

// readApplianceStatus reads a small, secret-free JSON snapshot directly from
// the selected pod. It deliberately does not route through the tenant network.
func (r *VPNGatewayReconciler) readApplianceStatus(ctx context.Context, podIP, backend string) (*vpnstatus.Snapshot, error) {
	if net.ParseIP(podIP) == nil {
		return nil, fmt.Errorf("selected appliance pod has no valid PodIP")
	}
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	// A compromised appliance must not redirect the privileged controller to
	// unrelated cluster services or external URLs.
	boundedClient := *client
	boundedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if boundedClient.Timeout <= 0 || boundedClient.Timeout > 2*time.Second {
		boundedClient.Timeout = 2 * time.Second
	}
	url := "http://" + net.JoinHostPort(podIP, "9410") + "/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build appliance status request: %w", err)
	}
	resp, err := boundedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read appliance status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read appliance status: HTTP %d", resp.StatusCode)
	}
	var snapshot vpnstatus.Snapshot
	decoder := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode appliance status: %w", err)
	}
	if snapshot.Backend != backend {
		return nil, fmt.Errorf("appliance status backend %q, expected %q", snapshot.Backend, backend)
	}
	if snapshot.ObservedAt.IsZero() {
		return nil, fmt.Errorf("appliance status has no observation timestamp")
	}
	return &snapshot, nil
}

func mergeVPNSnapshots(backend string, snapshots []*vpnstatus.Snapshot) *vpnstatus.Snapshot {
	if len(snapshots) == 0 {
		return nil
	}
	merged := &vpnstatus.Snapshot{Backend: backend, Connections: map[string]vpnstatus.Connection{}}
	for _, snapshot := range snapshots {
		if snapshot == nil {
			continue
		}
		if snapshot.ObservedAt.After(merged.ObservedAt) {
			merged.ObservedAt = snapshot.ObservedAt
		}
		for name, connection := range snapshot.Connections {
			current := merged.Connections[name]
			current.Up = current.Up || connection.Up
			if connection.LastHandshakeUnix > current.LastHandshakeUnix {
				current.LastHandshakeUnix = connection.LastHandshakeUnix
			}
			current.RXBytes += connection.RXBytes
			current.TXBytes += connection.TXBytes
			current.RXPackets += connection.RXPackets
			current.TXPackets += connection.TXPackets
			current.AssignedAddresses = appendUnique(current.AssignedAddresses, connection.AssignedAddresses...)
			merged.Connections[name] = current
		}
	}
	return merged
}

func appendUnique(values []string, more ...string) []string {
	for _, value := range more {
		if value != "" && !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

// ensureFloatingIP reconciles the tunnel endpoint — a FloatingIP bound 1:1 to
// the appliance's tenant IP, whose external address the remote peer dials.
// Returns the assigned address once the LB implementation fills it.
func (r *VPNGatewayReconciler) ensureFloatingIP(ctx context.Context, gw *sdnv1alpha1.VPNGateway, applianceIP string) (string, error) {
	return r.ensureFloatingIPNamed(ctx, gw, gw.Name+"-vpn", applianceIP, gw.Spec.ExternalAddress.AddressClaimName)
}

func (r *VPNGatewayReconciler) ensureFloatingIPNamed(ctx context.Context, gw *sdnv1alpha1.VPNGateway, name, applianceIP, claimName string) (string, error) {
	desired := &sdnv1alpha1.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Spec: sdnv1alpha1.FloatingIPSpec{
			VPCRef:            sdnv1alpha1.LocalVPCRef{Name: gw.Spec.VPCRef.Name},
			Target:            applianceIP,
			LoadBalancerClass: gw.Spec.ExternalAddress.LoadBalancerClass,
			AddressClaimName:  claimName,
		},
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return "", err
	}
	existing := &sdnv1alpha1.FloatingIP{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return "", fmt.Errorf("create FloatingIP: %w", err)
		}
		return "", nil // address fills on a later pass
	case err != nil:
		return "", fmt.Errorf("get FloatingIP: %w", err)
	}
	if err := requireVPNOwner(existing, gw); err != nil {
		return "", err
	}
	if !equality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return "", fmt.Errorf("update FloatingIP: %w", err)
		}
	}
	return existing.Status.Address, nil
}

func (r *VPNGatewayReconciler) pruneFloatingIPs(ctx context.Context, gw *sdnv1alpha1.VPNGateway, keep map[string]bool) error {
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace), client.MatchingLabels{vpnGatewayLabel: gw.Name}); err != nil {
		return fmt.Errorf("list VPN endpoint FloatingIPs: %w", err)
	}
	for i := range list.Items {
		if keep[list.Items[i].Name] {
			continue
		}
		if err := r.deleteVPNOwned(ctx, gw, &list.Items[i]); err != nil {
			return fmt.Errorf("delete stale VPN endpoint FloatingIP %q: %w", list.Items[i].Name, err)
		}
	}
	return nil
}

// reflectConnectionStatus combines route readiness with the appliance's live
// kernel/IKE state. Routes alone never imply an established tunnel.
func (r *VPNGatewayReconciler) reflectConnectionStatus(ctx context.Context, conns []sdnv1alpha1.VPNConnection,
	routesReady bool, snapshot *vpnstatus.Snapshot, snapshotErr error) error {
	for i := range conns {
		c := &conns[i]
		want := sdnv1alpha1.VPNConnectionStatus{
			Phase:             sdnv1alpha1.VPNConnectionPhasePending,
			LastHandshake:     c.Status.LastHandshake,
			ObservedAt:        c.Status.ObservedAt,
			AssignedAddresses: append([]string(nil), c.Status.AssignedAddresses...),
		}
		connection, reported := vpnstatus.Connection{}, false
		if snapshot != nil {
			connection, reported = snapshot.Connections[c.Name]
			observedAt := metav1.NewTime(snapshot.ObservedAt)
			want.ObservedAt = &observedAt
			// A successful observation supersedes the previous value, including
			// an explicit zero for a connection that has never handshaked.
			want.LastHandshake = nil
			if c.Spec.WireGuard == nil || c.Spec.WireGuard.Client == nil {
				want.AssignedAddresses = append([]string(nil), connection.AssignedAddresses...)
			}
		}
		if connection.LastHandshakeUnix > 0 {
			lastHandshake := metav1.NewTime(time.Unix(connection.LastHandshakeUnix, 0).UTC())
			want.LastHandshake = &lastHandshake
		}
		established := routesReady && reported && connection.Up
		if established {
			want.Phase = sdnv1alpha1.VPNConnectionPhaseEstablished
		} else if routesReady {
			want.Phase = sdnv1alpha1.VPNConnectionPhaseDown
		}
		want.Conditions = slices.Clone(c.Status.Conditions)
		want.ClientConfig = c.Status.ClientConfig
		if c.Spec.WireGuard != nil && c.Spec.WireGuard.Client != nil && !routesReady {
			want.ClientConfig = nil
			setConnCondition(&want, sdnv1alpha1.VPNConnectionConditionClientConfigured, false,
				"ConfigurationPending", "waiting for the WireGuard client configuration to be applied")
		}
		setConnCondition(&want, sdnv1alpha1.VPNConnectionConditionRoutesProgrammed, routesReady,
			"RoutesProgrammed", routesMessage(routesReady, len(c.Spec.RemoteCIDRs)))
		reason, message := connectionStatusReason(routesReady, reported, connection.Up, snapshotErr)
		setConnCondition(&want, sdnv1alpha1.VPNConnectionConditionEstablished, established, reason, message)
		for j := range want.Conditions {
			want.Conditions[j].ObservedGeneration = c.Generation
		}
		if connStatusEqual(c.Status, want) {
			continue
		}
		c.Status = want
		if err := r.Status().Update(ctx, c); err != nil && !apierrors.IsConflict(err) {
			return fmt.Errorf("update VPNConnection status: %w", err)
		}
	}
	return nil
}

func connectionStatusReason(routesReady, reported, up bool, statusErr error) (string, string) {
	if !routesReady {
		return "RoutesPending", "waiting for remote-CIDR routes to the appliance"
	}
	if statusErr != nil {
		return "StatusUnavailable", "the appliance's live tunnel status is unavailable"
	}
	if !reported {
		return "ConnectionNotReported", "the appliance did not report this connection"
	}
	if !up {
		return "TunnelDown", "the appliance reports no established tunnel"
	}
	return "TunnelEstablished", "the appliance reports an established tunnel"
}

func (r *VPNGatewayReconciler) writeStatus(ctx context.Context, gw *sdnv1alpha1.VPNGateway, status sdnv1alpha1.VPNGatewayStatus) error {
	status.Conditions = slices.Clone(status.Conditions)
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = gw.Generation
	}
	if vpnGWStatusEqual(gw.Status, status) {
		return nil
	}
	gw.Status = status
	if err := r.Status().Update(ctx, gw); err != nil {
		if apierrors.IsConflict(err) {
			return nil
		}
		return fmt.Errorf("update VPNGateway status: %w", err)
	}
	return nil
}

func applianceReadyMessage(port string) string {
	if port != "" {
		return "the tunnel appliance holds Port " + port + " in the VPC"
	}
	return "waiting for the tunnel appliance's Port to appear"
}

func addressMessage(addr string) string {
	if addr != "" {
		return "the endpoint address is " + addr
	}
	return "waiting for the endpoint FloatingIP address"
}

func routesMessage(ready bool, n int) string {
	if ready {
		return fmt.Sprintf("%d remote-CIDR route(s) programmed toward the appliance", n)
	}
	return "remote CIDRs not yet routed toward the appliance"
}

func remoteCIDRsReason(rejected []string) string {
	if len(rejected) == 0 {
		return "RemoteCIDRsAccepted"
	}
	return "ForbiddenRemoteCIDR"
}

func remoteCIDRsMessage(rejected []string) string {
	if len(rejected) == 0 {
		return "every remote CIDR is outside cluster-internal space"
	}
	return "refused remote CIDR(s) overlapping cluster-internal space: " + strings.Join(rejected, ", ")
}

// setVPNGWCondition sets a condition through meta.SetStatusCondition (which fills
// LastTransitionTime and de-duplicates by type).
func setVPNGWCondition(status *sdnv1alpha1.VPNGatewayStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: condType, Status: st, Reason: reason, Message: msg})
}

func setConnCondition(status *sdnv1alpha1.VPNConnectionStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: condType, Status: st, Reason: reason, Message: msg})
}

func vpnGWStatusEqual(a, b sdnv1alpha1.VPNGatewayStatus) bool {
	if a.Phase != b.Phase || a.Address != b.Address || a.PublicKey != b.PublicKey ||
		a.AppliancePort != b.AppliancePort || !slices.Equal(a.Addresses, b.Addresses) ||
		!slices.Equal(a.PublicKeys, b.PublicKeys) || !slices.Equal(a.AppliancePorts, b.AppliancePorts) ||
		len(a.Conditions) != len(b.Conditions) ||
		!routeStatusEqual(a.Routes, b.Routes) {
		return false
	}
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message || cb.ObservedGeneration != ca.ObservedGeneration {
			return false
		}
	}
	return true
}

func connStatusEqual(a, b sdnv1alpha1.VPNConnectionStatus) bool {
	if a.Phase != b.Phase || !timePtrEqual(a.LastHandshake, b.LastHandshake) ||
		!timePtrEqual(a.ObservedAt, b.ObservedAt) || !slices.Equal(a.AssignedAddresses, b.AssignedAddresses) ||
		len(a.Conditions) != len(b.Conditions) || !equality.Semantic.DeepEqual(a.ClientConfig, b.ClientConfig) {
		return false
	}
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message || cb.ObservedGeneration != ca.ObservedGeneration {
			return false
		}
	}
	return true
}

func timePtrEqual(a, b *metav1.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

// SetupWithManager wires the controller: VPNGateway drives it; VPNConnections,
// the appliance's Port and Pod, and owned objects re-enqueue their gateway.
func (r *VPNGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// VPCGateway setup registers the shared Port pod index first in main.
	for _, obj := range []client.Object{&sdnv1alpha1.VPNGateway{}, &sdnv1alpha1.VPNConnection{}} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), obj, vpnCredentialIndex, vpnCredentialKeys); err != nil {
			return err
		}
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &sdnv1alpha1.VPNGateway{}, gatewayVPCIndex, gatewayVPCKeys); err != nil {
		return err
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &sdnv1alpha1.VPNConnection{}, vpnConnectionGatewayIndex, vpnConnectionGatewayKeys); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPNGateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Secret{}).
		Owns(&sdnv1alpha1.VPCBinding{}).
		Owns(&sdnv1alpha1.FloatingIP{}).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapVPCToVPNGateways)).
		Watches(&sdnv1alpha1.VPNConnection{}, handler.EnqueueRequestsFromMapFunc(r.mapConnectionToGateway), builder.WithPredicates(vpnConnectionEvents())).
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(r.mapPortToVPNGateways)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToVPNGateways)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.mapCredentialToVPNGateways)).
		Named("vpngateway").
		Complete(r)
}

// Credentials may be tenant-owned, so Owns(Secret) alone cannot observe their
// deletion or rotation. Reconcile every gateway consuming the changed Secret.
func (r *VPNGatewayReconciler) mapCredentialToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	var gateways sdnv1alpha1.VPNGatewayList
	var connections sdnv1alpha1.VPNConnectionList
	if err := r.List(ctx, &gateways, client.InNamespace(obj.GetNamespace()), client.MatchingFields{vpnCredentialIndex: obj.GetName()}); err != nil {
		return nil
	}
	if err := r.List(ctx, &connections, client.InNamespace(obj.GetNamespace()), client.MatchingFields{vpnCredentialIndex: obj.GetName()}); err != nil {
		return nil
	}
	consumers := map[string]*sdnv1alpha1.VPNGateway{}
	lookedUp := map[string]bool{}
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		consumers[gw.Name] = gw
		lookedUp[gw.Name] = true
	}
	for i := range connections.Items {
		conn := &connections.Items[i]
		name := conn.Spec.GatewayRef.Name
		if !vpnlimits.ObjectName(name) || lookedUp[name] {
			continue
		}
		lookedUp[name] = true
		gw := &sdnv1alpha1.VPNGateway{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: conn.Namespace, Name: name}, gw); err == nil {
			consumers[name] = gw
		}
	}
	var requests []ctrl.Request
	for _, gw := range consumers {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	}
	return requests
}

func (r *VPNGatewayReconciler) mapConnectionToGateway(ctx context.Context, obj client.Object) []ctrl.Request {
	conn, ok := obj.(*sdnv1alpha1.VPNConnection)
	if !ok || !vpnlimits.ObjectName(conn.Spec.GatewayRef.Name) {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: conn.Namespace, Name: conn.Spec.GatewayRef.Name}}}
}

// mapPortToVPNGateways re-enqueues the gateways of the Port's VPC when
// an appliance Port appears or moves.
func (r *VPNGatewayReconciler) mapPortToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	ns := obj.GetLabels()[sdnv1alpha1.LabelVPCNamespace]
	name := obj.GetLabels()[sdnv1alpha1.LabelVPC]
	if ns == "" || name == "" {
		return nil
	}
	return r.vpnGatewaysIn(ctx, ns, name)
}

// mapPodToVPNGateways re-enqueues the gateway that owns an appliance pod.
func (r *VPNGatewayReconciler) mapPodToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	name := obj.GetLabels()[vpnGatewayLabel]
	if name == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: name}}}
}

func (r *VPNGatewayReconciler) vpnGatewaysIn(ctx context.Context, namespace, vpcName string) []ctrl.Request {
	var list sdnv1alpha1.VPNGatewayList
	if err := r.List(ctx, &list, client.InNamespace(namespace), client.MatchingFields{gatewayVPCIndex: vpcName}); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}

func (r *VPNGatewayReconciler) mapVPCToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.vpnGatewaysIn(ctx, obj.GetNamespace(), obj.GetName())
}
