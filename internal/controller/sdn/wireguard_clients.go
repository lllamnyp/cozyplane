package sdn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	wgClientStateName     = "cozyplane-wireguard-client-allocations"
	wgClientStateLabel    = "sdn.cozystack.io/wireguard-client-state"
	wgClientFinalizer     = "sdn.cozystack.io/wireguard-client-cleanup"
	wgClientStateBytes    = 512 << 10
	wgClientStateRecords  = 4096
	wgClientRetainedPools = 2 * vpnlimits.AddressPools
)

type wgClientReservation struct {
	Name      string   `json:"name"`
	Pools     []string `json:"pools"`
	Addresses []string `json:"addresses"`
}

type wgClientGatewayReservation struct {
	Name     string                         `json:"name"`
	VPCs     []string                       `json:"vpcs"`
	Pools    map[string]string              `json:"pools"`
	Clients  map[string]wgClientReservation `json:"clients"`
	PodUIDs  []string                       `json:"podUIDs,omitempty"`
	PortUIDs map[string]string              `json:"portUIDs,omitempty"`
}

type wgClientState struct {
	Gateways map[string]wgClientGatewayReservation `json:"gateways"`
}

func isWGClientGateway(gw *sdn.VPNGateway) bool {
	return gw.Spec.WireGuard != nil && len(gw.Spec.WireGuard.AddressPools) != 0
}

func clientAllowsVPC(c *sdn.VPNConnection, name string) bool {
	if c.Spec.WireGuard == nil || c.Spec.WireGuard.Client == nil {
		return true
	}
	for _, ref := range c.Spec.WireGuard.Client.VPCRefs {
		if ref.Name == name {
			return true
		}
	}
	return false
}

func connectionsForVPC(conns []sdn.VPNConnection, name string) []sdn.VPNConnection {
	var out []sdn.VPNConnection
	for i := range conns {
		if clientAllowsVPC(&conns[i], name) {
			out = append(out, conns[i])
		}
	}
	return out
}

func clientDestinationCIDRs(c *sdn.VPNConnection, vpcs []*sdn.VPC) []string {
	var out []string
	for _, vpc := range vpcs {
		if clientAllowsVPC(c, vpc.Name) {
			out = append(out, vpc.Spec.CIDRs...)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func (r *VPNGatewayReconciler) loadWGClientState(ctx context.Context, namespace string) (*corev1.Secret, *wgClientState, error) {
	secret := &corev1.Secret{}
	err := r.quotaReader().Get(ctx, client.ObjectKey{Namespace: namespace, Name: wgClientStateName}, secret)
	if apierrors.IsNotFound(err) {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: wgClientStateName, Namespace: namespace, Labels: map[string]string{wgClientStateLabel: "true"}}, Type: corev1.SecretTypeOpaque}, &wgClientState{Gateways: map[string]wgClientGatewayReservation{}}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if secret.Labels[wgClientStateLabel] != "true" || len(secret.OwnerReferences) != 0 || !secret.DeletionTimestamp.IsZero() {
		return nil, nil, fmt.Errorf("WireGuard allocation state is not controller-managed")
	}
	raw := secret.Data["allocations.json"]
	if len(raw) == 0 || len(raw) > wgClientStateBytes {
		return nil, nil, fmt.Errorf("WireGuard allocation state exceeds its byte budget or is missing")
	}
	state := &wgClientState{}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(state); err != nil {
		return nil, nil, fmt.Errorf("invalid WireGuard allocation state")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, nil, fmt.Errorf("invalid trailing WireGuard allocation state")
	}
	if state.Gateways == nil || len(state.Gateways) > wgClientStateRecords {
		return nil, nil, fmt.Errorf("invalid WireGuard allocation gateway count")
	}
	count := 0
	for uid, gw := range state.Gateways {
		if uid == "" || len(uid) > 253 || !vpnlimits.ObjectName(gw.Name) || len(gw.VPCs) > 20 || len(gw.PodUIDs) > 64 || len(gw.PortUIDs) > wgClientPortWitnesses || len(gw.Pools) > wgClientRetainedPools || gw.Pools == nil || gw.Clients == nil {
			return nil, nil, fmt.Errorf("invalid WireGuard allocation gateway")
		}
		for _, vpc := range gw.VPCs {
			if vpc == "" || len(vpc) > 253 {
				return nil, nil, fmt.Errorf("invalid WireGuard allocation VPC identity")
			}
		}
		for _, uid := range gw.PodUIDs {
			if uid == "" || len(uid) > 253 {
				return nil, nil, fmt.Errorf("invalid WireGuard allocation pod identity")
			}
		}
		for name, uid := range gw.PortUIDs {
			if !vpnlimits.ObjectName(name) || uid == "" || len(uid) > 253 {
				return nil, nil, fmt.Errorf("invalid WireGuard allocation Port identity")
			}
		}
		for name, cidr := range gw.Pools {
			if !vpnlimits.ObjectName(name) || len(cidr) > vpnlimits.RoutePrefixBytes {
				return nil, nil, fmt.Errorf("invalid WireGuard allocation pool")
			}
			if p, err := netip.ParsePrefix(cidr); err != nil || p.Addr().Is4In6() || p != p.Masked() {
				return nil, nil, fmt.Errorf("invalid WireGuard allocation pool prefix")
			}
		}
		count += len(gw.Clients)
		if count > wgClientStateRecords {
			return nil, nil, fmt.Errorf("WireGuard allocation clients exceed budget")
		}
		used := map[string]bool{}
		for uid, c := range gw.Clients {
			if uid == "" || len(uid) > 253 || !vpnlimits.ObjectName(c.Name) || len(c.Addresses) < 1 || len(c.Addresses) > 2 || len(c.Pools) != len(c.Addresses) {
				return nil, nil, fmt.Errorf("invalid WireGuard client allocation")
			}
			for i, a := range c.Addresses {
				if len(a) > 64 {
					return nil, nil, fmt.Errorf("invalid WireGuard client allocation address")
				}
				ip, err := netip.ParseAddr(a)
				if err != nil || ip.Is4In6() || a != ip.String() || used[a] {
					return nil, nil, fmt.Errorf("invalid or duplicate WireGuard client allocation address")
				}
				p, err := netip.ParsePrefix(gw.Pools[c.Pools[i]])
				if err != nil || !p.Contains(ip) {
					return nil, nil, fmt.Errorf("WireGuard allocation is outside its pool")
				}
				used[a] = true
			}
		}
	}
	return secret, state, nil
}

func (r *VPNGatewayReconciler) saveWGClientState(ctx context.Context, secret *corev1.Secret, state *wgClientState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(raw) > wgClientStateBytes {
		return fmt.Errorf("WireGuard allocation state exceeds byte budget")
	}
	if bytes.Equal(secret.Data["allocations.json"], raw) {
		return nil
	}
	secret.Data = map[string][]byte{"allocations.json": raw}
	if secret.ResourceVersion == "" {
		return r.Create(ctx, secret)
	}
	return r.Update(ctx, secret) // Conflict aborts realization; next reconcile rereads the complete state.
}

func vpcReservationIdentity(vpc *sdn.VPC) string { return string(vpc.UID) }

func (r *VPNGatewayReconciler) validateWGClientPools(ctx context.Context, gw *sdn.VPNGateway, vpcs []*sdn.VPC, servedCIDRs []*net.IPNet) error {
	for _, pool := range gw.Spec.WireGuard.AddressPools {
		if reason := r.forbiddenRemoteCIDR(pool.CIDR, servedCIDRs); reason != "" {
			return fmt.Errorf("WireGuard client pool overlaps forbidden address space")
		}
	}
	// Include retained status intent and site peer specs, not just healthy routes.
	var gateways sdn.VPNGatewayList
	if err := r.quotaReader().List(ctx, &gateways, client.InNamespace(gw.Namespace), client.Limit(wgClientStateRecords+1)); err != nil {
		return err
	}
	if gateways.Continue != "" || len(gateways.Items) > wgClientStateRecords {
		return fmt.Errorf("WireGuard pool conflict scan exceeds budget")
	}
	var peers sdn.VPNConnectionList
	if err := r.quotaReader().List(ctx, &peers, client.InNamespace(gw.Namespace), client.Limit(wgClientStateRecords+1)); err != nil {
		return err
	}
	if peers.Continue != "" || len(peers.Items) > wgClientStateRecords {
		return fmt.Errorf("WireGuard peer conflict scan exceeds budget")
	}
	served := map[string]bool{}
	for _, v := range vpcs {
		served[v.Name] = true
	}
	relevant := map[string]bool{}
	budget := 0
	check := func(cidrs []string) error {
		for _, cidr := range cidrs {
			budget++
			if budget > vpnlimits.RoutePrefixes {
				return fmt.Errorf("WireGuard conflict prefix scan exceeds budget")
			}
			if len(cidr) > 64 {
				return fmt.Errorf("invalid VPN prefix in pool conflict scan")
			}
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("invalid VPN prefix in pool conflict scan")
			}
			for _, pool := range gw.Spec.WireGuard.AddressPools {
				q, _ := netip.ParsePrefix(pool.CIDR)
				if p.Overlaps(q) {
					return fmt.Errorf("WireGuard client pool overlaps another VPN route")
				}
			}
		}
		return nil
	}
	for _, other := range gateways.Items {
		if other.UID == gw.UID {
			continue
		}
		if len(other.Spec.AdditionalVPCRefs) > 9 || len(other.Status.Routes) > vpnlimits.RoutePrefixes {
			return fmt.Errorf("WireGuard gateway conflict input exceeds budget")
		}
		refs := append([]sdn.LocalVPCRef{other.Spec.VPCRef}, other.Spec.AdditionalVPCRefs...)
		for _, ref := range refs {
			if served[ref.Name] {
				relevant[other.Name] = true
			}
		}
		if relevant[other.Name] {
			if other.Spec.IPsec != nil {
				if len(other.Spec.IPsec.AddressPools) > vpnlimits.AddressPools {
					return fmt.Errorf("IPsec pool conflict scan exceeds budget")
				}
				for _, pool := range other.Spec.IPsec.AddressPools {
					if err := check([]string{pool.CIDR}); err != nil {
						return err
					}
				}
			}
			if other.Spec.WireGuard != nil {
				if len(other.Spec.WireGuard.AddressPools) > vpnlimits.AddressPools {
					return fmt.Errorf("WireGuard pool conflict scan exceeds budget")
				}
				for _, pool := range other.Spec.WireGuard.AddressPools {
					if err := check([]string{pool.CIDR}); err != nil {
						return err
					}
				}
			}
		}
		for _, route := range other.Status.Routes {
			budget++
			if budget > vpnlimits.RoutePrefixes {
				return fmt.Errorf("WireGuard route conflict scan exceeds budget")
			}
			ref := route.VPCRef.Name
			if ref == "" {
				ref = other.Spec.VPCRef.Name
			}
			if served[ref] {
				if err := check(route.CIDRs); err != nil {
					return err
				}
			}
		}
	}
	for _, peer := range peers.Items {
		if relevant[peer.Spec.GatewayRef.Name] {
			if err := check(peer.Spec.RemoteCIDRs); err != nil {
				return err
			}
		}
	}
	return nil
}

func nextWGClientAddress(prefix netip.Prefix, used map[string]bool) (string, error) {
	// IPv4 network and broadcast addresses are not leased. IPv6 subnet-router
	// anycast (offset zero) is not leased. Work is bounded by live reservations.
	addr := prefix.Masked().Addr().Next()
	for attempts := 0; attempts <= len(used)+1; attempts++ {
		if !addr.IsValid() || !prefix.Contains(addr) {
			break
		}
		if addr.Is4() && !prefix.Contains(addr.Next()) {
			break
		}
		if !used[addr.String()] {
			return addr.String(), nil
		}
		addr = addr.Next()
	}
	return "", fmt.Errorf("WireGuard client address pool exhausted")
}

func (r *VPNGatewayReconciler) allocateWGClients(ctx context.Context, gw *sdn.VPNGateway, vpcs []*sdn.VPC, conns []sdn.VPNConnection) error {
	if gw.UID == "" {
		return fmt.Errorf("WireGuard client gateway has no UID")
	}
	secret, state, err := r.loadWGClientState(ctx, gw.Namespace)
	if err != nil {
		return err
	}
	id := string(gw.UID)
	record, exists := state.Gateways[id]
	if !exists {
		record = wgClientGatewayReservation{Name: gw.Name, Pools: map[string]string{}, Clients: map[string]wgClientReservation{}}
	}
	if record.Name != gw.Name {
		return fmt.Errorf("WireGuard allocation gateway identity mismatch")
	}
	var scopes []string
	for _, vpc := range vpcs {
		if vpc.UID == "" {
			return fmt.Errorf("WireGuard served VPC has no UID")
		}
		scopes = append(scopes, vpcReservationIdentity(vpc))
	}
	// Retain predecessor VPC scopes until the new config is confirmed, so a
	// concurrent gateway cannot reuse a pool while the old appliance still runs.
	for _, scope := range scopes {
		if !slices.Contains(record.VPCs, scope) {
			record.VPCs = append(record.VPCs, scope)
		}
	}
	if len(record.VPCs) > 20 {
		clear, err := r.wgClientConfigApplied(ctx, gw, "", false)
		if err != nil || !clear {
			return fmt.Errorf("WireGuard VPC scope changes await prior configuration cleanup")
		}
		record.VPCs = slices.Clone(scopes)
	}
	if err := r.rememberWGClientAppliances(ctx, gw, &record); err != nil {
		return err
	}
	for name := range record.Pools {
		keep := false
		for _, pool := range gw.Spec.WireGuard.AddressPools {
			keep = keep || pool.Name == name
		}
		for _, allocation := range record.Clients {
			keep = keep || slices.Contains(allocation.Pools, name)
		}
		if !keep {
			delete(record.Pools, name)
		}
	}
	for _, pool := range gw.Spec.WireGuard.AddressPools {
		p, _ := netip.ParsePrefix(pool.CIDR)
		cidr := p.Masked().String()
		if old, ok := record.Pools[pool.Name]; ok && old != cidr {
			for _, c := range record.Clients {
				if slices.Contains(c.Pools, pool.Name) {
					return fmt.Errorf("WireGuard pool CIDR cannot change while addresses are reserved")
				}
			}
		}
		record.Pools[pool.Name] = cidr
	}
	for otherID, other := range state.Gateways {
		if otherID == id {
			continue
		}
		shared := false
		for _, scope := range record.VPCs {
			shared = shared || slices.Contains(other.VPCs, scope)
		}
		if !shared {
			continue
		}
		for _, cidr := range record.Pools {
			p, _ := netip.ParsePrefix(cidr)
			for _, otherCIDR := range other.Pools {
				q, _ := netip.ParsePrefix(otherCIDR)
				if p.Overlaps(q) {
					return fmt.Errorf("WireGuard pools overlap another gateway serving the same VPC")
				}
			}
		}
	}
	used := map[string]bool{}
	for _, c := range record.Clients {
		for _, addr := range c.Addresses {
			used[addr] = true
		}
	}
	keys := map[string]bool{}
	served := map[string]bool{}
	for _, vpc := range vpcs {
		served[vpc.Name] = true
	}
	for i := range conns {
		c := &conns[i]
		wg := c.Spec.WireGuard
		if wg == nil || wg.Client == nil || c.Spec.IPsec != nil {
			return fmt.Errorf("WireGuard client gateway only accepts client peers")
		}
		if len(wg.Client.VPCRefs) < 1 || len(wg.Client.VPCRefs) > 10 || len(wg.Client.AddressPools) < 1 || len(wg.Client.AddressPools) > 2 {
			return fmt.Errorf("WireGuard client reference collections exceed budget")
		}
		var refs []string
		for _, ref := range wg.Client.VPCRefs {
			refs = append(refs, ref.Name)
			if !served[ref.Name] {
				return fmt.Errorf("WireGuard client references a VPC outside its gateway")
			}
		}
		if problem := vpnlimits.WireGuardClientProblem(vpnlimits.WireGuardPeer{PublicKey: wg.PeerPublicKey, PublicKeys: wg.PeerPublicKeys, Endpoint: wg.PeerEndpoint, Endpoints: wg.PeerEndpoints, Keepalive: int64(wg.PersistentKeepalive)}, wg.Client.AddressPools, refs, c.Spec.RemoteCIDRs); problem != "" {
			return fmt.Errorf("invalid WireGuard client: %s", problem)
		}
		if c.UID == "" || keys[wg.PeerPublicKey] {
			return fmt.Errorf("WireGuard clients require distinct public keys and nonempty UIDs")
		}
		keys[wg.PeerPublicKey] = true
		families := map[bool]bool{}
		for _, name := range wg.Client.AddressPools {
			cidr, ok := record.Pools[name]
			if !ok {
				return fmt.Errorf("WireGuard client pool is not declared")
			}
			declared := false
			for _, pool := range gw.Spec.WireGuard.AddressPools {
				declared = declared || pool.Name == name
			}
			if !declared {
				return fmt.Errorf("WireGuard client pool has been removed")
			}
			p, _ := netip.ParsePrefix(cidr)
			if families[p.Addr().Is4()] {
				return fmt.Errorf("WireGuard client selects multiple pools of one family")
			}
			families[p.Addr().Is4()] = true
		}
		if families[false] && wgClientTunnelMTU(vpcs) < 1280 {
			return fmt.Errorf("WireGuard IPv6 clients require a tunnel MTU of at least 1280")
		}
		allocation, ok := record.Clients[string(c.UID)]
		if ok && (allocation.Name != c.Name || !slices.Equal(allocation.Pools, wg.Client.AddressPools)) {
			return fmt.Errorf("WireGuard client allocation identity or pools changed")
		}
		if !ok {
			allocation = wgClientReservation{Name: c.Name, Pools: slices.Clone(wg.Client.AddressPools)}
			for _, pool := range allocation.Pools {
				p, _ := netip.ParsePrefix(record.Pools[pool])
				addr, err := nextWGClientAddress(p, used)
				if err != nil {
					return err
				}
				used[addr] = true
				allocation.Addresses = append(allocation.Addresses, addr)
			}
			record.Clients[string(c.UID)] = allocation
		}
		c.Spec.RemoteCIDRs = nil
		for _, addr := range allocation.Addresses {
			ip, _ := netip.ParseAddr(addr)
			c.Spec.RemoteCIDRs = append(c.Spec.RemoteCIDRs, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
		c.Status.AssignedAddresses = slices.Clone(allocation.Addresses)
	}
	state.Gateways[id] = record
	if len(record.Pools) > wgClientRetainedPools || len(state.Gateways) > wgClientStateRecords {
		return fmt.Errorf("WireGuard allocation records exceed budget")
	}
	total := 0
	for _, g := range state.Gateways {
		total += len(g.Clients)
	}
	if total > wgClientStateRecords {
		return fmt.Errorf("WireGuard client reservations exceed budget")
	}
	return r.saveWGClientState(ctx, secret, state)
}

func (r *VPNGatewayReconciler) ensureWGClientFinalizers(ctx context.Context, gw *sdn.VPNGateway, conns []sdn.VPNConnection) error {
	if !slices.Contains(gw.Finalizers, wgClientFinalizer) {
		gw.Finalizers = append(gw.Finalizers, wgClientFinalizer)
		if err := r.Update(ctx, gw); err != nil {
			return err
		}
	}
	for i := range conns {
		current := &sdn.VPNConnection{}
		if err := r.quotaReader().Get(ctx, client.ObjectKeyFromObject(&conns[i]), current); err != nil {
			return err
		}
		if current.UID != conns[i].UID || current.Generation != conns[i].Generation || !current.DeletionTimestamp.IsZero() {
			return fmt.Errorf("WireGuard client changed while reserving its address")
		}
		if !slices.Contains(current.Finalizers, wgClientFinalizer) {
			current.Finalizers = append(current.Finalizers, wgClientFinalizer)
			if err := r.Update(ctx, current); err != nil {
				return err
			}
		}
		conns[i].ResourceVersion = current.ResourceVersion
		conns[i].Finalizers = slices.Clone(current.Finalizers)
	}
	return nil
}

// Confirm every non-completed owned replica, including terminating predecessor
// pods. Warm standby needs both replicas; a selected endpoint alone is not proof
// that a removed key has stopped running on its sibling.
func (r *VPNGatewayReconciler) wgClientConfigApplied(ctx context.Context, gw *sdn.VPNGateway, checksum string, requireReplicas bool) (bool, error) {
	pods, err := r.listWGClientPods(ctx, gw.Namespace)
	if err != nil {
		return false, err
	}
	_, state, err := r.loadWGClientState(ctx, gw.Namespace)
	if err != nil {
		return false, err
	}
	witnesses := state.Gateways[string(gw.UID)].PodUIDs
	count := 0
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		// Reuse the protected workload owner-reference chain, rather than labels.
		owned := r.appliancePodOwned(ctx, gw, p)
		if !owned && p.Labels[vpnGatewayLabel] != gw.Name && !slices.Contains(witnesses, string(p.UID)) {
			continue
		}
		if !owned {
			return false, nil
		}
		count++
		if !requireReplicas {
			return false, nil
		}
		if !p.DeletionTimestamp.IsZero() || !podReady(p) || p.Annotations[vpnConfigChecksumAnnotation] != checksum {
			return false, nil
		}
		snapshot, err := r.readApplianceStatus(ctx, p.Status.PodIP, backendWireGuard)
		if err != nil {
			return false, err
		}
		if snapshot.ConfigChecksum != checksum {
			return false, nil
		}
	}
	if !requireReplicas {
		if count != 0 {
			return false, nil
		}
		return r.wgClientPortsRevoked(ctx, gw, state.Gateways[string(gw.UID)], &corev1.PodList{})
	}
	expected := 1
	if haMode(gw) == sdn.VPNGatewayHAModeWarmStandby {
		expected = 2
	}
	if count != expected {
		return false, nil
	}
	return r.wgClientPortsRevoked(ctx, gw, state.Gateways[string(gw.UID)], pods)
}

func (r *VPNGatewayReconciler) listWGClientPods(ctx context.Context, namespace string) (*corev1.PodList, error) {
	pods := &corev1.PodList{}
	if err := r.quotaReader().List(ctx, pods, client.InNamespace(namespace), client.Limit(wgClientStateRecords+1)); err != nil {
		return nil, err
	}
	if pods.Continue != "" || len(pods.Items) > wgClientStateRecords {
		return nil, fmt.Errorf("WireGuard ownership scan exceeds budget")
	}
	return pods, nil
}

func (r *VPNGatewayReconciler) rememberWGClientAppliances(ctx context.Context, gw *sdn.VPNGateway, record *wgClientGatewayReservation) error {
	pods, err := r.listWGClientPods(ctx, gw.Namespace)
	if err != nil {
		return err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if r.appliancePodOwned(ctx, gw, pod) || pod.Labels[vpnGatewayLabel] == gw.Name {
			if pod.UID == "" {
				return fmt.Errorf("WireGuard appliance pod has no UID")
			}
			if !slices.Contains(record.PodUIDs, string(pod.UID)) {
				record.PodUIDs = append(record.PodUIDs, string(pod.UID))
			}
		}
	}
	if len(record.PodUIDs) > 64 {
		return fmt.Errorf("WireGuard predecessor pod witnesses exceed budget")
	}
	return r.rememberWGClientPorts(ctx, gw, record, pods)
}

// Persist the predecessor witnesses before deleting their workload owners.
func (r *VPNGatewayReconciler) persistWGClientAppliances(ctx context.Context, gw *sdn.VPNGateway) error {
	secret, state, err := r.loadWGClientState(ctx, gw.Namespace)
	if err != nil {
		return err
	}
	record, exists := state.Gateways[string(gw.UID)]
	if !exists {
		return nil
	}
	if err := r.rememberWGClientAppliances(ctx, gw, &record); err != nil {
		return err
	}
	state.Gateways[string(gw.UID)] = record
	return r.saveWGClientState(ctx, secret, state)
}

func (r *VPNGatewayReconciler) releaseWGClientReservations(ctx context.Context, gw *sdn.VPNGateway, conns []sdn.VPNConnection, deleting bool) error {
	secret, state, err := r.loadWGClientState(ctx, gw.Namespace)
	if err != nil {
		return err
	}
	record, ok := state.Gateways[string(gw.UID)]
	if !ok {
		return r.cleanupUnreservedWGClientFinalizers(ctx, gw, deleting)
	}
	active := map[string]bool{}
	for i := range conns {
		active[string(conns[i].UID)] = true
	}
	for uid, allocation := range record.Clients {
		if !deleting && active[uid] {
			continue
		}
		c := &sdn.VPNConnection{}
		err := r.quotaReader().Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: allocation.Name}, c)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err == nil && string(c.UID) == uid && !deleting && c.DeletionTimestamp.IsZero() {
			return fmt.Errorf("active WireGuard client is missing from the configuration snapshot")
		}
		if err == nil && string(c.UID) == uid && slices.Contains(c.Finalizers, wgClientFinalizer) {
			c.Finalizers = slices.DeleteFunc(c.Finalizers, func(s string) bool { return s == wgClientFinalizer })
			if err := r.Update(ctx, c); err != nil {
				return err
			}
		}
		delete(record.Clients, uid)
	}
	if deleting {
		delete(state.Gateways, string(gw.UID))
	} else {
		// Release historical scopes/pools only after all replicas confirm current config.
		pods, err := r.listWGClientPods(ctx, gw.Namespace)
		if err != nil {
			return err
		}
		currentPorts, err := r.currentWGClientPorts(ctx, gw, record, pods)
		if err != nil {
			return err
		}
		record.PortUIDs = currentPorts
		record.PodUIDs = nil
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed && r.appliancePodOwned(ctx, gw, p) {
				record.PodUIDs = append(record.PodUIDs, string(p.UID))
			}
		}
		record.VPCs = nil
		for _, ref := range append([]sdn.LocalVPCRef{gw.Spec.VPCRef}, gw.Spec.AdditionalVPCRefs...) {
			vpc := &sdn.VPC{}
			if err := r.quotaReader().Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: ref.Name}, vpc); err != nil {
				return err
			}
			record.VPCs = append(record.VPCs, string(vpc.UID))
		}
		for name := range record.Pools {
			keep := false
			for _, pool := range gw.Spec.WireGuard.AddressPools {
				keep = keep || pool.Name == name
			}
			if !keep {
				delete(record.Pools, name)
			}
		}
		state.Gateways[string(gw.UID)] = record
	}
	if err := r.saveWGClientState(ctx, secret, state); err != nil {
		return err
	}
	return r.cleanupUnreservedWGClientFinalizers(ctx, gw, deleting)
}

func (r *VPNGatewayReconciler) cleanupUnreservedWGClientFinalizers(ctx context.Context, gw *sdn.VPNGateway, deleting bool) error {
	_, state, err := r.loadWGClientState(ctx, gw.Namespace)
	if err != nil {
		return err
	}
	reserved := map[string]bool{}
	for _, record := range state.Gateways {
		for uid := range record.Clients {
			reserved[uid] = true
		}
	}
	var peers sdn.VPNConnectionList
	if err := r.quotaReader().List(ctx, &peers, client.InNamespace(gw.Namespace), client.Limit(wgClientStateRecords+1)); err != nil {
		return err
	}
	if peers.Continue != "" || len(peers.Items) > wgClientStateRecords {
		return fmt.Errorf("WireGuard client cleanup scan exceeds budget")
	}
	for i := range peers.Items {
		c := &peers.Items[i]
		if reserved[string(c.UID)] || c.Spec.GatewayRef.Name != gw.Name || c.Spec.WireGuard == nil || c.Spec.WireGuard.Client == nil || !slices.Contains(c.Finalizers, wgClientFinalizer) || (!deleting && c.DeletionTimestamp.IsZero()) {
			continue
		}
		c.Finalizers = slices.DeleteFunc(c.Finalizers, func(s string) bool { return s == wgClientFinalizer })
		if err := r.Update(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) finalizeWGClientGateway(ctx context.Context, gw *sdn.VPNGateway) (bool, error) {
	if !slices.Contains(gw.Finalizers, wgClientFinalizer) {
		return true, nil
	}
	if err := r.persistWGClientAppliances(ctx, gw); err != nil {
		return false, r.fenceWGClientStateFailure(ctx, gw, err)
	}
	if err := r.teardownOwned(ctx, gw); err != nil {
		return false, err
	}
	if err := r.invalidateWGClientStatuses(ctx, gw, "GatewayTerminating", "the WireGuard gateway is terminating"); err != nil {
		return false, err
	}
	clear, err := r.wgClientConfigApplied(ctx, gw, "", false)
	if err != nil || !clear {
		return false, err
	}
	if err := r.releaseWGClientReservations(ctx, gw, nil, true); err != nil {
		return false, err
	}
	gw.Finalizers = slices.DeleteFunc(gw.Finalizers, func(s string) bool { return s == wgClientFinalizer })
	return true, r.Update(ctx, gw)
}

func (r *VPNGatewayReconciler) reflectWGClientConfig(ctx context.Context, gw *sdn.VPNGateway, vpcs []*sdn.VPC, conns []sdn.VPNConnection, applied bool) error {
	for i := range conns {
		want := &conns[i]
		current := &sdn.VPNConnection{}
		if err := r.quotaReader().Get(ctx, client.ObjectKeyFromObject(want), current); err != nil {
			return client.IgnoreNotFound(err)
		}
		if current.UID != want.UID || current.Generation != want.Generation || !current.DeletionTimestamp.IsZero() {
			continue
		}
		previous := current.DeepCopy().Status
		current.Status.AssignedAddresses = slices.Clone(want.Status.AssignedAddresses)
		current.Status.ClientConfig = nil
		ready := applied && gw.Status.Address != "" && gw.Status.PublicKey != ""
		if ready {
			var dns []string
			for _, pool := range gw.Spec.WireGuard.AddressPools {
				if slices.Contains(want.Spec.WireGuard.Client.AddressPools, pool.Name) {
					dns = appendUnique(dns, pool.DNS...)
				}
			}
			current.Status.ClientConfig = &sdn.VPNWireGuardClientConfig{Endpoint: net.JoinHostPort(gw.Status.Address, strconv.Itoa(int(r.listenPort(gw)))), ServerPublicKey: gw.Status.PublicKey, AllowedIPs: clientDestinationCIDRs(want, vpcs), DNS: dns, MTU: int32(wgClientTunnelMTU(vpcs)), PersistentKeepalive: 25}
		}
		reason, message := "ConfigurationPending", "waiting for current client configuration on every appliance"
		if ready {
			reason, message = "ClientConfigured", "current client parameters applied to every appliance"
		}
		setConnCondition(&current.Status, sdn.VPNConnectionConditionClientConfigured, ready, reason, message)
		for j := range current.Status.Conditions {
			current.Status.Conditions[j].ObservedGeneration = current.Generation
		}
		if connStatusEqual(previous, current.Status) {
			continue
		}
		if err := r.Status().Update(ctx, current); err != nil {
			return err
		}
	}
	return nil
}

func wgClientTunnelMTU(vpcs []*sdn.VPC) int {
	// A concrete conservative default also keeps IPv6 enabled on client
	// interfaces; zero is not a usable WireGuard profile MTU.
	mtu := 1280
	if vpcs[0].Spec.MTU != 0 {
		mtu = tunnelMTU(vpcs[0].Spec.MTU, backendWireGuard)
	}
	for _, vpc := range vpcs[1:] {
		if vpc.Spec.MTU > 0 {
			mtu = min(mtu, int(vpc.Spec.MTU))
		}
	}
	return mtu
}

// Retain reservations indefinitely on interrupted cleanup. This poll is short
// enough for local client setup and deletion, without a status feedback loop.
const wgClientCleanupPoll = 2 * time.Second
