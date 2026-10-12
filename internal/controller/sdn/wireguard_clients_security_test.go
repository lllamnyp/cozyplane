package sdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func wgSecurityFixture() (*sdn.VPNGateway, *sdn.VPNConnection, *sdn.VPC) {
	gateway := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "workstation-gateway", Namespace: "tenant-a", UID: "gateway-current", Generation: 1}, Spec: sdn.VPNGatewaySpec{
		VPCRef:    sdn.LocalVPCRef{Name: "app"},
		WireGuard: &sdn.VPNGatewayWireGuard{AddressPools: []sdn.VPNWireGuardAddressPool{{Name: "workstations", CIDR: "198.18.0.0/24"}}},
	}}
	connection := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "workstation", Namespace: gateway.Namespace, UID: "connection-current", Generation: 7}, Spec: sdn.VPNConnectionSpec{
		GatewayRef: sdn.LocalVPNGatewayRef{Name: gateway.Name},
		WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Client: &sdn.VPNWireGuardClient{
			AddressPools: []string{"workstations"}, VPCRefs: []sdn.LocalVPCRef{{Name: "app"}},
		}},
	}, Status: sdn.VPNConnectionStatus{
		Phase: sdn.VPNConnectionPhaseEstablished, AssignedAddresses: []string{"198.18.0.1"},
		ClientConfig: &sdn.VPNWireGuardClientConfig{Endpoint: "192.0.2.1:51820", ServerPublicKey: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.0.0.0/24"}, MTU: 1320, PersistentKeepalive: 25},
		Conditions:   []metav1.Condition{{Type: sdn.VPNConnectionConditionClientConfigured, Status: metav1.ConditionTrue, Reason: "Configured", ObservedGeneration: 6}},
	}}
	vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: gateway.Namespace, UID: "vpc-current"}, Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}}
	return gateway, connection, vpc
}

func TestWireGuardFailureRevokesPublishedClientConfig(t *testing.T) {
	for _, state := range []string{"active", "deleting", "legacy-malformed"} {
		t.Run(state, func(t *testing.T) {
			gw, connection, _ := wgSecurityFixture()
			switch state {
			case "deleting":
				now := metav1.Now()
				connection.DeletionTimestamp = &now
				connection.Finalizers = []string{wgClientFinalizer}
			case "legacy-malformed":
				connection.Spec.WireGuard = nil
			}
			other := connection.DeepCopy()
			other.Name, other.UID, other.Spec.GatewayRef.Name = "unrelated", "other-current", "other-gateway"
			c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(gw, connection, other).Build()
			r := &VPNGatewayReconciler{Client: c}
			if err := r.invalidateWGClientStatuses(t.Context(), gw, "ConfigurationFailed", "appliance configuration failed"); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
				t.Fatal(err)
			}
			if connection.Status.ClientConfig != nil || len(connection.Status.AssignedAddresses) != 1 || connection.Status.AssignedAddresses[0] != "198.18.0.1" {
				t.Fatal("published config retained or reservation status erased")
			}
			for _, typ := range []string{sdn.VPNConnectionConditionClientConfigured, sdn.VPNConnectionConditionEstablished, sdn.VPNConnectionConditionRoutesProgrammed} {
				condition := meta.FindStatusCondition(connection.Status.Conditions, typ)
				if condition == nil || condition.Status != metav1.ConditionFalse || condition.ObservedGeneration != 7 {
					t.Fatal("client readiness still claims success", typ, condition)
				}
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(other), other); err != nil {
				t.Fatal(err)
			}
			if other.Status.ClientConfig == nil || !meta.IsStatusConditionTrue(other.Status.Conditions, sdn.VPNConnectionConditionClientConfigured) {
				t.Fatal("unrelated gateway status modified")
			}
		})
	}
}

func TestWireGuardFailureAndGatewayDeletionInvalidateClientStatus(t *testing.T) {
	for _, operation := range []string{"configuration-failure", "gateway-deletion"} {
		t.Run(operation, func(t *testing.T) {
			gw, connection, _ := wgSecurityFixture()
			gw.Finalizers = []string{wgClientFinalizer}
			if operation == "gateway-deletion" {
				now := metav1.Now()
				gw.DeletionTimestamp = &now
			}
			scheme := gatewayScheme(t)
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNGateway{}, &sdn.VPNConnection{}).WithObjects(gw, connection).Build()
			r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
				t.Fatal(err)
			}
			if operation == "configuration-failure" {
				if _, err := r.reportUnready(t.Context(), gw, "ConfigurationFailed", "failed"); err != nil {
					t.Fatal(err)
				}
			} else {
				if done, err := r.finalizeWGClientGateway(t.Context(), gw); err != nil || !done {
					t.Fatal("gateway cleanup failed", done, err)
				}
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
				t.Fatal(err)
			}
			if connection.Status.ClientConfig != nil || !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionClientConfigured) {
				t.Fatal("gateway teardown left client parameters claiming successful configuration")
			}
		})
	}
}

func TestWireGuardGenericStatusCannotUpgradeStaleClientConfiguration(t *testing.T) {
	_, connection, _ := wgSecurityFixture()
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(connection).Build()
	r := &VPNGatewayReconciler{Client: c}
	if err := r.reflectConnectionStatus(t.Context(), []sdn.VPNConnection{*connection}, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(connection.Status.Conditions, sdn.VPNConnectionConditionClientConfigured)
	if condition != nil && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == connection.Generation {
		t.Fatal("stale client configuration incorrectly promoted to the newly revoked generation")
	}
}

type wgStatusScanReader struct {
	client.Reader
	partial bool
	err     error
}

func (r wgStatusScanReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if r.err != nil {
		return r.err
	}
	if err := r.Reader.List(ctx, list, opts...); err != nil {
		return err
	}
	if r.partial {
		list.(*sdn.VPNConnectionList).Continue = "remaining"
	}
	return nil
}

func TestWireGuardFailureNeverTreatsIncompleteStatusScanAsSuccess(t *testing.T) {
	for _, failure := range []wgStatusScanReader{{partial: true}, {err: errors.New("reader unavailable")}} {
		gw, connection, _ := wgSecurityFixture()
		c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(gw, connection).Build()
		failure.Reader = c
		r := &VPNGatewayReconciler{Client: c, Reader: failure}
		if err := r.invalidateWGClientStatuses(t.Context(), gw, "ConfigurationFailed", "failed"); err == nil {
			t.Fatal("incomplete live scan reported successful invalidation")
		}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
			t.Fatal(err)
		}
		if connection.Status.ClientConfig == nil {
			t.Fatal("partial enumeration modified a status")
		}
	}
}

func TestWireGuardUnallocatedClientFinalizerCanBeReleased(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	connection.Status = sdn.VPNConnectionStatus{}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(gw, connection, vpc).Build()
	r := &VPNGatewayReconciler{Client: c}
	connection.Spec.WireGuard.Client.AddressPools = []string{"missing-pool"}
	conns := []sdn.VPNConnection{*connection}
	if err := r.ensureWGClientFinalizers(t.Context(), gw, conns); err != nil {
		t.Fatal(err)
	}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, conns); err == nil {
		t.Fatal("missing pool accepted")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
	// No appliance ever received this peer, and no reservation exists. The
	// cleanup pass must still release any previously installed finalizer.
	if err := r.releaseWGClientReservations(t.Context(), gw, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), &sdn.VPNConnection{}); !apierrors.IsNotFound(err) {
		t.Fatal("unallocated deleting client remains stuck behind cleanup finalizer", err)
	}
}

func TestWireGuardLateDeletionRetainsFinalizerWhilePeerRemainsConfigured(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	connection.Finalizers = []string{wgClientFinalizer}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, connection, vpc).Build()
	r := &VPNGatewayReconciler{Client: c}
	activeSnapshot := []sdn.VPNConnection{*connection}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, activeSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
	// Deletion happened after the config snapshot was built/applied. This
	// snapshot still authorizes the peer, so the next rollout must revoke it
	// before deleting its resource, even if cleanup now observes termination.
	if err := r.releaseWGClientReservations(t.Context(), gw, activeSnapshot, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal("client deletion completed while the applied snapshot still contains its key", err)
	}
	if !slices.Contains(connection.Finalizers, wgClientFinalizer) {
		t.Fatal("late deletion lost its revocation barrier")
	}
}

func TestWireGuardMalformedAllocationMapsFailClosed(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	for _, broken := range []wgClientGatewayReservation{
		{Name: gw.Name, VPCs: []string{string(vpc.UID)}, Pools: nil, Clients: map[string]wgClientReservation{}},
		{Name: gw.Name, VPCs: []string{string(vpc.UID)}, Pools: map[string]string{"workstations": "198.18.0.0/24"}, Clients: nil},
	} {
		raw, err := json.Marshal(wgClientState{Gateways: map[string]wgClientGatewayReservation{string(gw.UID): broken}})
		if err != nil {
			t.Fatal(err)
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: wgClientStateName, Namespace: gw.Namespace, Labels: map[string]string{wgClientStateLabel: "true"}}, Data: map[string][]byte{"allocations.json": raw}}
		c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, connection, vpc, secret).Build()
		r := &VPNGatewayReconciler{Client: c}
		if _, _, err := r.loadWGClientState(t.Context(), gw.Namespace); err == nil {
			t.Fatal("malformed allocation map accepted before allocator mutation")
		}
	}
}

func TestWireGuardCleanupFindsOwnedPodWithStrippedLabel(t *testing.T) {
	gw, _, _ := wgSecurityFixture()
	scheme := gatewayScheme(t)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "deployment-current"}}
	replicaSet := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "appliance-current", Namespace: gw.Namespace, UID: "replicaset-current"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "appliance-current", Namespace: gw.Namespace, UID: "pod-current"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	for _, pair := range [][2]client.Object{{gw, deployment}, {deployment, replicaSet}, {replicaSet, pod}} {
		if err := controllerutil.SetControllerReference(pair[0], pair[1], scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, deployment, replicaSet, pod).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	clear, err := r.wgClientConfigApplied(t.Context(), gw, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if clear {
		t.Fatal("stripped label hid a live owned appliance and authorized premature release")
	}
}

func TestWireGuardTenVPCGatewayCanReplaceOneScope(t *testing.T) {
	gw, _, _ := wgSecurityFixture()
	var vpcs []*sdn.VPC
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("vpc-%d", i)
		if i == 0 {
			gw.Spec.VPCRef.Name = name
		} else {
			gw.Spec.AdditionalVPCRefs = append(gw.Spec.AdditionalVPCRefs, sdn.LocalVPCRef{Name: name})
		}
		vpcs = append(vpcs, &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace, UID: types.UID(fmt.Sprintf("vpc-current-%d", i))}})
	}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw).Build()
	r := &VPNGatewayReconciler{Client: c}
	if err := r.allocateWGClients(t.Context(), gw, vpcs, nil); err != nil {
		t.Fatal(err)
	}
	vpcs[9] = &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: "replacement-vpc", Namespace: gw.Namespace, UID: "vpc-replacement"}}
	gw.Spec.AdditionalVPCRefs[8].Name = vpcs[9].Name
	if err := r.allocateWGClients(t.Context(), gw, vpcs, nil); err != nil {
		t.Fatal("valid VPC replacement is permanently blocked by retained-scope budget", err)
	}
	_, state, err := r.loadWGClientState(t.Context(), gw.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Gateways[string(gw.UID)].VPCs) != 11 {
		t.Fatal("predecessor scope was released before config confirmation")
	}
}

func TestWireGuardPoolReplacementNeverPoisonsNamespaceState(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	gw.Spec.WireGuard.AddressPools = nil
	for i := 0; i < 128; i++ {
		gw.Spec.WireGuard.AddressPools = append(gw.Spec.WireGuard.AddressPools, sdn.VPNWireGuardAddressPool{Name: fmt.Sprintf("pool-%d", i), CIDR: fmt.Sprintf("198.18.%d.0/24", i)})
	}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, vpc).Build()
	r := &VPNGatewayReconciler{Client: c}
	connection.Spec.WireGuard.Client.AddressPools = []string{"pool-127"}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, []sdn.VPNConnection{*connection}); err != nil {
		t.Fatal(err)
	}
	gw.Spec.WireGuard.AddressPools[127] = sdn.VPNWireGuardAddressPool{Name: "replacement", CIDR: "198.19.0.0/24"}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, nil); err != nil {
		t.Fatal(err)
	}
	_, state, err := r.loadWGClientState(t.Context(), gw.Namespace)
	if err != nil {
		t.Fatal("valid pool replacement saved unreadable state for every gateway in namespace", err)
	}
	if len(state.Gateways[string(gw.UID)].Pools) != 129 {
		t.Fatal("predecessor pool was released before config confirmation")
	}
}

func TestWireGuardPoolRejectsPendingIPsecPoolInSameVPC(t *testing.T) {
	gw, _, vpc := wgSecurityFixture()
	ipsec := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: gw.Namespace, UID: "ike-current"}, Spec: sdn.VPNGatewaySpec{
		VPCRef: sdn.LocalVPCRef{Name: vpc.Name}, IPsec: &sdn.VPNGatewayIPsec{AddressPools: []sdn.VPNIPsecAddressPool{{Name: "ike-clients", CIDR: "198.18.0.0/24"}}},
	}}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, vpc, ipsec).Build()
	r := &VPNGatewayReconciler{Client: c}
	_, served, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := r.validateWGClientPools(t.Context(), gw, []*sdn.VPC{vpc}, []*net.IPNet{served}); err == nil {
		t.Fatal("pending IPsec pool can later lease the same range as the WireGuard clients")
	}
}
