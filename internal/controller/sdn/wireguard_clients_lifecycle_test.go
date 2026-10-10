package sdn

import (
	"context"
	"reflect"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWireGuardClientAddressSurvivesRestartAndKeyRotation(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	gw.Spec.WireGuard.AddressPools = append(gw.Spec.WireGuard.AddressPools, sdn.VPNWireGuardAddressPool{Name: "workstations-v6", CIDR: "fd90::/120"})
	connection.Spec.WireGuard.Client.AddressPools = append(connection.Spec.WireGuard.Client.AddressPools, "workstations-v6")
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, connection, vpc).Build()
	want := []string{"198.18.0.1", "fd90::1"}
	for round := range 3 {
		// A new reconciler models controller restart; no local allocator state.
		r := &VPNGatewayReconciler{Client: c}
		peer := connection.DeepCopy()
		if round > 0 {
			peer.Spec.WireGuard.PeerPublicKey = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}
		peers := []sdn.VPNConnection{*peer}
		if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, peers); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(peers[0].Status.AssignedAddresses, want) || !reflect.DeepEqual(peers[0].Spec.RemoteCIDRs, []string{"198.18.0.1/32", "fd90::1/128"}) {
			t.Fatal("reservation changed", peers[0].Status.AssignedAddresses, peers[0].Spec.RemoteCIDRs)
		}
	}
	stored := &sdn.VPNConnection{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), stored); err != nil || len(stored.Spec.RemoteCIDRs) != 0 {
		t.Fatal("computed server prefixes leaked into user spec", err)
	}
}

func TestWireGuardRetiredAddressIsNotReusedUntilCleanup(t *testing.T) {
	gw, first, vpc := wgSecurityFixture()
	gw.Spec.WireGuard.AddressPools[0].CIDR = "198.18.0.0/30"
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, first, vpc).Build()
	r := &VPNGatewayReconciler{Client: c}
	peers := []sdn.VPNConnection{*first.DeepCopy()}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, peers); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	second := first.DeepCopy()
	second.Name, second.UID = "workstation-next", "connection-next"
	peers = []sdn.VPNConnection{*second}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, peers); err != nil {
		t.Fatal(err)
	}
	if peers[0].Status.AssignedAddresses[0] != "198.18.0.2" {
		t.Fatal("retired address reused before cleanup")
	}
	third := second.DeepCopy()
	third.Name, third.UID = "workstation-third", "connection-third"
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, []sdn.VPNConnection{*third}); err == nil {
		t.Fatal("pool exhaustion ignored")
	}
	// The caller first confirms all old appliances are gone or reconfigured.
	if err := r.releaseWGClientReservations(t.Context(), gw, nil, false); err != nil {
		t.Fatal(err)
	}
	peers = []sdn.VPNConnection{*third}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, peers); err != nil || peers[0].Status.AssignedAddresses[0] != "198.18.0.1" {
		t.Fatal("confirmed cleanup did not release address", err)
	}
}

type wgConflictClient struct {
	client.Client
}

func (c wgConflictClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		return apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, obj.GetName(), nil)
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestWireGuardAllocationConflictCannotCommitNewPeer(t *testing.T) {
	gw, first, vpc := wgSecurityFixture()
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, first, vpc).Build()
	r := &VPNGatewayReconciler{Client: c}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, []sdn.VPNConnection{*first}); err != nil {
		t.Fatal(err)
	}
	second := first.DeepCopy()
	second.Name, second.UID = "workstation-next", "connection-next"
	r.Client = wgConflictClient{Client: c}
	if err := r.allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, []sdn.VPNConnection{*second}); !apierrors.IsConflict(err) {
		t.Fatal("reservation conflict was not propagated", err)
	}
	_, state, err := (&VPNGatewayReconciler{Client: c}).loadWGClientState(t.Context(), gw.Namespace)
	if err != nil || len(state.Gateways[string(gw.UID)].Clients) != 1 {
		t.Fatal("conflicting peer reservation was persisted", err)
	}
}

func TestWireGuardClientConfigContainsOnlySelectedVPCs(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	gw.Status.Address, gw.Status.PublicKey = "192.0.2.1", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	gw.Spec.WireGuard.AddressPools[0].DNS = []string{"10.0.0.53"}
	other := vpc.DeepCopy()
	other.Name, other.UID, other.Spec.CIDRs = "restricted", "vpc-restricted", []string{"10.1.0.0/24"}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(connection).Build()
	r := &VPNGatewayReconciler{Client: c}
	for _, ready := range []bool{true, false} {
		if err := r.reflectWGClientConfig(t.Context(), gw, []*sdn.VPC{vpc, other}, []sdn.VPNConnection{*connection}, ready); err != nil {
			t.Fatal(err)
		}
		stored := &sdn.VPNConnection{}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), stored); err != nil {
			t.Fatal(err)
		}
		if ready {
			cfg := stored.Status.ClientConfig
			if cfg == nil || !reflect.DeepEqual(cfg.AllowedIPs, vpc.Spec.CIDRs) || cfg.Endpoint != "192.0.2.1:51820" || cfg.PersistentKeepalive != 25 || cfg.MTU != 1280 || !reflect.DeepEqual(cfg.DNS, []string{"10.0.0.53"}) {
				t.Fatal("invalid client parameters", cfg)
			}
		} else if stored.Status.ClientConfig != nil {
			t.Fatal("unapplied configuration published")
		}
		condition := meta.FindStatusCondition(stored.Status.Conditions, sdn.VPNConnectionConditionClientConfigured)
		if condition == nil || condition.ObservedGeneration != connection.Generation {
			t.Fatal("missing current generation")
		}
	}
}

func TestWireGuardClientMTURespectsEveryVPCLeg(t *testing.T) {
	gw, connection, vpc := wgSecurityFixture()
	other := vpc.DeepCopy()
	for _, tc := range []struct {
		primary, secondary int32
		want               int
	}{
		{0, 0, 1280}, {1450, 1450, 1370}, {1500, 1300, 1300},
	} {
		vpc.Spec.MTU, other.Spec.MTU = tc.primary, tc.secondary
		if got := wgClientTunnelMTU([]*sdn.VPC{vpc, other}); got != tc.want {
			t.Fatal("unexpected MTU", got, tc.want)
		}
	}
	gw.Spec.WireGuard.AddressPools = []sdn.VPNWireGuardAddressPool{{Name: "workstations-v6", CIDR: "fd90::/120"}}
	connection.Spec.WireGuard.Client.AddressPools = []string{"workstations-v6"}
	vpc.Spec.MTU = 1280
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(gw, vpc).Build()
	if err := (&VPNGatewayReconciler{Client: c}).allocateWGClients(t.Context(), gw, []*sdn.VPC{vpc}, []sdn.VPNConnection{*connection}); err == nil {
		t.Fatal("unusable IPv6 MTU accepted")
	}
}
