package sdn

import (
	"context"
	"net"
	"reflect"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func accessSGGateway() *sdnv1alpha1.VPNGateway {
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name, gw.Namespace, gw.UID = "gateway", "tenant", types.UID("gateway-uid")
	gw.Spec.VPCRef.Name = "vpc-a"
	return gw
}

func getAccessSG(t *testing.T, c client.Client) *sdnv1alpha1.SecurityGroup {
	t.Helper()
	sg := &sdnv1alpha1.SecurityGroup{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant", Name: "gateway-vpn"}, sg); err != nil {
		t.Fatalf("get access SecurityGroup: %v", err)
	}
	return sg
}

func TestAccessSecurityGroupAdmitsOnlyTheTunnelPorts(t *testing.T) {
	gw := accessSGGateway()
	gw.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{ListenPort: 51900}
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	_, pods, _ := net.ParseCIDR("10.244.0.0/16")
	_, services, _ := net.ParseCIDR("10.96.0.0/12")
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{InternalCIDRs: []*net.IPNet{pods, services}}}

	if err := r.ensureAccessSecurityGroup(context.Background(), gw, backendWireGuard); err != nil {
		t.Fatalf("ensureAccessSecurityGroup: %v", err)
	}
	sg := getAccessSG(t, c)
	if !metav1.IsControlledBy(sg, gw) {
		t.Fatalf("access group is not controlled by the gateway: %v", sg.OwnerReferences)
	}
	if sg.Spec.VPCRef.Name != "vpc-a" || sg.Spec.PodSelector.MatchLabels[vpnGatewayLabel] != "gateway" || len(sg.Spec.PodSelector.MatchLabels) != 1 {
		t.Fatalf("access group targets %v / %v, want the gateway's appliance in vpc-a", sg.Spec.VPCRef, sg.Spec.PodSelector)
	}
	// The world reaches the tunnel port only; the cluster's own networks also reach the status/metrics port.
	status := []sdnv1alpha1.SecurityGroupPort{{Protocol: "TCP", Port: 9410}}
	want := []sdnv1alpha1.SecurityGroupRule{
		{From: sdnv1alpha1.SecurityGroupPeer{CIDR: "0.0.0.0/0"}, Ports: []sdnv1alpha1.SecurityGroupPort{{Protocol: "UDP", Port: 51900}}},
		{From: sdnv1alpha1.SecurityGroupPeer{CIDR: "10.244.0.0/16"}, Ports: status},
		{From: sdnv1alpha1.SecurityGroupPeer{CIDR: "10.96.0.0/12"}, Ports: status},
	}
	if !reflect.DeepEqual(sg.Spec.Ingress, want) {
		t.Fatalf("ingress = %+v, want %+v", sg.Spec.Ingress, want)
	}
	udp := []sdnv1alpha1.SecurityGroupPort{{Protocol: "UDP"}}
	wantEgress := []sdnv1alpha1.SecurityGroupEgressRule{
		{To: sdnv1alpha1.SecurityGroupPeer{CIDR: "0.0.0.0/0"}, Ports: udp},
		{To: sdnv1alpha1.SecurityGroupPeer{CIDR: "::/0"}, Ports: udp},
	}
	if !reflect.DeepEqual(sg.Spec.Egress, wantEgress) {
		t.Fatalf("egress = %+v, want UDP to both families only", sg.Spec.Egress)
	}
}

func TestAccessSecurityGroupIPsecPorts(t *testing.T) {
	gw := accessSGGateway()
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}

	if err := r.ensureAccessSecurityGroup(context.Background(), gw, backendIPsec); err != nil {
		t.Fatalf("ensureAccessSecurityGroup: %v", err)
	}
	ports := getAccessSG(t, c).Spec.Ingress[0].Ports
	want := []sdnv1alpha1.SecurityGroupPort{{Protocol: "UDP", Port: 500}, {Protocol: "UDP", Port: 4500}}
	if len(ports) != 2 || ports[0] != want[0] || ports[1] != want[1] {
		t.Fatalf("IPsec ingress ports = %+v, want %+v", ports, want)
	}
}

func TestAccessSecurityGroupRestoresTamperedRules(t *testing.T) {
	gw := accessSGGateway()
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	ctx := context.Background()
	if err := r.ensureAccessSecurityGroup(ctx, gw, backendWireGuard); err != nil {
		t.Fatalf("ensureAccessSecurityGroup: %v", err)
	}

	// A tenant widens the group to expose the appliance's metrics port.
	sg := getAccessSG(t, c)
	sg.Spec.Ingress = append(sg.Spec.Ingress, sdnv1alpha1.SecurityGroupRule{
		From:  sdnv1alpha1.SecurityGroupPeer{CIDR: "0.0.0.0/0"},
		Ports: []sdnv1alpha1.SecurityGroupPort{{Protocol: "TCP", Port: 9410}},
	})
	if err := c.Update(ctx, sg); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := r.ensureAccessSecurityGroup(ctx, gw, backendWireGuard); err != nil {
		t.Fatalf("ensureAccessSecurityGroup: %v", err)
	}
	if got := getAccessSG(t, c).Spec.Ingress; len(got) != 1 || got[0].Ports[0].Port != 51820 {
		t.Fatalf("ingress after reconcile = %+v, want the listen port only", got)
	}
}

func TestAccessSecurityGroupNeverAdoptsAForeignGroup(t *testing.T) {
	gw := accessSGGateway()
	foreign := &sdnv1alpha1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: "tenant"}}
	foreign.Spec.VPCRef.Name = "vpc-a"
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(foreign).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}

	if err := r.ensureAccessSecurityGroup(context.Background(), gw, backendWireGuard); err == nil {
		t.Fatal("ensureAccessSecurityGroup adopted a group the gateway does not control")
	}
	if sg := getAccessSG(t, c); len(sg.Spec.Ingress) != 0 || len(sg.OwnerReferences) != 0 {
		t.Fatalf("foreign group was modified: %+v", sg)
	}
}

func TestTeardownRemovesAccessSecurityGroup(t *testing.T) {
	gw := accessSGGateway()
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	ctx := context.Background()
	if err := r.ensureAccessSecurityGroup(ctx, gw, backendWireGuard); err != nil {
		t.Fatalf("ensureAccessSecurityGroup: %v", err)
	}
	if err := r.teardownOwned(ctx, gw); err != nil {
		t.Fatalf("teardownOwned: %v", err)
	}
	var list sdnv1alpha1.SecurityGroupList
	if err := c.List(ctx, &list, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("access group survived teardown: %v", list.Items)
	}
}

// Through Reconcile: the gateway grows its access group with the appliance, and drops it when rejected input
// tears the appliance down.
func TestReconcileOwnsTheAccessSecurityGroup(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "door", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPNConnectionSpec{GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}, RemoteCIDRs: []string{"203.0.113.0/24"}, WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{PeerPublicKey: key.PublicKey().String()}}}
	c := vpnIndexClient(t, gw, vpc, peer)
	r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
	sg := &sdnv1alpha1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "door-vpn"}}

	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(sg), sg); err != nil {
		t.Fatalf("access group after Reconcile: %v", err)
	}
	if sg.Spec.Ingress[0].Ports[0] != (sdnv1alpha1.SecurityGroupPort{Protocol: "UDP", Port: 51820}) {
		t.Fatalf("access group ingress = %+v, want the default listen port", sg.Spec.Ingress)
	}

	if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
		t.Fatal(err)
	}
	peer.Spec.RemoteCIDRs = make([]string, 4097)
	for i := range peer.Spec.RemoteCIDRs {
		peer.Spec.RemoteCIDRs[i] = "203.0.113.0/24"
	}
	if err := c.Update(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(sg), sg); !apierrors.IsNotFound(err) {
		t.Fatalf("a torn-down gateway keeps its access group: %v", err)
	}
}
