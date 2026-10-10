package sdn

import (
	"fmt"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVPNRejectsOversizedRouteInputAndRecovers(t *testing.T) {
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
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "door-vpn"}}
	binding := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "door-vpn"}}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(binding), binding); err != nil || !binding.Spec.AllowForwarding {
		t.Fatalf("valid input did not authorize forwarding: %+v %v", binding.Spec, err)
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
	for _, obj := range []client.Object{deployment, binding} {
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); !apierrors.IsNotFound(err) {
			t.Errorf("oversized input keeps active %T: %v", obj, err)
		}
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
		t.Fatal(err)
	}
	peer.Spec.RemoteCIDRs = []string{"203.0.113.0/24"}
	if err := c.Update(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	for _, obj := range []client.Object{deployment, binding} {
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
			t.Fatalf("valid input did not recover %T: %v", obj, err)
		}
	}
}

func TestVPNRejectionDiagnosticsAreBounded(t *testing.T) {
	cidrs := make([]string, 4096)
	for i := range cidrs {
		cidrs[i] = "169.254.169.254/32"
	}
	cidrs[0] = strings.Repeat("invalid", 10000)
	conns := []sdnv1alpha1.VPNConnection{{Spec: sdnv1alpha1.VPNConnectionSpec{RemoteCIDRs: cidrs}}}
	r := &VPNGatewayReconciler{}
	rejected := r.filterForbiddenCIDRs(conns, nil)
	message := remoteCIDRsMessage(rejected)
	if len(conns[0].Spec.RemoteCIDRs) != 0 {
		t.Fatal("forbidden inputs retained")
	}
	if len(message) > 4096 || len(rejected) > 33 {
		t.Fatalf("diagnostics retained=%d message=%d bytes", len(rejected), len(message))
	}
	if !strings.Contains(message, "omitted") {
		t.Fatal("omitted diagnostics not reported")
	}
}

func TestVPNPrefixBudgetIncludesAllPeersAndPoolExpansion(t *testing.T) {
	conns := []sdnv1alpha1.VPNConnection{
		{Spec: sdnv1alpha1.VPNConnectionSpec{RemoteCIDRs: make([]string, 2048)}},
		{Spec: sdnv1alpha1.VPNConnectionSpec{RemoteCIDRs: make([]string, 2048), IPsec: &sdnv1alpha1.VPNConnectionIPsec{AddressPool: "clients"}}},
	}
	if problem := vpnRouteInputProblem(conns); problem != "" {
		t.Fatal("exact capacity rejected", problem)
	}
	gw := &sdnv1alpha1.VPNGateway{Spec: sdnv1alpha1.VPNGatewaySpec{IPsec: &sdnv1alpha1.VPNGatewayIPsec{AddressPools: []sdnv1alpha1.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24"}}}}}
	if err := applyIPsecAddressPools(gw, conns); err != nil {
		t.Fatal(err)
	}
	if problem := vpnRouteInputProblem(conns); problem == "" {
		t.Fatal("pool prefix bypassed aggregate capacity")
	}
	conns[1].Spec.RemoteCIDRs = []string{"10.250.0.0/24"}
	if err := applyIPsecAddressPools(gw, conns); err != nil {
		t.Fatal(err)
	}
	if len(conns[1].Spec.RemoteCIDRs) != 1 {
		t.Fatal("existing selected pool expanded twice")
	}
}

func TestVPNQuotaRejectsBeforePoolExpansionOrCredentialRead(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "door", UID: "gateway-current"}, Spec: sdnv1alpha1.VPNGatewaySpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "net"}, IPsec: &sdnv1alpha1.VPNGatewayIPsec{}}}
	objects := []client.Object{gw, vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")}
	for i := range 17 {
		objects = append(objects, &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: fmt.Sprintf("peer-%d", i)}, Spec: sdnv1alpha1.VPNConnectionSpec{GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}, IPsec: &sdnv1alpha1.VPNConnectionIPsec{AddressPool: "missing-pool"}}})
	}
	c := vpnIndexClient(t, objects...)
	r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPNGatewayConditionApplianceReady)
	if condition == nil || condition.Reason != "QuotaExceeded" {
		t.Fatalf("over-quota gateway reached pool/credential stage: %+v", condition)
	}
}

func TestVPNLegacyOversizedCollectionsStopBeforeSecretsOrWorkloads(t *testing.T) {
	for _, collection := range []string{"pools", "DNS", "BGP"} {
		t.Run(collection, func(t *testing.T) {
			gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "door", UID: "gateway-current"}, Spec: sdnv1alpha1.VPNGatewaySpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "net"}, IPsec: &sdnv1alpha1.VPNGatewayIPsec{CredentialSecretRef: "missing-credential"}}}
			switch collection {
			case "pools":
				gw.Spec.IPsec.AddressPools = make([]sdnv1alpha1.VPNIPsecAddressPool, 129)
			case "DNS":
				gw.Spec.IPsec.AddressPools = []sdnv1alpha1.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24", DNS: make([]string, 17)}}
			case "BGP":
				gw.Spec.IPsec = nil
				gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeActiveActive, ActiveActive: &sdnv1alpha1.VPNGatewayActiveActive{LocalASN: 64520, PeerASN: 64521, PeerAddresses: make([]string, 65)}}
				for i := range gw.Spec.HA.ActiveActive.PeerAddresses {
					gw.Spec.HA.ActiveActive.PeerAddresses[i] = "10.250.0.1"
				}
			}
			c := vpnIndexClient(t, gw, vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24"))
			r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
				t.Fatal(err)
			}
			condition := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPNGatewayConditionApplianceReady)
			if condition == nil || condition.Reason != "InputLimitExceeded" {
				t.Fatalf("legacy oversized %s reached configuration stage: %+v", collection, condition)
			}
		})
	}
}
