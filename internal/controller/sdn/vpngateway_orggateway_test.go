package sdn

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/orggateway"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var testOrgGateway = orggateway.Config{
	Enabled: true, GatewayLabel: "namespace.cozystack.io/gateway", ApexLabel: "namespace.cozystack.io/host",
	ServiceSelector: map[string]string{
		"gateway.envoyproxy.io/owning-gateway-name":      "cozystack",
		"gateway.envoyproxy.io/owning-gateway-namespace": orggateway.NamespacePlaceholder,
	},
	AddressCIDRs: []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")},
	ApexSuffixes: []string{"apps.example.test"},
}

// orgGatewayObjects: namespace tenant-a owns its Gateway, whose Envoy proxy
// Service holds 10.240.0.5 from the reserve.
func orgGatewayObjects() []client.Object {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Labels: map[string]string{testOrgGateway.GatewayLabel: "tenant-a"}}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "envoy-tenant-a-cozystack", Labels: map[string]string{
		"gateway.envoyproxy.io/owning-gateway-name":      "cozystack",
		"gateway.envoyproxy.io/owning-gateway-namespace": "tenant-a",
	}}}
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.240.0.5"}}
	return []client.Object{ns, svc}
}

type renderedWG struct {
	Peers []struct {
		AllowedDestinationCIDRs []string `json:"allowedDestinationCIDRs"`
	} `json:"peers"`
	Routing             *vpnRoutingConfig `json:"routing"`
	GatewayDestinations []string          `json:"gatewayDestinations"`
	DNSDestination      string            `json:"dnsDestination"`
}

func TestWireGuardClientsReachTheOrgGateway(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		poolDNS  []string
		vpnDNS   bool
		wantDNS  bool
		disabled bool
	}{
		{name: "gateway only"},
		{name: "tenant pool DNS never widens", poolDNS: []string{"192.0.2.53"}, vpnDNS: true},
		{name: "cluster DNS without vpnDNS stays closed", poolDNS: []string{"10.96.0.10"}},
		{name: "cluster DNS with vpnDNS", poolDNS: []string{"10.96.0.10"}, vpnDNS: true, wantDNS: true},
		{name: "feature off", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, connection, vpc := wgSecurityFixture()
			gw.Spec.WireGuard.AddressPools[0].DNS = tc.poolDNS
			c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).
				WithObjects(append(orgGatewayObjects(), gw, connection, vpc)...).Build()
			cfg := testOrgGateway
			cfg.VPNDNS = tc.vpnDNS
			if tc.disabled {
				cfg = orggateway.Config{}
			}
			r := &VPNGatewayReconciler{Client: c, Config: VPNGatewayConfig{OrgGateway: cfg, ClusterDNS: "10.96.0.10"}}
			raw, err := r.buildWGConfig(t.Context(), gw, []*sdn.VPC{vpc}, []string{key.String()}, []sdn.VPNConnection{*connection}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			var got renderedWG
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			want := []string{"10.0.0.0/24", "10.240.0.5/32"}
			wantGateways := []string{"10.240.0.5/32"}
			if tc.wantDNS {
				want = []string{"10.0.0.0/24", "10.240.0.5/32", "10.96.0.10/32"}
			}
			if tc.disabled {
				want, wantGateways = []string{"10.0.0.0/24"}, nil
			}
			if !slices.Equal(got.Peers[0].AllowedDestinationCIDRs, want) || !slices.Equal(got.GatewayDestinations, wantGateways) {
				t.Fatalf("filter %v gateways %v, want %v %v", got.Peers[0].AllowedDestinationCIDRs, got.GatewayDestinations, want, wantGateways)
			}
			if (got.DNSDestination != "") != tc.wantDNS {
				t.Fatalf("dnsDestination = %q", got.DNSDestination)
			}

			// The published client profile carries the same AllowedIPs as the filter.
			gw.Status.Address, gw.Status.PublicKey = "192.0.2.1", key.PublicKey().String()
			if err := r.reflectWGClientConfig(t.Context(), gw, []*sdn.VPC{vpc}, []sdn.VPNConnection{*connection}, true); err != nil {
				t.Fatal(err)
			}
			current := &sdn.VPNConnection{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), current); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(current.Status.ClientConfig.AllowedIPs, want) {
				t.Fatalf("client AllowedIPs %v, want %v", current.Status.ClientConfig.AllowedIPs, want)
			}
		})
	}
}

func TestIPsecAndBGPCarryTheOrgGateway(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{}}}
	gw.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"}}}
	peer := sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site"}, Spec: sdn.VPNConnectionSpec{
		RemoteCIDRs: []string{"198.18.0.0/24"}, IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "psk"}},
	}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "psk", Namespace: gw.Namespace}, Data: map[string][]byte{"psk": []byte("test-secret")}}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(append(orgGatewayObjects(), secret)...).Build()
	r := &VPNGatewayReconciler{Client: c, Config: VPNGatewayConfig{OrgGateway: testOrgGateway}}
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}}}, []sdn.VPNConnection{peer}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Peers []struct {
			LocalCIDRs []string `json:"localCIDRs"`
		} `json:"peers"`
		Routing             *vpnRoutingConfig `json:"routing"`
		GatewayDestinations []string          `json:"gatewayDestinations"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/24", "10.240.0.5/32"}
	if !slices.Equal(got.Peers[0].LocalCIDRs, want) || got.Routing == nil || !slices.Equal(got.Routing.AdvertiseCIDRs, want) ||
		!slices.Equal(got.GatewayDestinations, []string{"10.240.0.5/32"}) {
		t.Fatalf("selectors %v adverts %+v gateways %v, want %v", got.Peers[0].LocalCIDRs, got.Routing, got.GatewayDestinations, want)
	}
}

func TestOrgGatewayWatchesEnqueueServedGateways(t *testing.T) {
	child := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a-web", Labels: map[string]string{testOrgGateway.GatewayLabel: "tenant-a"}}}
	unrelated := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b", Labels: map[string]string{testOrgGateway.GatewayLabel: "tenant-b"}}}
	gateways := []client.Object{
		&sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "office", Namespace: "tenant-a"}},
		&sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "laptops", Namespace: "tenant-a-web"}},
		&sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "tenant-b"}},
	}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(append(append(orgGatewayObjects(), child, unrelated), gateways...)...).Build()
	r := &VPNGatewayReconciler{Client: c, Config: VPNGatewayConfig{OrgGateway: testOrgGateway}}
	names := func(reqs []ctrl.Request) []string {
		var out []string
		for _, req := range reqs {
			out = append(out, req.Namespace+"/"+req.Name)
		}
		slices.Sort(out)
		return out
	}
	svc := orgGatewayObjects()[1]
	if got := names(r.mapOrgGatewayServiceToVPNGateways(t.Context(), svc)); !slices.Equal(got, []string{"tenant-a-web/laptops", "tenant-a/office"}) {
		t.Fatalf("Service event enqueued %v", got)
	}
	other := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "web"}}
	if got := r.mapOrgGatewayServiceToVPNGateways(t.Context(), other); len(got) != 0 {
		t.Fatalf("an unrelated Service enqueued %v", got)
	}
	if got := names(r.mapNamespaceToVPNGateways(t.Context(), child)); !slices.Equal(got, []string{"tenant-a-web/laptops"}) {
		t.Fatalf("Namespace event enqueued %v", got)
	}
}

// A reserve address any other Service holds is contested: no VPN client or site
// is pointed at it, and that Service's events re-render every gateway.
func TestOrgGatewayAddressHeldElsewhereIsDropped(t *testing.T) {
	squatter := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-z", Name: "lb"}}
	squatter.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.240.0.5"}}
	gateways := []client.Object{
		&sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "office", Namespace: "tenant-a"}},
		&sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "tenant-z"}},
	}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(append(append(orgGatewayObjects(), squatter), gateways...)...).Build()
	r := &VPNGatewayReconciler{Client: c, Config: VPNGatewayConfig{OrgGateway: testOrgGateway}}
	got, err := r.orgGatewayDestinations(t.Context(), "tenant-a")
	if err != nil || len(got) != 0 {
		t.Fatalf("contested address still granted: %v %v", got, err)
	}
	if reqs := r.mapOrgGatewayServiceToVPNGateways(t.Context(), squatter); len(reqs) != 2 {
		t.Fatalf("a reserve-holding Service enqueued %v, want every gateway", reqs)
	}
}
