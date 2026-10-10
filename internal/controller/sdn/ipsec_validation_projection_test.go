package sdn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIPsecPSKGatewayProjectsConfiguredLocalIdentity(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a"}, Spec: sdn.VPNGatewaySpec{
		IPsec: &sdn.VPNGatewayIPsec{LocalIdentity: "vpn.example.invalid"},
	}}
	peer := sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site"}, Spec: sdn.VPNConnectionSpec{
		RemoteCIDRs: []string{"198.18.0.0/24"}, IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "psk"}},
	}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "psk", Namespace: gw.Namespace}, Data: map[string][]byte{"psk": []byte("test-secret")}}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(secret).Build()
	r := &VPNGatewayReconciler{Client: c}
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}}}, []sdn.VPNConnection{peer}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		LocalIdentity string
		Credentials   *struct{ LocalIdentity string }
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.LocalIdentity != gw.Spec.IPsec.LocalIdentity && (cfg.Credentials == nil || cfg.Credentials.LocalIdentity != gw.Spec.IPsec.LocalIdentity) {
		t.Fatal("PSK gateway localIdentity silently omitted from appliance configuration")
	}
}

func TestIPsecCloudInitPinsChecksumToEmbeddedConfiguration(t *testing.T) {
	for _, cfg := range [][]byte{[]byte(`{"peers":[],"localIdentity":"vpn.example.invalid"}`), []byte("{\n  \"peers\": []\n}\n")} {
		userdata := vpnCloudInit(backendIPsec, cfg)
		sum := sha256.Sum256(cfg)
		if !strings.Contains(userdata, "VPN_CONFIG_CHECKSUM="+hex.EncodeToString(sum[:])) {
			t.Fatal("generated VM appliance does not pin the exact embedded configuration checksum")
		}
		if !strings.Contains(userdata, "content: "+base64.StdEncoding.EncodeToString(cfg)) {
			t.Fatal("generated VM payload changed the configuration bytes that its checksum attests")
		}
	}
}

func TestIPsecPeersProjectOnlyServedVPCTrafficSelectors(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{}}}
	peer := sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site"}, Spec: sdn.VPNConnectionSpec{
		RemoteCIDRs: []string{"198.18.0.0/24"}, IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "psk"}},
	}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "psk", Namespace: gw.Namespace}, Data: map[string][]byte{"psk": []byte("test-secret")}}
	r := &VPNGatewayReconciler{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(secret).Build()}
	served := []*sdn.VPC{
		{Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24", "fd00:1::/64"}}},
		{Spec: sdn.VPCSpec{CIDRs: []string{"10.1.0.0/24"}}},
	}
	for _, vpcs := range [][]*sdn.VPC{served, served[:1]} {
		raw, err := r.buildIPsecConfig(t.Context(), gw, vpcs, []sdn.VPNConnection{peer}, 1280)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Peers []struct{ LocalCIDRs []string }
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, vpc := range vpcs {
			want = append(want, vpc.Spec.CIDRs...)
		}
		if len(cfg.Peers) != 1 {
			t.Fatalf("expected one peer, got %d", len(cfg.Peers))
		}
		slices.Sort(want)
		slices.Sort(cfg.Peers[0].LocalCIDRs)
		if !slices.Equal(cfg.Peers[0].LocalCIDRs, want) {
			t.Fatalf("peer local selectors = %v, expected only current served VPCs %v", cfg.Peers[0].LocalCIDRs, want)
		}
	}
}

func TestIPsecPooledDefaultActionIsResponderOnly(t *testing.T) {
	for _, action := range []sdn.VPNIPsecStartAction{"", sdn.VPNIPsecStartActionNone} {
		spec := &sdn.VPNConnectionIPsec{PeerAddress: "192.0.2.1", AddressPool: "clients", StartAction: action}
		if got := ipsecStartAction(spec); got != "none" {
			t.Fatalf("pooled connection with action %q rendered %q, expected responder-only", action, got)
		}
	}
}

func TestIPsecPeersSharingPoolUseOneXFRMInterfaceDomain(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{
		CredentialSecretRef: "tls", AddressPools: []sdn.VPNIPsecAddressPool{{Name: "first", CIDR: "198.18.0.0/24"}, {Name: "second", CIDR: "198.18.1.0/24"}},
	}}}
	tls := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: gw.Namespace}, Data: map[string][]byte{corev1.TLSCertKey: []byte("certificate"), corev1.TLSPrivateKeyKey: []byte("private-key")}}
	password := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "password", Namespace: gw.Namespace}, Data: map[string][]byte{"password": []byte("test-password")}}
	r := &VPNGatewayReconciler{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(tls, password).Build()}
	var peers []sdn.VPNConnection
	for i, name := range []string{"account-a", "account-b", "account-c"} {
		pool, cidr := "first", "198.18.0.0/24"
		if i == 2 {
			pool, cidr = "second", "198.18.1.0/24"
		}
		peers = append(peers, sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: sdn.VPNConnectionSpec{RemoteCIDRs: []string{cidr}, IPsec: &sdn.VPNConnectionIPsec{AddressPool: pool, Auth: sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: name, SecretRef: password.Name}}}}})
	}
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}}}, peers, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct{ Peers []struct{ IfID uint32 } }
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 3 || cfg.Peers[0].IfID == 0 || cfg.Peers[0].IfID != cfg.Peers[1].IfID || cfg.Peers[0].IfID == cfg.Peers[2].IfID {
		t.Fatalf("pool interface domains incorrectly isolated: %+v", cfg.Peers)
	}
}
