package sdn

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestRoadwarriorPoolBecomesRouteAndVICIConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "gateway-ike-tls", Namespace: "tenant"}, Data: map[string][]byte{
			corev1.TLSCertKey: []byte("certificate"), corev1.TLSPrivateKeyKey: []byte("private-key"), "ca.crt": []byte("ca"),
		}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "device-001-eap", Namespace: "tenant"}, Data: map[string][]byte{
			"password": []byte("password"),
		}},
	).Build()
	r := &VPNGatewayReconciler{Client: client}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}}
	gw.Spec.IPsec = &sdnv1alpha1.VPNGatewayIPsec{
		CredentialSecretRef: "gateway-ike-tls",
		LocalIdentity:       "vpn.example.invalid",
		AddressPools:        []sdnv1alpha1.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24", DNS: []string{"10.0.0.53"}}},
	}
	conns := []sdnv1alpha1.VPNConnection{{ObjectMeta: metav1.ObjectMeta{Name: "device-001"}, Spec: sdnv1alpha1.VPNConnectionSpec{
		IPsec: &sdnv1alpha1.VPNConnectionIPsec{AddressPool: "clients", Auth: sdnv1alpha1.VPNConnectionIPsecAuth{
			EAP: &sdnv1alpha1.VPNIPsecEAPAuth{Identity: "device-001", SecretRef: "device-001-eap"},
		}},
	}}}
	if err := applyIPsecAddressPools(gw, conns); err != nil {
		t.Fatal(err)
	}
	if len(conns[0].Spec.RemoteCIDRs) != 1 || conns[0].Spec.RemoteCIDRs[0] != "10.250.0.0/24" {
		t.Fatalf("pool was not materialized as a route: %v", conns[0].Spec.RemoteCIDRs)
	}
	raw, err := r.buildIPsecConfig(context.Background(), gw, []*sdnv1alpha1.VPC{{}}, conns, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Credentials struct{ Certificate, PrivateKey, CA, LocalID string }
		Pools       []struct{ Name, CIDR string }
		Peers       []struct {
			AuthMode, EAPIdentity, EAPPassword, AddressPool string
			RemoteCIDRs                                     []string
		}
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials.Certificate == "" || cfg.Credentials.PrivateKey == "" || cfg.Credentials.CA == "" {
		t.Fatalf("TLS credentials missing from appliance config: %+v", cfg.Credentials)
	}
	if len(cfg.Pools) != 1 || cfg.Pools[0].CIDR != "10.250.0.0/24" {
		t.Fatalf("unexpected pools: %+v", cfg.Pools)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].AuthMode != "eap" || cfg.Peers[0].EAPPassword == "" || cfg.Peers[0].AddressPool != "clients" {
		t.Fatalf("unexpected peer config: %+v", cfg.Peers)
	}
}

func TestActiveActiveWireGuardConfigUsesPairedPeers(t *testing.T) {
	r := &VPNGatewayReconciler{}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}}
	gw.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{}
	conn := sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "remote"}, Spec: sdnv1alpha1.VPNConnectionSpec{
		RemoteCIDRs: []string{"10.251.0.0/24"},
		WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{
			PeerPublicKeys: []string{"peer-key-0", "peer-key-1"},
			PeerEndpoints:  []string{"192.0.2.10:51820", "192.0.2.11:51820"},
		},
	}}
	raw, err := r.buildWGConfig(context.Background(), gw, []*sdnv1alpha1.VPC{{}}, []string{"private-0", "private-1"}, []sdnv1alpha1.VPNConnection{conn}, 1320)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		PrivateKeys   []string
		PeerInstances [][]struct{ PublicKey, Endpoint string }
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.PrivateKeys) != 2 || len(cfg.PeerInstances) != 2 ||
		cfg.PeerInstances[0][0].PublicKey != "peer-key-0" || cfg.PeerInstances[1][0].Endpoint != "192.0.2.11:51820" {
		t.Fatalf("unexpected active-active WireGuard config: %+v", cfg)
	}
}
