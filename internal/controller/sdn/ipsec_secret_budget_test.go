package sdn

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ipsecSecretBudgetFixture(tb testing.TB) (*VPNGatewayReconciler, *sdn.VPNGateway, []sdn.VPNConnection) {
	tb.Helper()
	r, gw, conns := ipsecProposalBudgetFixture(tb)
	gw.Spec.IPsec.Proposals = nil
	secret := &corev1.Secret{}
	if err := r.Get(tb.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: "credential"}, secret); err != nil {
		tb.Fatal(err)
	}
	secret.Data["psk"] = []byte(strings.Repeat("a", 256<<10))
	if len(secret.Data["psk"]) > corev1.MaxSecretSize {
		tb.Fatal("fixture exceeds Kubernetes Secret limit")
	}
	if err := r.Update(tb.Context(), secret); err != nil {
		tb.Fatal(err)
	}
	r.Client.(*wgBudgetClient).secretReads = 0
	return r, gw, conns
}

func TestIPsecSecretBudgetBeforeRepeatedSerialization(t *testing.T) {
	r, gw, conns := ipsecSecretBudgetFixture(t)
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	if err == nil {
		t.Fatalf("256KiB PSK in one valid-size Secret produced %d-byte config for16 peers", len(raw))
	}
	if raw != nil || r.Client.(*wgBudgetClient).secretReads != 1 {
		t.Fatal("oversized credential was repeatedly fetched or serialized")
	}
}

func BenchmarkIPsecRepeatedSecretBudget(b *testing.B) {
	r, gw, conns := ipsecSecretBudgetFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.buildIPsecConfig(b.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	}
}

func TestIPsecPSKSecretBudgetAliasesAndExactRecovery(t *testing.T) {
	for _, key := range []string{"psk", "presharedKey", "custom"} {
		t.Run(key, func(t *testing.T) {
			r, gw, _ := ipsecSecretBudgetFixture(t)
			secret := &corev1.Secret{}
			objectKey := client.ObjectKey{Namespace: gw.Namespace, Name: "credential"}
			if err := r.Get(t.Context(), objectKey, secret); err != nil {
				t.Fatal(err)
			}
			bad := []byte("secret-canary-" + strings.Repeat("a", vpnlimits.IPsecAuthBytes))
			secret.Data = map[string][]byte{key: bad}
			if err := r.Update(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
			value, err := r.readPSK(t.Context(), gw.Namespace, secret.Name)
			if err == nil || value != "" || len(err.Error()) > 128 || strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("oversized PSK accepted or exposed")
			}
			if err := r.Get(t.Context(), objectKey, secret); err != nil || !bytes.Equal(secret.Data[key], bad) {
				t.Fatal("rejection changed stored identity")
			}
			want := strings.Repeat("a", vpnlimits.IPsecAuthBytes-3) + "\r\nb"
			secret.Data[key] = []byte(want)
			if err := r.Update(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
			value, err = r.readPSK(t.Context(), gw.Namespace, secret.Name)
			if err != nil || value != want {
				t.Fatal("boundary PSK was truncated, normalized or rejected")
			}
		})
	}
}

func TestIPsecEAPSecretBudgetAndConfigurationRecovery(t *testing.T) {
	r, gw, conns := ipsecSecretBudgetFixture(t)
	gw.Spec.IPsec.CredentialSecretRef = "tls"
	gw.Spec.IPsec.AddressPools = []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "203.0.113.0/24"}}
	tls := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "tls"}, Data: map[string][]byte{corev1.TLSCertKey: []byte("certificate"), corev1.TLSPrivateKeyKey: []byte("private-key")}}
	if err := r.Create(t.Context(), tls); err != nil {
		t.Fatal(err)
	}
	conns = conns[:1]
	conns[0].Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: "peer@example.invalid", SecretRef: "credential"}}
	conns[0].Spec.IPsec.AddressPool = "clients"
	secret := &corev1.Secret{}
	if err := r.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: "credential"}, secret); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"password", "eap", "custom"} {
		secret.Data = map[string][]byte{key: []byte("secret-canary-" + strings.Repeat("a", vpnlimits.IPsecAuthBytes))}
		if err := r.Update(t.Context(), secret); err != nil {
			t.Fatal(err)
		}
		raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
		if err == nil || raw != nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("oversized EAP serialized or exposed")
		}
		want := strings.Repeat("a", vpnlimits.IPsecAuthBytes-3) + "\r\nb"
		secret.Data[key] = []byte(want)
		if err := r.Update(t.Context(), secret); err != nil {
			t.Fatal(err)
		}
		raw, err = r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Peers []struct {
				Password string `json:"eapPassword"`
			} `json:"peers"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Peers) != 1 || cfg.Peers[0].Password != want {
			t.Fatal("EAP credential was not preserved exactly")
		}
	}
}

func TestIPsecTLSSecretTupleBudgetAndRecovery(t *testing.T) {
	for _, key := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, "ca.crt"} {
		t.Run(key, func(t *testing.T) {
			r, gw, _ := ipsecSecretBudgetFixture(t)
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "tls"}, Data: map[string][]byte{corev1.TLSCertKey: []byte("certificate"), corev1.TLSPrivateKeyKey: []byte("key"), "ca.crt": []byte("ca")}}
			secret.Data[key] = []byte("secret-canary-" + strings.Repeat("a", vpnlimits.IPsecTLSBytes))
			if err := r.Create(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
			cert, private, ca, err := r.readTLSCredential(t.Context(), gw.Namespace, secret.Name)
			if err == nil || cert != "" || private != "" || ca != "" || strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("oversized TLS tuple partly returned or exposed")
			}
			secret.Data[key] = []byte(strings.Repeat("a", vpnlimits.IPsecTLSBytes))
			if err := r.Update(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
			cert, private, ca, err = r.readTLSCredential(t.Context(), gw.Namespace, secret.Name)
			if err != nil || cert != string(secret.Data[corev1.TLSCertKey]) || private != string(secret.Data[corev1.TLSPrivateKeyKey]) || ca != string(secret.Data["ca.crt"]) {
				t.Fatal("boundary TLS tuple changed")
			}
			if key == "ca.crt" {
				value, err := r.readSecretValue(t.Context(), gw.Namespace, secret.Name, key)
				if err != nil || value != ca {
					t.Fatal("separate CA Secret boundary changed")
				}
				secret.Data[key] = append(secret.Data[key], 'a')
				if err := r.Update(t.Context(), secret); err != nil {
					t.Fatal(err)
				}
				if value, err = r.readSecretValue(t.Context(), gw.Namespace, secret.Name, key); err == nil || value != "" {
					t.Fatal("oversized separate CA Secret accepted")
				}
			}
		})
	}
}
