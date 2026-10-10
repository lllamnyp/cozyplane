package sdn

import (
	"fmt"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ipsecProposalBudgetFixture(t testing.TB) (*VPNGatewayReconciler, *sdn.VPNGateway, []sdn.VPNConnection) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sdn.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{Proposals: []string{strings.Repeat("a", 128<<10)}}}}
	credential := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "credential"}, Data: map[string][]byte{"psk": []byte("test-key")}}
	c := &wgBudgetClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(credential).Build()}
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	conns := make([]sdn.VPNConnection, 16)
	for i := range conns {
		conns[i] = sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("peer-%d", i)}, Spec: sdn.VPNConnectionSpec{RemoteCIDRs: []string{"203.0.113.0/24"}, IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: fmt.Sprintf("peer-%d.example.invalid", i)}}}
		conns[i].Spec.IPsec.Auth.PSKSecretRef = credential.Name
	}
	return r, gw, conns
}

func TestIPsecDefaultProposalBudgetBeforeSerialization(t *testing.T) {
	r, gw, conns := ipsecProposalBudgetFixture(t)
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	if err == nil {
		t.Fatalf("128KiB default proposal generated %d-byte config for16 peers (Secret limit1048576)", len(raw))
	}
	if raw != nil || r.Client.(*wgBudgetClient).secretReads != 0 {
		t.Fatal("oversized proposals reached credentials or serialization")
	}
}

func BenchmarkIPsecDefaultProposalBudget(b *testing.B) {
	r, gw, conns := ipsecProposalBudgetFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.buildIPsecConfig(b.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	}
}

func TestIPsecOverrideProposalBudgetAndRecovery(t *testing.T) {
	r, gw, conns := ipsecProposalBudgetFixture(t)
	gw.Spec.IPsec.Proposals = nil
	for _, proposals := range [][]string{make([]string, 17), {"input-canary-" + strings.Repeat("a", 128<<10)}} {
		conns[15].Spec.IPsec.Proposals = proposals
		raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
		if err == nil || raw != nil || r.Client.(*wgBudgetClient).secretReads != 0 {
			t.Fatal("late invalid override reached earlier peer credential work")
		}
		if len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") {
			t.Fatal("proposal payload retained in error")
		}
	}
	conns[15].Spec.IPsec.Proposals = []string{"aes256gcm16-prfsha384-ecp384"}
	gw.Spec.IPsec.Proposals = []string{"aes256-sha256-modp2048"}
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	if err != nil || len(raw) == 0 || r.Client.(*wgBudgetClient).secretReads != 16 {
		t.Fatalf("valid proposal recovery failed: %v", err)
	}
	if !strings.Contains(string(raw), "aes256-sha256-modp2048") || !strings.Contains(string(raw), "aes256gcm16-prfsha384-ecp384") {
		t.Fatal("default/override semantics changed")
	}
}
