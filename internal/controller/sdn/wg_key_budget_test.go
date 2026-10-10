package sdn

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type wgBudgetClient struct {
	client.Client
	secretReads int
}

func (c *wgBudgetClient) Get(ctx context.Context, key client.ObjectKey, out client.Object, opts ...client.GetOption) error {
	if _, ok := out.(*corev1.Secret); ok {
		c.secretReads++
	}
	return c.Client.Get(ctx, key, out, opts...)
}

func TestWGLegacyInputsRejectedWithoutSensitiveDiagnostics(t *testing.T) {
	const key = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	scheme := svcScheme(t)
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
	bad := []byte("secret-canary-" + strings.Repeat("A", 128<<10))
	psk := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "credential"}, Data: map[string][]byte{"psk": bad}}
	c := &wgBudgetClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(psk).Build()}
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	conn := sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKey: string(bad), PresharedKeySecretRef: psk.Name}}}
	raw, err := r.buildWGConfig(t.Context(), gw, []*sdn.VPC{{}}, []string{key}, []sdn.VPNConnection{conn}, 0)
	if err == nil || raw != nil || c.secretReads != 0 {
		t.Fatal("invalid public key reached Secret reads or serialization")
	}
	conn.Spec.WireGuard.PeerPublicKey = key
	raw, err = r.buildWGConfig(t.Context(), gw, []*sdn.VPC{{}}, []string{key}, []sdn.VPNConnection{conn}, 0)
	if err == nil || raw != nil || c.secretReads != 1 {
		t.Fatal("invalid PSK serialized")
	}
	if len(err.Error()) > 1024 || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("PSK appears in diagnostic")
	}
	stored := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: gw.Name + "-wg-keys"}, Data: map[string][]byte{"privateKey": bad}}
	if err := controllerutil.SetControllerReference(gw, stored, scheme); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(t.Context(), stored); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ensureKeypairs(t.Context(), gw, 1); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("invalid stored private key accepted or exposed")
	}
	current := &corev1.Secret{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(stored), current); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.Data["privateKey"], bad) || len(current.Data) != 1 {
		t.Fatal("invalid existing private identity regenerated or mutated")
	}
}

func wgLargePeerSet() []sdn.VPNConnection {
	peers := make([]sdn.VPNConnection, 16)
	large := strings.Repeat("A", 128<<10)
	for i := range peers {
		peers[i].Spec.WireGuard = &sdn.VPNConnectionWireGuard{PeerPublicKey: large}
	}
	return peers
}

func TestWGKeyBudgetRejectsBeforeConfigSerialization(t *testing.T) {
	r := &VPNGatewayReconciler{}
	raw, err := r.buildWGConfig(t.Context(), &sdn.VPNGateway{}, []*sdn.VPC{{}}, []string{"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, wgLargePeerSet(), 0)
	if err == nil {
		t.Fatalf("invalid keys generated %d-byte Secret config (Secret data limit=1048576)", len(raw))
	}
}

func BenchmarkWGInvalidKeyConfigBudget(b *testing.B) {
	r := &VPNGatewayReconciler{}
	peers := wgLargePeerSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.buildWGConfig(b.Context(), &sdn.VPNGateway{}, []*sdn.VPC{{}}, []string{"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, peers, 0)
	}
}
