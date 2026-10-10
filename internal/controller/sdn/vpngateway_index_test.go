package sdn

import (
	"context"
	"fmt"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type vpnListCounter struct {
	client.Client
	gateways, connections, gets int
}

func (c *vpnListCounter) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*sdnv1alpha1.VPNGateway); ok {
		c.gets++
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *vpnListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	switch rows := list.(type) {
	case *sdnv1alpha1.VPNGatewayList:
		c.gateways += len(rows.Items)
	case *sdnv1alpha1.VPNConnectionList:
		c.connections += len(rows.Items)
	}
	return nil
}

func vpnIndexClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(svcScheme(t)).
		WithIndex(&sdnv1alpha1.Port{}, vpnAppliancePodIndex, vpnAppliancePodKeys).
		WithIndex(&sdnv1alpha1.VPNGateway{}, vpnCredentialIndex, vpnCredentialKeys).
		WithIndex(&sdnv1alpha1.VPNConnection{}, vpnCredentialIndex, vpnCredentialKeys).
		WithIndex(&sdnv1alpha1.VPNGateway{}, gatewayVPCIndex, gatewayVPCKeys).
		WithIndex(&sdnv1alpha1.VPNConnection{}, vpnConnectionGatewayIndex, vpnConnectionGatewayKeys).
		WithStatusSubresource(&sdnv1alpha1.VPNGateway{}, &sdnv1alpha1.VPNConnection{}).WithObjects(objects...).Build()
}

func TestVPNEventsAndPeerLookupCopyOnlyRelatedObjects(t *testing.T) {
	gateway := func(ns, name, vpc string) *sdnv1alpha1.VPNGateway {
		g := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
		g.Spec.VPCRef.Name = vpc
		return g
	}
	peer := func(ns, name, gw string) *sdnv1alpha1.VPNConnection {
		c := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
		c.Spec.GatewayRef.Name = gw
		return c
	}
	a, b := gateway("tenant-a", "door", "net"), gateway("tenant-a", "second-door", "net")
	old := peer("tenant-a", "old-peer", a.Name)
	now := metav1.Now()
	old.DeletionTimestamp = &now
	old.Finalizers = []string{"example.invalid/cleanup"}
	objects := []client.Object{a, b, gateway("tenant-b", "foreign-door", "net"), peer("tenant-a", "peer-a", a.Name), peer("tenant-a", "peer-b", a.Name), old, peer("tenant-b", "foreign-peer", a.Name)}
	for i := range 1400 {
		objects = append(objects, gateway("tenant-a", fmt.Sprintf("other-door-%d", i), fmt.Sprintf("other-vpc-%d", i)), peer("tenant-a", fmt.Sprintf("other-peer-%d", i), fmt.Sprintf("other-door-%d", i)))
	}
	c := &vpnListCounter{Client: vpnIndexClient(t, objects...)}
	r := &VPNGatewayReconciler{Client: c}
	vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/24")
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: vpc.Namespace, sdnv1alpha1.LabelVPC: vpc.Name}}}
	t.Run("Port", func(t *testing.T) {
		c.gateways = 0
		requests := r.mapPortToVPNGateways(t.Context(), port)
		if c.gateways != 2 || len(requests) != 2 {
			t.Fatalf("Port copied=%d queued=%d", c.gateways, len(requests))
		}
	})
	t.Run("VPC", func(t *testing.T) {
		c.gateways = 0
		requests := r.mapVPCToVPNGateways(t.Context(), vpc)
		if c.gateways != 2 || len(requests) != 2 {
			t.Fatalf("VPC copied=%d queued=%d", c.gateways, len(requests))
		}
	})
	t.Run("Peers", func(t *testing.T) {
		conns, err := r.connectionsFor(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}
		if c.connections != 2 || len(conns) != 2 || conns[0].Name != "peer-a" || conns[1].Name != "peer-b" {
			t.Fatalf("peers copied=%d active=%v", c.connections, conns)
		}
	})
}

func TestVPNHubAdditionalVPCEventsFollowRetargetAndDeletion(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "hub"}, Spec: sdnv1alpha1.VPNGatewaySpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "primary"}, AdditionalVPCRefs: []sdnv1alpha1.LocalVPCRef{{Name: "secondary"}}}}
	c := &vpnListCounter{Client: vpnIndexClient(t, gw)}
	r := &VPNGatewayReconciler{Client: c}
	vpc := vpcWithCIDRs(gw.Namespace, "secondary", 101, "10.0.0.0/24")
	if got := r.mapVPCToVPNGateways(t.Context(), vpc); len(got) != 1 || got[0].Name != gw.Name || c.gateways != 1 {
		t.Fatalf("additional VPC event lost: %v copies=%d", got, c.gateways)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	gw.Spec.AdditionalVPCRefs[0].Name = "replacement"
	if err := c.Update(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 0 {
		t.Fatal("old hub VPC retained")
	}
	vpc.Name = "replacement"
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 1 {
		t.Fatal("replacement VPC event lost")
	}
	if err := c.Delete(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 0 {
		t.Fatal("deleted hub retained")
	}
}

func TestVPNReferenceIndexesFollowChangesAndDeletion(t *testing.T) {
	g := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "door"}}
	g.Spec.VPCRef.Name = "net"
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: g.Namespace, Name: "peer"}}
	peer.Spec.GatewayRef.Name = g.Name
	c := vpnIndexClient(t, g, peer)
	r := &VPNGatewayReconciler{Client: c}
	vpc := vpcWithCIDRs(g.Namespace, "net", 101, "10.0.0.0/24")
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 1 {
		t.Fatal("initial VPC index missing")
	}
	if conns, err := r.connectionsFor(t.Context(), g); err != nil || len(conns) != 1 {
		t.Fatalf("initial peer index: %v %v", conns, err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(g), g); err != nil {
		t.Fatal(err)
	}
	g.Spec.VPCRef.Name = "next"
	if err := c.Update(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 0 {
		t.Fatal("old VPC index retained")
	}
	vpc.Name = "next"
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 1 {
		t.Fatal("replacement VPC index missing")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
		t.Fatal(err)
	}
	peer.Spec.GatewayRef.Name = "next-door"
	if err := c.Update(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if conns, err := r.connectionsFor(t.Context(), g); err != nil || len(conns) != 0 {
		t.Fatalf("old peer index retained: %v %v", conns, err)
	}
	other := g.DeepCopy()
	other.Name = "next-door"
	if conns, err := r.connectionsFor(t.Context(), other); err != nil || len(conns) != 1 {
		t.Fatalf("new peer index missing: %v %v", conns, err)
	}
	if err := c.Delete(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if conns, err := r.connectionsFor(t.Context(), other); err != nil || len(conns) != 0 {
		t.Fatalf("deleted peer index retained: %v %v", conns, err)
	}
	if err := c.Delete(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToVPNGateways(t.Context(), vpc)) != 0 {
		t.Fatal("deleted gateway index retained")
	}
}

func TestVPNCredentialEventsCopyOnlyConsumers(t *testing.T) {
	tlsGW := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "tls-door"}, Spec: sdnv1alpha1.VPNGatewaySpec{IPsec: &sdnv1alpha1.VPNGatewayIPsec{CredentialSecretRef: "credential", TrustedCASecretRef: "credential"}}}
	wgGW := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: tlsGW.Namespace, Name: "wg-door"}}
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: tlsGW.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPNConnectionSpec{GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: wgGW.Name}, WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{PresharedKeySecretRef: "credential"}}}
	foreign := tlsGW.DeepCopy()
	foreign.Namespace = "tenant-b"
	objects := []client.Object{tlsGW, wgGW, peer, foreign}
	for i := range 1400 {
		objects = append(objects, &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: tlsGW.Namespace, Name: fmt.Sprintf("other-gw-%d", i)}}, &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: tlsGW.Namespace, Name: fmt.Sprintf("other-peer-%d", i)}})
	}
	c := &vpnListCounter{Client: vpnIndexClient(t, objects...)}
	r := &VPNGatewayReconciler{Client: c}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: tlsGW.Namespace, Name: "credential"}}
	requests := r.mapCredentialToVPNGateways(t.Context(), secret)
	seen := map[string]bool{}
	for _, req := range requests {
		seen[req.Namespace+"/"+req.Name] = true
	}
	if c.gateways != 1 || c.connections != 1 || len(requests) != 2 || !seen["tenant-a/tls-door"] || !seen["tenant-a/wg-door"] {
		t.Errorf("credential event copied gateways=%d peers=%d enqueued=%v", c.gateways, c.connections, seen)
	}
	if c.gets != 1 {
		t.Fatalf("peer gateway resolution gets=%d want=1", c.gets)
	}
	c.gateways, c.connections = 0, 0
	secret.Name = "unreferenced"
	if requests := r.mapCredentialToVPNGateways(t.Context(), secret); len(requests) != 0 || c.gateways != 0 || c.connections != 0 {
		t.Errorf("unreferenced Secret copied gateways=%d peers=%d queued=%d", c.gateways, c.connections, len(requests))
	}
}

func TestVPNCredentialIndexesTrackEveryAuthenticationReference(t *testing.T) {
	for _, kind := range []string{"TLS", "CA", "WG-PSK", "IPsec-PSK", "EAP"} {
		t.Run(kind, func(t *testing.T) {
			gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "door"}}
			peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPNConnectionSpec{GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}}}
			var obj client.Object
			setRef := func(ref string) {
				switch kind {
				case "TLS":
					gw.Spec.IPsec = &sdnv1alpha1.VPNGatewayIPsec{CredentialSecretRef: ref}
					obj = gw
				case "CA":
					gw.Spec.IPsec = &sdnv1alpha1.VPNGatewayIPsec{TrustedCASecretRef: ref}
					obj = gw
				case "WG-PSK":
					peer.Spec.WireGuard = &sdnv1alpha1.VPNConnectionWireGuard{PresharedKeySecretRef: ref}
					obj = peer
				case "IPsec-PSK":
					peer.Spec.IPsec = &sdnv1alpha1.VPNConnectionIPsec{Auth: sdnv1alpha1.VPNConnectionIPsecAuth{PSKSecretRef: ref}}
					obj = peer
				case "EAP":
					peer.Spec.IPsec = &sdnv1alpha1.VPNConnectionIPsec{Auth: sdnv1alpha1.VPNConnectionIPsecAuth{EAP: &sdnv1alpha1.VPNIPsecEAPAuth{SecretRef: ref}}}
					obj = peer
				}
			}
			setRef("old-credential")
			c := vpnIndexClient(t, gw, peer)
			r := &VPNGatewayReconciler{Client: c}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "old-credential"}}
			if len(r.mapCredentialToVPNGateways(t.Context(), secret)) != 1 {
				t.Fatal("authentication reference not observed")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			setRef("new-credential")
			if err := c.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			if len(r.mapCredentialToVPNGateways(t.Context(), secret)) != 0 {
				t.Fatal("retired reference still observed")
			}
			secret.Name = "new-credential"
			if len(r.mapCredentialToVPNGateways(t.Context(), secret)) != 1 {
				t.Fatal("rotated credential not observed")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			setRef("")
			if err := c.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			if len(r.mapCredentialToVPNGateways(t.Context(), secret)) != 0 {
				t.Fatal("removed credential reference retained")
			}
			if err := c.Delete(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			if len(r.mapCredentialToVPNGateways(t.Context(), secret)) != 0 {
				t.Fatal("deleted consumer retained")
			}
		})
	}
}

func TestVPNCredentialMissingGatewayIsResolvedOnce(t *testing.T) {
	objects := []client.Object{}
	for i := range 100 {
		objects = append(objects, &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: fmt.Sprintf("peer-%d", i)}, Spec: sdnv1alpha1.VPNConnectionSpec{GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: "missing-door"}, WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{PresharedKeySecretRef: "credential"}}})
	}
	c := &vpnListCounter{Client: vpnIndexClient(t, objects...)}
	r := &VPNGatewayReconciler{Client: c}
	requests := r.mapCredentialToVPNGateways(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "credential"}})
	if len(requests) != 0 || c.gets != 1 {
		t.Fatalf("missing gateway queued=%d cache gets=%d", len(requests), c.gets)
	}
}
