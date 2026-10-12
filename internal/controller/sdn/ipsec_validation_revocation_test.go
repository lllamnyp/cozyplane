package sdn

import (
	"errors"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestIPsecConfigurationFailureInvalidatesPublishedConnectionStatus(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a", UID: "gateway-current"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{}}}
	connection := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: gw.Namespace, Generation: 3}, Spec: sdn.VPNConnectionSpec{
		GatewayRef: sdn.LocalVPNGatewayRef{Name: gw.Name}, IPsec: &sdn.VPNConnectionIPsec{Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "deleted-psk"}},
	}, Status: sdn.VPNConnectionStatus{Phase: sdn.VPNConnectionPhaseEstablished, Conditions: []metav1.Condition{
		{Type: sdn.VPNConnectionConditionEstablished, Status: metav1.ConditionTrue, Reason: "TunnelEstablished", ObservedGeneration: 2},
		{Type: sdn.VPNConnectionConditionRoutesProgrammed, Status: metav1.ConditionTrue, Reason: "RoutesProgrammed", ObservedGeneration: 2},
	}}}
	other := connection.DeepCopy()
	other.Name, other.Spec.GatewayRef.Name = "unrelated", "other-gateway"
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNGateway{}, &sdn.VPNConnection{}).WithObjects(gw, connection, other).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
	if _, err := r.reportUnready(t.Context(), gw, "ConfigurationFailed", "credential unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	if connection.Status.Phase == sdn.VPNConnectionPhaseEstablished {
		t.Fatal("configuration failure still publishes an established IPSec connection")
	}
	for _, typ := range []string{sdn.VPNConnectionConditionEstablished, sdn.VPNConnectionConditionRoutesProgrammed} {
		condition := meta.FindStatusCondition(connection.Status.Conditions, typ)
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.ObservedGeneration != 3 {
			t.Fatalf("configuration failure left stale success for %s: %+v", typ, condition)
		}
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(other), other); err != nil {
		t.Fatal(err)
	}
	if other.Status.Phase != sdn.VPNConnectionPhaseEstablished {
		t.Fatal("unrelated gateway connection invalidated")
	}
}

func TestIPsecFailureInvalidatesStatusEvenIfGrantDeletionFails(t *testing.T) {
	gw, connection, _ := wgSecurityFixture()
	gw.Spec.WireGuard, gw.Spec.IPsec = nil, &sdn.VPNGatewayIPsec{}
	connection.Spec.WireGuard, connection.Spec.IPsec = nil, &sdn.VPNConnectionIPsec{}
	connection.Status.ClientConfig = nil
	connection.Status.Conditions = nil
	setConnCondition(&connection.Status, sdn.VPNConnectionConditionEstablished, true, "TunnelEstablished", "tunnel established")
	scheme := gatewayScheme(t)
	binding := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "binding-current"}}
	if err := controllerutil.SetControllerReference(gw, binding, scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNGateway{}, &sdn.VPNConnection{}).WithObjects(gw, connection, binding).Build()
	failure := errors.New("delete unavailable")
	r := &VPNGatewayReconciler{Client: wgFenceDeleteFailure{Client: c, failure: failure}, Scheme: scheme}
	if _, err := r.reportUnready(t.Context(), gw, "ConfigurationFailed", "credential unavailable"); !errors.Is(err, failure) {
		t.Fatal("grant deletion failure must remain visible", err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionEstablished) {
		t.Fatal("grant deletion error skipped failed connection status publication")
	}
}

func TestIPsecRevocationIncludesDeletingCertificateAndEAPPeers(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{}}}
	now := metav1.Now()
	certificate := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "certificate", Namespace: gw.Namespace, Generation: 4}, Spec: sdn.VPNConnectionSpec{
		GatewayRef: sdn.LocalVPNGatewayRef{Name: gw.Name}, IPsec: &sdn.VPNConnectionIPsec{Auth: sdn.VPNConnectionIPsecAuth{Certificate: &sdn.VPNIPsecCertificateAuth{RemoteIdentity: "peer.example.invalid"}}},
	}, Status: sdn.VPNConnectionStatus{Phase: sdn.VPNConnectionPhaseEstablished, AssignedAddresses: []string{"198.18.0.1"}}}
	eap := certificate.DeepCopy()
	eap.Name, eap.DeletionTimestamp, eap.Finalizers = "eap", &now, []string{"example.invalid/cleanup"}
	eap.Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: "account", SecretRef: "password"}}
	changed := certificate.DeepCopy()
	changed.Name, changed.Spec.IPsec = "changed-backend", nil
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(certificate, eap, changed).Build()
	r := &VPNGatewayReconciler{Client: c}
	if err := r.invalidateGatewayConnectionStatuses(t.Context(), gw, "ConfigurationFailed", "credential unavailable"); err != nil {
		t.Fatal(err)
	}
	for _, connection := range []*sdn.VPNConnection{certificate, eap, changed} {
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
			t.Fatal(err)
		}
		if connection.Status.Phase != sdn.VPNConnectionPhasePending || len(connection.Status.AssignedAddresses) != 1 || !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionEstablished) {
			t.Fatal("certificate/EAP revocation left stale success or erased assignment history")
		}
	}
}

func TestIPsecRevocationRejectsPartialOrUnavailableLiveScan(t *testing.T) {
	for _, reader := range []wgStatusScanReader{{partial: true}, {err: errors.New("reader unavailable")}} {
		gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a"}}
		connection := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: gw.Namespace}, Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: gw.Name}, IPsec: &sdn.VPNConnectionIPsec{}}, Status: sdn.VPNConnectionStatus{Phase: sdn.VPNConnectionPhaseEstablished}}
		c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(connection).Build()
		reader.Reader = c
		r := &VPNGatewayReconciler{Client: c, Reader: reader}
		if err := r.invalidateGatewayConnectionStatuses(t.Context(), gw, "ConfigurationFailed", "failed"); err == nil {
			t.Fatal("incomplete revocation scan reported success")
		}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
			t.Fatal(err)
		}
		if connection.Status.Phase != sdn.VPNConnectionPhaseEstablished {
			t.Fatal("incomplete enumeration wrote partial statuses")
		}
	}
}

func TestIPsecConnectionPendingStatusRecordsCurrentGeneration(t *testing.T) {
	connection := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "tenant-a", Generation: 3}, Spec: sdn.VPNConnectionSpec{IPsec: &sdn.VPNConnectionIPsec{}}, Status: sdn.VPNConnectionStatus{Phase: sdn.VPNConnectionPhasePending}}
	setConnCondition(&connection.Status, sdn.VPNConnectionConditionRoutesProgrammed, false, "RoutesProgrammed", routesMessage(false, 0))
	setConnCondition(&connection.Status, sdn.VPNConnectionConditionEstablished, false, "RoutesPending", "waiting for remote-CIDR routes to the appliance")
	for i := range connection.Status.Conditions {
		connection.Status.Conditions[i].ObservedGeneration = 2
	}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(connection).Build()
	r := &VPNGatewayReconciler{Client: c}
	if err := r.reflectConnectionStatus(t.Context(), []sdn.VPNConnection{*connection}, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	for _, condition := range connection.Status.Conditions {
		if condition.ObservedGeneration != connection.Generation {
			t.Fatalf("current pending result retained generation %d", condition.ObservedGeneration)
		}
	}
}

func TestIPsecGatewayStatusRecordsCurrentGenerationWhenReadinessUnchanged(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "ike-gateway", Namespace: "tenant-a", Generation: 3}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{}}, Status: sdn.VPNGatewayStatus{Phase: sdn.VPNGatewayPhaseReady}}
	setVPNGWCondition(&gw.Status, sdn.VPNGatewayConditionApplianceReady, true, "ApplianceReady", "appliance ready")
	gw.Status.Conditions[0].ObservedGeneration = 2
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPNGateway{}).WithObjects(gw).Build()
	r := &VPNGatewayReconciler{Client: c}
	if err := r.writeStatus(t.Context(), gw, gw.Status); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	if gw.Status.Conditions[0].ObservedGeneration != gw.Generation {
		t.Fatalf("current ready result retained generation %d", gw.Status.Conditions[0].ObservedGeneration)
	}
}
