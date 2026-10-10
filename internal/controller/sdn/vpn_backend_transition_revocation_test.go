package sdn

import (
	"context"
	"errors"
	"reflect"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestVPNBackendTransitionFailureRevokesPreviousSuccess(t *testing.T) {
	for _, teardownFails := range []bool{false, true} {
		teardownName := "drained"
		if teardownFails {
			teardownName = "delete-failed"
		}
		for _, historicalClientStatus := range []string{"none", "config", "condition", "both"} {
			t.Run(historicalClientStatus+"/"+teardownName, func(t *testing.T) {
				gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant-a", UID: "gateway-current"}, Spec: sdn.VPNGatewaySpec{IPsec: &sdn.VPNGatewayIPsec{}}}
				connection := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: gw.Namespace, Generation: 3}, Spec: sdn.VPNConnectionSpec{
					GatewayRef: sdn.LocalVPNGatewayRef{Name: gw.Name}, IPsec: &sdn.VPNConnectionIPsec{},
				}, Status: sdn.VPNConnectionStatus{Phase: sdn.VPNConnectionPhaseEstablished, AssignedAddresses: []string{"198.18.0.1"}, Conditions: []metav1.Condition{
					{Type: sdn.VPNConnectionConditionEstablished, Status: metav1.ConditionTrue, Reason: "TunnelEstablished", ObservedGeneration: 2},
					{Type: sdn.VPNConnectionConditionRoutesProgrammed, Status: metav1.ConditionTrue, Reason: "RoutesProgrammed", ObservedGeneration: 2},
				}}}
				// Both specs have migrated; only the retained status records the old
				// successful tunnel. The new WireGuard gateway is site-to-site.
				gw.Spec.IPsec, gw.Spec.WireGuard = nil, &sdn.VPNGatewayWireGuard{}
				connection.Spec.IPsec, connection.Spec.WireGuard = nil, &sdn.VPNConnectionWireGuard{PeerPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
				if historicalClientStatus == "config" || historicalClientStatus == "both" {
					connection.Status.ClientConfig = &sdn.VPNWireGuardClientConfig{Endpoint: "192.0.2.1:51820"}
				}
				if historicalClientStatus == "condition" || historicalClientStatus == "both" {
					connection.Status.Conditions = append(connection.Status.Conditions, metav1.Condition{Type: sdn.VPNConnectionConditionClientConfigured, Status: metav1.ConditionTrue, Reason: "Configured", ObservedGeneration: 2})
				}
				other := connection.DeepCopy()
				other.Name, other.Spec.GatewayRef.Name = "unrelated", "other-gateway"
				otherStatus := other.Status.DeepCopy()
				scheme := gatewayScheme(t)
				binding := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "binding-current"}, Spec: sdn.VPCBindingSpec{AllowForwarding: true, ForwardingCIDRs: []string{"198.18.0.1/32"}}}
				if err := controllerutil.SetControllerReference(gw, binding, scheme); err != nil {
					t.Fatal(err)
				}
				c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNGateway{}, &sdn.VPNConnection{}).WithObjects(gw, connection, other, binding).Build()
				reader := &vpnRevocationCountingReader{Reader: c}
				r := &VPNGatewayReconciler{Client: c, Reader: reader, Scheme: scheme}
				failure := errors.New("grant deletion unavailable")
				if teardownFails {
					r.Client = wgFenceDeleteFailure{Client: c, failure: failure}
				}
				_, err := r.reportUnready(t.Context(), gw, "ConfigurationFailed", "appliance configuration failed")
				if teardownFails && !errors.Is(err, failure) || !teardownFails && err != nil {
					t.Fatal("teardown failure lost or successful revocation failed", err)
				}
				if reader.connectionLists != 1 {
					t.Fatalf("gateway failure enumerated connections %d times", reader.connectionLists)
				}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
					t.Fatal(err)
				}
				if connection.Status.Phase != sdn.VPNConnectionPhasePending || !reflect.DeepEqual(connection.Status.AssignedAddresses, []string{"198.18.0.1"}) || connection.Status.ClientConfig != nil {
					t.Fatal("revocation retained success/configuration or discarded assignment history")
				}
				for _, typ := range []string{sdn.VPNConnectionConditionEstablished, sdn.VPNConnectionConditionRoutesProgrammed} {
					condition := meta.FindStatusCondition(connection.Status.Conditions, typ)
					if condition == nil || condition.Status != metav1.ConditionFalse || condition.ObservedGeneration != connection.Generation {
						t.Fatalf("stale success after both backend edits: %+v", condition)
					}
				}
				configured := meta.FindStatusCondition(connection.Status.Conditions, sdn.VPNConnectionConditionClientConfigured)
				if historicalClientStatus == "none" {
					if configured != nil {
						t.Fatal("site-to-site peer received an invented ClientConfigured condition")
					}
				} else if configured == nil || configured.Status != metav1.ConditionFalse || configured.ObservedGeneration != connection.Generation {
					t.Fatal("historical client status was not revoked at the current generation")
				}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(other), other); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(&other.Status, otherStatus) {
					t.Fatal("unrelated gateway connection status changed")
				}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(binding), binding); teardownFails && err != nil || !teardownFails && !apierrors.IsNotFound(err) {
					t.Fatal("unexpected grant deletion result", err)
				}
			})
		}
	}
}

type vpnRevocationCountingReader struct {
	client.Reader
	connectionLists int
}

func (r *vpnRevocationCountingReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*sdn.VPNConnectionList); ok {
		r.connectionLists++
	}
	return r.Reader.List(ctx, list, opts...)
}
