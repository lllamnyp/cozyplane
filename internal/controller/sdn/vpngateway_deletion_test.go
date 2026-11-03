package sdn

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestTerminatingVPNDoesNotCreateOrRetainAuthorization(t *testing.T) {
	for _, deleting := range []string{"gateway", "VPC"} {
		t.Run(deleting, func(t *testing.T) {
			for _, existing := range []bool{false, true} {
				t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
					scheme := svcScheme(t)
					gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "door", Namespace: "tenant-a", UID: "gateway-current", Finalizers: []string{"example.invalid/cleanup"}}}
					gw.Spec.VPCRef.Name = "net"
					vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
					vpc.Finalizers = []string{"example.invalid/cleanup"}
					c := vpnIndexClient(t, gw, vpc)
					r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
					req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
					deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "door-vpn", Namespace: gw.Namespace}}
					binding := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: "door-vpn", Namespace: gw.Namespace}}
					if existing {
						if _, err := r.Reconcile(t.Context(), req); err != nil {
							t.Fatal(err)
						}
						for _, obj := range []client.Object{deployment, binding} {
							if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
								t.Fatalf("live VPN missing %T: %v", obj, err)
							}
						}
					}
					var obj client.Object = gw
					if deleting == "VPC" {
						obj = vpc
					}
					if err := c.Delete(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
					if deleting == "VPC" {
						requests := r.mapVPCToVPNGateways(t.Context(), vpc)
						if len(requests) != 1 || requests[0] != req {
							t.Fatalf("VPC deletion did not enqueue VPN: %v", requests)
						}
					}
					for range 2 {
						if _, err := r.Reconcile(t.Context(), req); err != nil {
							t.Fatal(err)
						}
						for _, active := range []client.Object{deployment, binding} {
							if err := c.Get(t.Context(), client.ObjectKeyFromObject(active), active); !apierrors.IsNotFound(err) {
								t.Errorf("terminating %s retains/recreates %T: %v", deleting, active, err)
							}
						}
						if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
							t.Fatal(err)
						}
						if gw.Status.Phase == sdnv1alpha1.VPNGatewayPhaseReady || gw.Status.Address != "" || len(gw.Status.Addresses) != 0 || gw.Status.AppliancePort != "" || len(gw.Status.AppliancePorts) != 0 || len(gw.Status.Routes) != 0 {
							t.Fatalf("terminating VPN retains active status: %+v", gw.Status)
						}
					}
				})
			}
		})
	}
}
