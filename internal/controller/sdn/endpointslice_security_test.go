package sdn

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestForeignEndpointSliceIsNeitherUpdatedNorRecreated(t *testing.T) {
	for _, family := range []discoveryv1.AddressType{discoveryv1.AddressTypeIPv4, discoveryv1.AddressTypeIPv6} {
		for _, nat := range []bool{false, true} {
			scheme := gatewayScheme(t)
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "service", Namespace: "tenant", UID: "current-service"}}
			slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: svc.Namespace, UID: "foreign-slice"}, AddressType: family, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.0.2.99"}}}}
			original := slice.DeepCopy()
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, slice).Build()
			var err error
			if nat {
				r := &VPCGatewayReconciler{Client: c, Scheme: scheme}
				err = r.ensureNATEndpointSlice(t.Context(), svc, &sdnv1alpha1.VPCGateway{}, corev1.IPv4Protocol, "192.0.2.10")
			} else {
				r := &FloatingIPReconciler{Client: c, Scheme: scheme}
				err = r.ensureEndpointSlice(t.Context(), svc, floatingIP("tenant", "public", "vpc", "10.0.0.2"), "node")
			}
			if err == nil {
				t.Fatalf("foreign slice accepted: family=%s nat=%v", family, nat)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(slice), slice); err != nil {
				t.Fatalf("foreign slice deleted: %v", err)
			}
			if !reflect.DeepEqual(slice.Endpoints, original.Endpoints) || slice.AddressType != original.AddressType {
				t.Fatal("foreign slice changed")
			}
		}
	}
}
