package sdn

import (
	"context"
	"errors"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type staleEndpointSliceReader struct {
	client.Client
	old         *discoveryv1.EndpointSlice
	gets        int
	replacement *discoveryv1.EndpointSlice
}

func (c *staleEndpointSliceReader) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := c.Client.Delete(ctx, obj, opts...); err != nil {
		return err
	}
	if c.replacement != nil {
		return c.Client.Create(ctx, c.replacement.DeepCopy())
	}
	return nil
}

func (c *staleEndpointSliceReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if slice, ok := obj.(*discoveryv1.EndpointSlice); ok && key == client.ObjectKeyFromObject(c.old) {
		c.gets++
		if c.gets > 3 {
			return errors.New("repeated cache read after deletion")
		}
		c.old.DeepCopyInto(slice)
		return nil
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestEndpointSliceReplacementCollisionIsPreserved(t *testing.T) {
	for _, nat := range []bool{false, true} {
		t.Run(map[bool]string{false: "floating", true: "nat"}[nat], func(t *testing.T) {
			scheme := gatewayScheme(t)
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "public-service", UID: "service-current"}}
			old := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: svc.Namespace, Name: svc.Name, UID: "slice-old"}, AddressType: discoveryv1.AddressTypeIPv6}
			if err := controllerutil.SetControllerReference(svc, old, scheme); err != nil {
				t.Fatal(err)
			}
			foreign := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: svc.Namespace, Name: svc.Name, UID: "foreign-replacement"}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.0.2.99"}}}}
			actual := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, old).Build()
			c := &staleEndpointSliceReader{Client: actual, old: old.DeepCopy(), replacement: foreign}
			var err error
			if nat {
				r := &VPCGatewayReconciler{Client: c, Scheme: scheme}
				err = r.ensureNATEndpointSlice(t.Context(), svc, &sdnv1alpha1.VPCGateway{}, corev1.IPv4Protocol, "192.0.2.10")
			} else {
				r := &FloatingIPReconciler{Client: c, Scheme: scheme}
				err = r.ensureEndpointSlice(t.Context(), svc, floatingIP(svc.Namespace, "public", "net", "10.0.0.2"), "node-a")
			}
			if err == nil || c.gets != 1 {
				t.Fatalf("collision accepted or retried inline: err=%v gets=%d", err, c.gets)
			}
			got := &discoveryv1.EndpointSlice{}
			if err := actual.Get(t.Context(), client.ObjectKeyFromObject(old), got); err != nil {
				t.Fatal(err)
			}
			if got.UID != foreign.UID || len(got.OwnerReferences) != 0 || got.Endpoints[0].Addresses[0] != "192.0.2.99" {
				t.Fatalf("foreign replacement modified: %+v", got)
			}
		})
	}
}

func TestEndpointSliceFamilyChangeDoesNotRecurseOnStaleCache(t *testing.T) {
	for _, nat := range []bool{false, true} {
		t.Run(map[bool]string{false: "floating", true: "nat"}[nat], func(t *testing.T) {
			scheme := gatewayScheme(t)
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "public-service", UID: "service-current"}}
			old := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: svc.Namespace, Name: svc.Name, UID: "slice-old"}, AddressType: discoveryv1.AddressTypeIPv6, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"2001:db8::10"}}}}
			if err := controllerutil.SetControllerReference(svc, old, scheme); err != nil {
				t.Fatal(err)
			}
			actual := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, old).Build()
			c := &staleEndpointSliceReader{Client: actual, old: old.DeepCopy()}
			var err error
			if nat {
				r := &VPCGatewayReconciler{Client: c, Scheme: scheme}
				err = r.ensureNATEndpointSlice(t.Context(), svc, &sdnv1alpha1.VPCGateway{}, corev1.IPv4Protocol, "192.0.2.10")
			} else {
				r := &FloatingIPReconciler{Client: c, Scheme: scheme}
				err = r.ensureEndpointSlice(t.Context(), svc, floatingIP(svc.Namespace, "public", "net", "10.0.0.2"), "node-a")
			}
			if err != nil {
				t.Fatalf("family replacement did not finish: %v", err)
			}
			if c.gets != 1 {
				t.Fatalf("family replacement re-read stale cache %d times", c.gets)
			}
			got := &discoveryv1.EndpointSlice{}
			if err := actual.Get(t.Context(), client.ObjectKeyFromObject(old), got); err != nil {
				t.Fatal(err)
			}
			if got.AddressType != discoveryv1.AddressTypeIPv4 || !metav1.IsControlledBy(got, svc) {
				t.Fatalf("wrong replacement: %+v", got)
			}
		})
	}
}
