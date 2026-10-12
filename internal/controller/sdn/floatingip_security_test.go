package sdn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestFloatingReferenceIndexBudgetAndRecovery(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{floatingTargetIndex: func(obj interface{}) ([]string, error) { return floatingTargetIndexKeys(obj.(client.Object)), nil }})
	obj := floatingIP("tenant-a", "binding", strings.Repeat("x", 128<<10), "192.0.2.5")
	if err := index.Add(obj); err != nil {
		t.Fatal(err)
	}
	keys := index.ListIndexFuncValues(floatingTargetIndex)
	if len(keys) != 0 {
		t.Fatalf("unusable reference retained: %d keys, first %d bytes", len(keys), len(keys[0]))
	}
	current := obj.DeepCopy()
	current.Spec.VPCRef.Name = "net"
	if err := index.Update(current); err != nil {
		t.Fatal(err)
	}
	if len(index.ListIndexFuncValues(floatingTargetIndex)) != 1 {
		t.Fatal("valid recovery missing")
	}
	if err := index.Delete(current); err != nil {
		t.Fatal(err)
	}
	if len(index.ListIndexFuncValues(floatingTargetIndex)) != 0 {
		t.Fatal("deleted reference retained")
	}
}

type floatingLookupGuard struct {
	client.Client
	vpcReads int
}

func (c *floatingLookupGuard) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*sdnv1alpha1.VPC); ok {
		c.vpcReads++
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestFloatingLegacyWithdrawsOnlyOwnedServiceAndRecovers(t *testing.T) {
	obj := floatingIP("tenant-a", "binding", "net", "192.0.2.5")
	obj.UID = "binding-uid"
	c := &floatingLookupGuard{Client: fipClient(t, obj)}
	r := &FloatingIPReconciler{Client: c, Scheme: gatewayScheme(t)}
	key := client.ObjectKeyFromObject(obj)
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	owned := ownedFloatingService(t, c, obj.Namespace, obj.Name)
	if owned == nil {
		t.Fatal("positive control did not allocate")
	}
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: obj.Namespace, UID: "foreign-uid", Labels: owned.Labels}}
	if err := c.Create(t.Context(), foreign); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), key, obj); err != nil {
		t.Fatal(err)
	}
	obj.Spec.VPCRef.Name = strings.Repeat("x", 128<<10)
	if err := c.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	c.vpcReads = 0
	reconcile()
	if c.vpcReads != 0 {
		t.Fatal("invalid reference looked up")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(owned), &corev1.Service{}); !apierrors.IsNotFound(err) {
		t.Fatal("owned service remains", err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(foreign), &corev1.Service{}); err != nil {
		t.Fatal("foreign service removed", err)
	}
	if err := c.Get(t.Context(), key, obj); err != nil {
		t.Fatal(err)
	}
	rv := obj.ResourceVersion
	for range 25 {
		reconcile()
	}
	if err := c.Get(t.Context(), key, obj); err != nil {
		t.Fatal(err)
	}
	if obj.ResourceVersion != rv {
		t.Fatal("unchanged invalid status churned")
	}
	obj.Spec.VPCRef.Name = "net"
	if err := c.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	reconcile()
	var services corev1.ServiceList
	if err := c.List(t.Context(), &services, client.InNamespace(obj.Namespace)); err != nil {
		t.Fatal(err)
	}
	ownedCount := 0
	for i := range services.Items {
		if metav1.IsControlledBy(&services.Items[i], obj) {
			ownedCount++
		}
	}
	if ownedCount != 1 {
		t.Fatal("valid recovery did not restore owned service", ownedCount)
	}
}

func TestFloatingLegacyDiagnosticBudget(t *testing.T) {
	obj := floatingIP("tenant-a", "binding", "net", strings.Repeat("x", 128<<10))
	c := fipClient(t, obj)
	got := reconcileFIP(t, c, obj.Namespace, obj.Name)
	body, err := json.Marshal(got.Status)
	if err != nil || len(body) > 4096 {
		t.Fatalf("status bytes=%d err=%v", len(body), err)
	}
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending || ownedFloatingService(t, c, obj.Namespace, obj.Name) != nil {
		t.Fatal("invalid target allocated a service")
	}
}
