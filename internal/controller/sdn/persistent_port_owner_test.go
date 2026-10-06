package sdn

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPersistentPortPreservedWhileVMHalted(t *testing.T) {
	port := persistentPort("vm", "192.168.0.2", "node-a")
	vm := &unstructured.Unstructured{}
	vm.SetGroupVersionKind(vmGVK)
	vm.SetNamespace(port.Spec.PodNamespace)
	vm.SetName("vm")
	if err := unstructured.SetNestedField(vm.Object, "Halted", "spec", "runStrategy"); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).WithObjects(port, vm).Build()
	r := &PersistentPortReconciler{Client: c}
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("requeue = %v", result.RequeueAfter)
	}
	got := &sdnv1alpha1.Port{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: port.Name}, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(port.Spec, got.Spec) {
		t.Fatalf("halted VM port changed: got %+v want %+v", got.Spec, port.Spec)
	}
}

func TestPersistentPortCollectedAfterVMDeletion(t *testing.T) {
	port := persistentPort("vm", "192.168.0.2", "node-a")
	vm := &unstructured.Unstructured{}
	vm.SetGroupVersionKind(vmGVK)
	vm.SetNamespace(port.Spec.PodNamespace)
	vm.SetName("vm")
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).WithObjects(port, vm).Build()
	if err := c.Delete(context.Background(), vm); err != nil {
		t.Fatal(err)
	}
	r := &PersistentPortReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: port.Name}, &sdnv1alpha1.Port{}); !apierrors.IsNotFound(err) {
		t.Fatalf("deleted VM port should be collected: %v", err)
	}
}

type ownerLookupErrorClient struct {
	client.Client
	err error
}

func (c ownerLookupErrorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if obj.GetObjectKind().GroupVersionKind() == vmGVK {
		return c.err
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestPersistentPortOwnerLookupErrorPreservesAddress(t *testing.T) {
	port := persistentPort("vm", "192.168.0.2", "node-a")
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).WithObjects(port).Build()
	want := errors.New("owner lookup unavailable")
	r := &PersistentPortReconciler{Client: ownerLookupErrorClient{Client: c, err: want}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}})
	if !errors.Is(err, want) {
		t.Fatalf("reconcile error = %v, want owner lookup failure", err)
	}
	got := &sdnv1alpha1.Port{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: port.Name}, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(port.Spec, got.Spec) {
		t.Fatalf("port changed after lookup error: %+v", got.Spec)
	}
}
