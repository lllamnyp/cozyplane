package sdn

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// A stop/start keeps the VirtualMachine but replaces its VMI. The retained Port
// must follow the replacement, or the CNI refuses the new launcher forever.
func TestPersistentPortFollowsRestartedVMI(t *testing.T) {
	for _, scenario := range []string{"restarted", "bare-vmi", "old-vmi-present"} {
		t.Run(scenario, func(t *testing.T) {
			port := persistentPort("vm", "192.168.0.2", "node-a")
			vm := &unstructured.Unstructured{}
			vm.SetGroupVersionKind(vmGVK)
			vm.SetNamespace(port.Spec.PodNamespace)
			vm.SetName("vm")
			vm.SetUID("vm-uid")
			replacement := vmi("vm", "node-b")
			replacement.SetUID("vmi-new")
			switch scenario {
			case "restarted":
				replacement.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(vm, vmGVK)})
			case "old-vmi-present":
				replacement.SetUID("vmi-vm")
				replacement.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(vm, vmGVK)})
			}
			pod := launcher("launcher-new", "node-b", "vm", "10.244.0.9", "pod-new")
			pod.OwnerReferences[0].UID = replacement.GetUID()
			c := fake.NewClientBuilder().WithScheme(ppScheme(t)).
				WithObjects(port, vm, replacement, pod, node("node-b", "192.0.2.2")).Build()
			r := &PersistentPortReconciler{Client: c}
			got := reconcilePP(t, r, port.Name)
			want := map[string]string{"restarted": "vmi-new", "bare-vmi": "vmi-vm", "old-vmi-present": "vmi-vm"}[scenario]
			if got.Labels[vmidentity.InstanceUIDLabel] != want || got.Spec.IP != port.Spec.IP || got.Spec.MAC != port.Spec.MAC {
				t.Fatalf("vmi-uid = %q, want %q (port %+v)", got.Labels[vmidentity.InstanceUIDLabel], want, got)
			}
			if scenario != "restarted" {
				return
			}
			// The next pass binds the replacement's launcher through the cutover.
			got = reconcilePP(t, r, port.Name)
			if got.Labels[sdnv1alpha1.LabelPodUID] != "pod-new" || got.Spec.Node != "node-b" {
				t.Fatalf("restarted launcher not bound: %+v", got)
			}
		})
	}
}
