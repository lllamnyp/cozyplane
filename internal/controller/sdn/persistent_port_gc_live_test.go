package sdn

import (
	"context"
	"errors"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type delayedLauncherClient struct {
	client.Client
	lists int
}

func (c *delayedLauncherClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if pods, ok := list.(*corev1.PodList); ok {
		c.lists++
		if c.lists == 1 {
			pods.Items = nil // first informer view has not observed the launcher yet
			return nil
		}
	}
	return c.Client.List(ctx, list, opts...)
}

func TestPersistentPortGCConfirmsMissingLaunchersBeforeDeletingIdentity(t *testing.T) {
	port := persistentPort("vm", "192.168.0.2", "node-a")
	pod := launcher("launcher", "node-a", "vm", "10.244.0.5", "pod-uid")
	c := &delayedLauncherClient{Client: fake.NewClientBuilder().WithScheme(ppScheme(t)).WithObjects(port, pod, node("node-a", "192.0.2.1")).Build()}
	r := &PersistentPortReconciler{Client: c}
	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)})
	if err != nil {
		t.Fatal(err)
	}
	got := &sdn.Port{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil || !got.DeletionTimestamp.IsZero() || got.Spec.IP != port.Spec.IP || got.Spec.MAC != port.Spec.MAC {
		t.Fatal("cache lag deleted or changed live VM identity", got, err)
	}
	if c.lists != 2 || result.RequeueAfter <= 0 {
		t.Fatalf("absence not confirmed or retried: lists=%d result=%v", c.lists, result)
	}
}

type failedLauncherReader struct {
	client.Reader
}

func (r failedLauncherReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("live read unavailable")
}

func TestPersistentPortGCLiveOwnershipAndFailure(t *testing.T) {
	for _, scenario := range []string{"current", "completed-current", "foreign-owner", "replacement-vmi", "foreign-namespace", "gone", "error"} {
		t.Run(scenario, func(t *testing.T) {
			port := persistentPort("vm", "192.168.0.2", "node-a")
			port.UID, port.Finalizers = "port-uid", []string{sdn.FinalizerSever}
			pod := launcher("launcher", "node-a", "vm", "10.244.0.5", "pod-uid")
			switch scenario {
			case "completed-current":
				pod.Status.Phase = corev1.PodSucceeded // persistent lifecycle includes all phases
			case "foreign-owner":
				pod.OwnerReferences = nil
			case "replacement-vmi":
				pod.OwnerReferences[0].UID = "replacement-vmi"
			case "foreign-namespace":
				pod.Namespace = "other"
			}
			scheme := ppScheme(t)
			cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(port).Build()
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if scenario != "gone" {
				builder.WithObjects(pod)
			}
			var live client.Reader = builder.Build()
			if scenario == "error" {
				live = failedLauncherReader{Reader: live}
			}
			r := &PersistentPortReconciler{Client: cached, Reader: live}
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)})
			if (err != nil) != (scenario == "error") {
				t.Fatal("unexpected GC error", err)
			}
			keep := scenario == "current" || scenario == "completed-current" || scenario == "error"
			got := &sdn.Port{}
			if err := cached.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
			if got.DeletionTimestamp.IsZero() != keep || got.Spec.IP != port.Spec.IP || got.Spec.MAC != port.Spec.MAC || len(got.Finalizers) != 1 {
				t.Fatal("GC lost identity or sever barrier", got)
			}
			if keep && scenario != "error" && result.RequeueAfter <= 0 {
				t.Fatal("delayed cache was not retried")
			}
			// Simulate the cache catching up; a live launcher now takes the normal
			// cutover path, without a new address allocation.
			if scenario == "current" {
				pod.Status.Phase = corev1.PodPending
				pod.ResourceVersion, pod.CreationTimestamp = "", metav1.Time{}
				if err := cached.Create(t.Context(), pod); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)}); err != nil {
					t.Fatal(err)
				}
				if err := cached.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil || !got.DeletionTimestamp.IsZero() || got.Spec.IP != port.Spec.IP || got.Spec.MAC != port.Spec.MAC {
					t.Fatal("cache recovery changed pinned identity", got, err)
				}
			}
		})
	}
}
