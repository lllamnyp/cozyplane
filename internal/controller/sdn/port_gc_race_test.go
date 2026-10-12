package sdn

import (
	"context"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type reboundPortDeleteClient struct {
	client.Client
	replace   bool
	rebound   bool
	namespace string
}

func (c *reboundPortDeleteClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if p, ok := obj.(*sdn.Port); ok && !c.rebound {
		c.rebound = true
		current := &sdn.Port{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(p), current); err != nil {
			return err
		}
		current.Labels[sdn.LabelPodUID] = "replacement-pod"
		if c.namespace != "" {
			current.Labels[sdn.LabelPodNamespace] = c.namespace
			current.Spec.PodNamespace = c.namespace
		}
		if c.replace {
			if err := c.Client.Delete(ctx, p); err != nil {
				return err
			}
			current.UID, current.ResourceVersion = "replacement-port", ""
			if err := c.Client.Create(ctx, current); err != nil {
				return err
			}
		} else if err := c.Client.Update(ctx, current); err != nil {
			return err
		}
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestBindingRevocationDoesNotDeleteReplacementConsumer(t *testing.T) {
	scheme := gatewayScheme(t)
	binding := vpcBinding("consumer", "grant", "owner", "net", true)
	port := portFor("v100.10-0-0-2", "owner", "net", "consumer")
	port.UID = "predecessor-port"
	c := &reboundPortDeleteClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, port).Build(), replace: true, namespace: "other-consumer"}
	if err := c.Client.Delete(t.Context(), binding); err != nil {
		t.Fatal(err)
	}
	r := &VPCBindingReconciler{Client: c, Scheme: scheme}
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(binding)})
	if err != nil && !apierrors.IsConflict(err) {
		t.Fatal(err)
	}
	current := &sdn.Port{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(port), current); err != nil || current.Spec.PodNamespace != "other-consumer" || !current.DeletionTimestamp.IsZero() {
		t.Fatal("stale revocation deleted a replacement consumer", current, err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(binding), &sdn.VPCBinding{}); err != nil {
		t.Fatal("revocation dropped retry barrier after incomplete reaping", err)
	}
}

func TestPortGCDoesNotDeleteReboundOrReplacementClaim(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "same UID rebound", true: "replacement UID"}[replace], func(t *testing.T) {
			port := claimedPort("v100.10-10-0-1", "tenant", "gone", "predecessor-pod", false)
			port.UID, port.Finalizers = "predecessor-port", nil
			c := &reboundPortDeleteClient{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(port).Build(), replace: replace}
			r := &PortGCReconciler{Client: c}
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)})
			if err != nil && !apierrors.IsConflict(err) {
				t.Fatal(err)
			}
			current := &sdn.Port{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(port), current); err != nil || current.Labels[sdn.LabelPodUID] != "replacement-pod" || !current.DeletionTimestamp.IsZero() {
				t.Fatal("stale GC removed the new claimant", current, err)
			}
		})
	}
}

func TestPortGCConfirmsMissingNodeBeforeReleasingSever(t *testing.T) {
	scheme := gatewayScheme(t)
	port := severPort("v100.10-10-0-2", "live-node")
	port.UID = "port-uid"
	cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(port).Build()
	live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: port.Spec.Node}}).Build()
	if err := cached.Delete(t.Context(), port); err != nil {
		t.Fatal(err)
	}
	r := &PortGCReconciler{Client: cached, Reader: live}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)}); err != nil {
		t.Fatal(err)
	}
	current := &sdn.Port{}
	if err := cached.Get(t.Context(), client.ObjectKeyFromObject(port), current); err != nil || len(current.Finalizers) != 1 {
		t.Fatal("stale Node cache released a live agent's sever barrier", current, err)
	}
}
