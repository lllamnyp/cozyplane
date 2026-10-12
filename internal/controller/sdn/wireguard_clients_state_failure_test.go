package sdn

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestWireGuardCorruptStateFencesAuthorizationBeforeReturning(t *testing.T) {
	for _, operation := range []string{"report-unready", "finalize"} {
		t.Run(operation, func(t *testing.T) {
			gw, connection, _ := wgSecurityFixture()
			gw.Finalizers, connection.Finalizers = []string{wgClientFinalizer}, []string{wgClientFinalizer}
			if operation == "finalize" {
				now := metav1.Now()
				gw.DeletionTimestamp = &now
			}
			scheme := gatewayScheme(t)
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "deployment-current"}}
			primary := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "primary-current"}, Spec: sdn.VPCBindingSpec{AllowForwarding: true, ForwardingCIDRs: []string{"198.18.0.1/32"}}}
			leg := primary.DeepCopy()
			leg.Name, leg.UID, leg.Labels = gw.Name+"-vpn-other", "leg-current", map[string]string{vpnGatewayLabel: gw.Name}
			for _, obj := range []client.Object{deployment, primary, leg} {
				if err := controllerutil.SetControllerReference(gw, obj, scheme); err != nil {
					t.Fatal(err)
				}
			}
			raw := []byte("{secret-canary-" + strings.Repeat("x", 1<<18))
			state := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: wgClientStateName, Namespace: gw.Namespace, Labels: map[string]string{wgClientStateLabel: "true"}}, Data: map[string][]byte{"allocations.json": raw}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNGateway{}, &sdn.VPNConnection{}).WithObjects(gw, connection, deployment, primary, leg, state).Build()
			r := &VPNGatewayReconciler{Client: c, Scheme: scheme}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
				t.Fatal(err)
			}
			var failure error
			if operation == "report-unready" {
				_, failure = r.reportUnready(t.Context(), gw, "ConfigurationFailed", "failed")
			} else {
				done, err := r.finalizeWGClientGateway(t.Context(), gw)
				failure = err
				if done {
					t.Fatal("corrupt state permitted gateway finalization")
				}
			}
			if failure == nil || len(failure.Error()) > 512 || strings.Contains(failure.Error(), "secret-canary") {
				t.Fatal("unsafe failure diagnostic", failure)
			}
			for _, binding := range []*sdn.VPCBinding{primary, leg} {
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(binding), &sdn.VPCBinding{}); !apierrors.IsNotFound(err) {
					t.Fatal("forwarding authorization survived corrupt state", err)
				}
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(deployment), &appsv1.Deployment{}); err != nil {
				t.Fatal("workload witness destroyed before it could be persisted", err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
				t.Fatal(err)
			}
			if connection.Status.ClientConfig != nil || !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionClientConfigured) {
				t.Fatal("client config still claims usable authorization")
			}
			if len(connection.Status.AssignedAddresses) != 1 || !slices.Contains(connection.Finalizers, wgClientFinalizer) {
				t.Fatal("allocation or revocation barrier was released")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(state), state); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(state.Data["allocations.json"], raw) {
				t.Fatal("corrupt reservation state was overwritten during fencing")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(gw.Finalizers, wgClientFinalizer) {
				t.Fatal("gateway revocation barrier was released")
			}
		})
	}
}

type wgFenceDeleteFailure struct {
	client.Client
	failure error
}

func (c wgFenceDeleteFailure) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if _, ok := obj.(*sdn.VPCBinding); ok {
		return c.failure
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestWireGuardFencingContinuesAfterGrantDeletionFailure(t *testing.T) {
	gw, connection, _ := wgSecurityFixture()
	scheme := gatewayScheme(t)
	binding := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "binding-current", Labels: map[string]string{vpnGatewayLabel: gw.Name}}}
	if err := controllerutil.SetControllerReference(gw, binding, scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNConnection{}).WithObjects(gw, connection, binding).Build()
	stateFailure := errors.New("state-secret-canary-" + strings.Repeat("x", 1<<18))
	deleteFailure := errors.New("delete-secret-canary-" + strings.Repeat("x", 1<<18))
	r := &VPNGatewayReconciler{Client: wgFenceDeleteFailure{Client: c, failure: deleteFailure}, Scheme: scheme}
	err := r.fenceWGClientStateFailure(t.Context(), gw, stateFailure)
	if !errors.Is(err, stateFailure) || !errors.Is(err, deleteFailure) || len(err.Error()) > 512 || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("joined errors lost their identities or leaked contents")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
		t.Fatal(err)
	}
	if connection.Status.ClientConfig != nil || !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionClientConfigured) {
		t.Fatal("grant delete failure skipped client status invalidation")
	}
}
