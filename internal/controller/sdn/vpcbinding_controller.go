/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sdn

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// vpcBindingFinalizer holds the binding until its authorized Ports are reaped,
// so deleting a VPCBinding actually severs the pods it permitted.
const vpcBindingFinalizer = "sdn.cozystack.io/reap-ports"

// VPCBindingReconciler reaps the Ports a VPCBinding authorized when it is
// deleted. A Port is reaped only if no *other* live binding in the same
// (consumer) namespace still authorizes the same VPC. Deleting the Ports makes
// the agents tear down the corresponding datapath (cross-node remote routes and,
// on the pod's own node, the live local datapath — see datapath.SeverLocal).
type VPCBindingReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// emitNAD is set when the cluster serves Multus's NetworkAttachmentDefinition.
	// When true the reconciler mirrors each binding into a shim NAD so a KubeVirt
	// VM can name the VPC at all — spec.networks admits only `pod` and `multus`
	// (docs/kubevirt-multi-nic.md). Without Multus there is nothing to emit.
	emitNAD bool
}

// nadGVK is Multus's NetworkAttachmentDefinition, handled as unstructured to
// avoid a dependency on the Multus API module for one object with one string
// field — the same reason the persistent-Port controller reads KubeVirt's VMI
// that way.
var nadGVK = schema.GroupVersionKind{
	Group:   "k8s.cni.cncf.io",
	Version: "v1",
	Kind:    "NetworkAttachmentDefinition",
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcbindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;delete
// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=network-attachment-definitions,verbs=get;list;watch;create;update;patch

// Reconcile maintains the reap finalizer and reaps Ports on deletion.
func (r *VPCBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	binding := &sdnv1alpha1.VPCBinding{}
	if err := r.Get(ctx, req.NamespacedName, binding); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if binding.DeletionTimestamp.IsZero() {
		if controllerutil.AddFinalizer(binding, vpcBindingFinalizer) {
			if err := r.Update(ctx, binding); err != nil {
				return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
			}
		}
		if err := r.reconcileNAD(ctx, binding); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Being deleted.
	if controllerutil.ContainsFinalizer(binding, vpcBindingFinalizer) {
		reaped, err := r.reapPorts(ctx, binding)
		if err != nil {
			return ctrl.Result{}, err
		}
		if reaped > 0 {
			logger.Info("reaped ports for revoked binding", "binding", req.NamespacedName.String(),
				"vpc", binding.Spec.VPCRef.Namespace+"/"+binding.Spec.VPCRef.Name, "count", reaped)
		}
		controllerutil.RemoveFinalizer(binding, vpcBindingFinalizer)
		if err := r.Update(ctx, binding); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// reconcileNAD mirrors a live binding into a shim NetworkAttachmentDefinition, so
// a KubeVirt VM in this namespace can reference the VPC.
//
// Per BINDING, not per VPC, and that placement is the whole argument. Multus
// resolves networkName in the POD's namespace, and a VPCBinding is exactly the
// object saying "pods in this namespace may attach to that VPC", authored by
// whoever holds `export` on the VPC. So the NAD exists precisely where attachment
// is already authorized and introduces no new authorization surface. A VPC
// consumed from three namespaces gets three NADs, which is what each tenant needs
// to name it.
//
// It is NOT a grant. The config carries a VPC name and nothing else; the CNI still
// resolves the VPCBinding before attaching, so a hand-written NAD naming another
// tenant's VPC buys nothing.
//
// Owned by the binding, so revoking the binding removes the NAD by ordinary
// garbage collection — the finalizer above stays about Ports.
func (r *VPCBindingReconciler) reconcileNAD(ctx context.Context, binding *sdnv1alpha1.VPCBinding) error {
	if !r.emitNAD {
		return nil
	}
	ref := binding.Spec.VPCRef

	// Named after the VPC, not the binding: two bindings authorizing the same VPC
	// in one namespace describe one network, and a VM references the network.
	// Both bindings reconcile to the same content, so the second is a no-op.
	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(ref.Name)
	nad.SetNamespace(binding.Namespace)

	config := fmt.Sprintf(`{"cniVersion":"1.0.0","name":%q,"type":"cozyplane","vpc":"%s/%s"}`,
		ref.Name, ref.Namespace, ref.Name)

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, nad, func() error {
		if err := unstructured.SetNestedField(nad.Object, config, "spec", "config"); err != nil {
			return err
		}
		labels := nad.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels[sdnv1alpha1.LabelVPCNamespace] = ref.Namespace
		labels[sdnv1alpha1.LabelVPC] = ref.Name
		nad.SetLabels(labels)
		// Only own it if nobody else does. An operator who wrote their own NAD
		// under this name keeps it — adopting it would make revoking any binding
		// delete an object cozyplane never created.
		if len(nad.GetOwnerReferences()) == 0 {
			return controllerutil.SetControllerReference(binding, nad, r.Scheme)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile network-attachment-definition %s/%s: %w", binding.Namespace, ref.Name, err)
	}
	return nil
}

// reapPorts deletes the Ports for pods in the binding's namespace attached to the
// referenced VPC, unless another live binding in that namespace still authorizes
// it. Returns the number of Ports deleted.
func (r *VPCBindingReconciler) reapPorts(ctx context.Context, binding *sdnv1alpha1.VPCBinding) (int, error) {
	ref := binding.Spec.VPCRef
	consumerNS := binding.Namespace

	// If another, still-live binding in this namespace authorizes the same VPC,
	// the pods stay; reaping waits until the last grant is gone.
	var bindings sdnv1alpha1.VPCBindingList
	if err := r.List(ctx, &bindings, client.InNamespace(consumerNS)); err != nil {
		return 0, fmt.Errorf("list vpcbindings: %w", err)
	}
	for i := range bindings.Items {
		other := &bindings.Items[i]
		if other.Name == binding.Name || !other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.Spec.VPCRef == ref {
			return 0, nil
		}
	}

	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{
		sdnv1alpha1.LabelVPCNamespace: ref.Namespace,
		sdnv1alpha1.LabelVPC:          ref.Name,
		sdnv1alpha1.LabelPodNamespace: consumerNS,
	}); err != nil {
		return 0, fmt.Errorf("list ports: %w", err)
	}

	reaped := 0
	for i := range ports.Items {
		if err := r.Delete(ctx, &ports.Items[i]); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return reaped, fmt.Errorf("delete port %q: %w", ports.Items[i].Name, err)
		}
		reaped++
	}
	return reaped, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *VPCBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Emit the Multus shim only where Multus exists. A cluster without it has no
	// KubeVirt secondary networks to serve, and watching a kind that is not served
	// would fail the manager's cache at startup.
	if _, err := mgr.GetRESTMapper().RESTMapping(nadGVK.GroupKind(), nadGVK.Version); err == nil {
		r.emitNAD = true
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPCBinding{}).
		Named("vpcbinding").
		Complete(r)
}
