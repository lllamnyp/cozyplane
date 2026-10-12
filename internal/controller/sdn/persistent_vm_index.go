package sdn

import (
	"context"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const persistentVMIndex = "cozyplane.persistentVM"

func persistentVMKey(namespace, name string) string {
	if namespace == "" || len(namespace) > validation.DNS1123LabelMaxLength ||
		name == "" || len(name) > validation.DNS1123SubdomainMaxLength ||
		len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return ""
	}
	return namespace + "/" + name
}

func persistentVMKeys(object client.Object) []string {
	port, ok := object.(*sdnv1alpha1.Port)
	if !ok {
		return nil
	}
	key := persistentVMKey(port.Spec.PodNamespace, port.Labels[sdnv1alpha1.LabelVMName])
	if key == "" {
		return nil
	}
	return []string{key}
}

func (r *PersistentPortReconciler) mapVMToPort(ctx context.Context, namespace, name string) []ctrl.Request {
	key := persistentVMKey(namespace, name)
	if key == "" {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingFields{persistentVMIndex: key}); err != nil {
		log.FromContext(ctx).Error(err, "lookup persistent VM Ports", "namespace", namespace, "vm", name)
		return nil
	}
	var requests []ctrl.Request
	for i := range ports.Items {
		port := &ports.Items[i]
		if port.Spec.PodNamespace == namespace && port.Labels[sdnv1alpha1.LabelVMName] == name {
			requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}})
		}
	}
	return requests
}
