// Package serviceidentity checks the generation of materialized Service data.
package serviceidentity

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func OwnsEndpointSlice(service *corev1.Service, slice *discoveryv1.EndpointSlice) bool {
	if service == nil || service.UID == "" || !service.DeletionTimestamp.IsZero() ||
		slice.Namespace != service.Namespace || !slice.DeletionTimestamp.IsZero() || slice.Labels[discoveryv1.LabelServiceName] != service.Name {
		return false
	}
	owner := metav1.GetControllerOf(slice)
	return owner != nil && owner.APIVersion == "v1" && owner.Kind == "Service" && owner.Name == service.Name && owner.UID == service.UID
}
