package authz

import (
	"context"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

const ManagedByLabel = "app.kubernetes.io/managed-by"
const PortalManager = "neosequentia-portal"

func PortalManaged(obj runtime.Object) bool {
	if obj == nil {
		return false
	}
	metadata, err := meta.Accessor(obj)
	return err == nil && metadata.GetLabels()[ManagedByLabel] == PortalManager
}

func CheckManaged(ctx context.Context, auth authorizer.Authorizer, resource string, obj, old runtime.Object) *field.Error {
	if !PortalManaged(obj) && !PortalManaged(old) {
		return nil
	}
	metadata, err := meta.Accessor(obj)
	if err != nil {
		return field.InternalError(field.NewPath("metadata"), err)
	}
	return CheckResourceVerb(ctx, auth, "manage-boundary", resource, resource, metadata.GetNamespace(), metadata.GetName(), field.NewPath("metadata", "labels").Key(ManagedByLabel))
}

func PreserveManager(obj, old runtime.Object) {
	current, _ := meta.Accessor(obj)
	previous, _ := meta.Accessor(old)
	labels := current.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	if value, exists := previous.GetLabels()[ManagedByLabel]; exists {
		labels[ManagedByLabel] = value
	} else {
		delete(labels, ManagedByLabel)
	}
	current.SetLabels(labels)
	current.SetGeneration(previous.GetGeneration())
}
