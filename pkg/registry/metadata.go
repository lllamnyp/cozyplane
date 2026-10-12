package registry

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/validate/content"
	validation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
)

// Qualified keys/finalizers contain an optional DNS prefix, '/', and a name
// with the same 63-byte limit as a label value. Reject impossible lengths
// before the SDK splits or matches arbitrarily long strings.
const maxMetadataQualifiedNameBytes = content.DNS1123SubdomainMaxLength + 1 + content.LabelValueMaxLength

// InstallMetadataValidation rejects malformed collections before the generic
// store formats their complete error list (which can amplify rejected input).
// Install before copying a store for /status, preserving any existing hooks.
func InstallMetadataValidation(store *genericregistry.Store) {
	check := func(obj runtime.Object) error {
		metadata, err := meta.Accessor(obj)
		if err != nil {
			return err
		}
		problem := metadataCollectionProblem(metadata)
		if problem == nil {
			return nil
		}
		kinds, _, err := store.CreateStrategy.ObjectKinds(obj)
		if err != nil {
			return err
		}
		if len(kinds) == 0 {
			return apierrors.NewInternalError(errors.New("object has no registered kind"))
		}
		name := metadata.GetName()
		// A diagnostic must not echo an arbitrary-length name.
		if len(name) > content.DNS1123SubdomainMaxLength {
			name = ""
		}
		return apierrors.NewInvalid(kinds[0].GroupKind(), name, field.ErrorList{problem})
	}
	beginCreate, beginUpdate := store.BeginCreate, store.BeginUpdate
	store.BeginCreate = func(ctx context.Context, obj runtime.Object, options *metav1.CreateOptions) (genericregistry.FinishFunc, error) {
		if err := check(obj); err != nil {
			return nil, err
		}
		if beginCreate != nil {
			return beginCreate(ctx, obj, options)
		}
		return finishMetadataValidation, nil
	}
	store.BeginUpdate = func(ctx context.Context, obj, old runtime.Object, options *metav1.UpdateOptions) (genericregistry.FinishFunc, error) {
		if err := check(obj); err != nil {
			return nil, err
		}
		if beginUpdate != nil {
			return beginUpdate(ctx, obj, old, options)
		}
		return finishMetadataValidation, nil
	}
}

func finishMetadataValidation(context.Context, bool) {}

func metadataCollectionProblem(metadata metav1.Object) *field.Error {
	path := field.NewPath("metadata")
	invalid := func(path *field.Path) *field.Error { return field.Invalid(path, nil, "contains invalid fields") }
	for key, value := range metadata.GetLabels() {
		if len(key) > maxMetadataQualifiedNameBytes || len(value) > content.LabelValueMaxLength || len(v1validation.ValidateLabels(map[string]string{key: value}, path.Child("labels"))) != 0 {
			return invalid(path.Child("labels"))
		}
	}
	if validation.ValidateAnnotationsSize(metadata.GetAnnotations()) != nil {
		return invalid(path.Child("annotations"))
	}
	for key, value := range metadata.GetAnnotations() {
		if len(key) > maxMetadataQualifiedNameBytes || len(validation.ValidateAnnotations(map[string]string{key: value}, path.Child("annotations"))) != 0 {
			return invalid(path.Child("annotations"))
		}
	}
	controller := false
	for i, owner := range metadata.GetOwnerReferences() {
		p := path.Child("ownerReferences").Index(i)
		if len(validation.ValidateOwnerReferences([]metav1.OwnerReference{owner}, p)) != 0 {
			return invalid(p)
		}
		if owner.Controller != nil && *owner.Controller {
			if controller {
				return invalid(p)
			}
			controller = true
		}
	}
	orphan, foreground := false, false
	for i, finalizer := range metadata.GetFinalizers() {
		p := path.Child("finalizers").Index(i)
		if len(finalizer) > maxMetadataQualifiedNameBytes || len(validation.ValidateFinalizerName(finalizer, p)) != 0 {
			return invalid(p)
		}
		orphan = orphan || finalizer == metav1.FinalizerOrphanDependents
		foreground = foreground || finalizer == metav1.FinalizerDeleteDependents
		if orphan && foreground {
			return invalid(p)
		}
	}
	for i, entry := range metadata.GetManagedFields() {
		p := path.Child("managedFields").Index(i)
		// ValidateFieldManager emits one error per non-printable rune. Its own
		// length rule must run first so even a single entry cannot fan out.
		if len(entry.Manager) > v1validation.FieldManagerMaxLength || len(v1validation.ValidateManagedFields([]metav1.ManagedFieldsEntry{entry}, p)) != 0 {
			return invalid(p)
		}
	}
	return nil
}
