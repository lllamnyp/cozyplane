package registry

import (
	"context"
	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/rest"
)

// ManagedREST checks the stored object during single and collection deletion.
type ManagedREST struct {
	*REST
	Auth     authorizer.Authorizer
	Resource string
}

func (r *ManagedREST) deletionCheck(check rest.ValidateObjectFunc) rest.ValidateObjectFunc {
	return func(ctx context.Context, obj runtime.Object) error {
		if err := authz.CheckManaged(ctx, r.Auth, r.Resource, obj, nil); err != nil {
			metadata, _ := meta.Accessor(obj)
			return apierrors.NewForbidden(sdn.Resource(r.Resource), metadata.GetName(), err)
		}
		if check != nil {
			return check(ctx, obj)
		}
		return nil
	}
}
func (r *ManagedREST) Delete(ctx context.Context, name string, check rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	return r.Store.Delete(ctx, name, r.deletionCheck(check), options)
}
func (r *ManagedREST) DeleteCollection(ctx context.Context, check rest.ValidateObjectFunc, options *metav1.DeleteOptions, listOptions *metainternalversion.ListOptions) (runtime.Object, error) {
	return r.Store.DeleteCollection(ctx, r.deletionCheck(check), options, listOptions)
}
