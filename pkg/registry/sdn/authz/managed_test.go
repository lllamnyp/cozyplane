package authz_test

import (
	"context"
	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/securitygroup"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcgateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"testing"
)

type managedAuthorizer struct {
	allow    bool
	resource string
}

func (a managedAuthorizer) Authorize(_ context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	if a.allow && attr.GetVerb() == "manage-boundary" && attr.GetResource() == a.resource && attr.GetNamespace() == "tenant-test" && attr.GetName() == "network-test" {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "", nil
}

type validationStrategy interface {
	Validate(context.Context, runtime.Object) field.ErrorList
	ValidateUpdate(context.Context, runtime.Object, runtime.Object) field.ErrorList
}

func TestManagedNetworkStrategiesRequireOperatorForCreateAndMarkerRemoval(t *testing.T) {
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "operator-test"})
	for _, resource := range []string{"securitygroups", "vpcgateways"} {
		for _, allow := range []bool{false, true} {
			t.Run(resource, func(t *testing.T) {
				metadata := metav1.ObjectMeta{Name: "network-test", Namespace: "tenant-test", Labels: map[string]string{authz.ManagedByLabel: authz.PortalManager}}
				var strategy validationStrategy
				var old runtime.Object
				if resource == "securitygroups" {
					strategy = securitygroup.NewStrategy(runtime.NewScheme(), managedAuthorizer{allow, resource})
					old = &sdn.SecurityGroup{ObjectMeta: metadata, Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "vpc-test"}}}
				} else {
					strategy = vpcgateway.NewStrategy(runtime.NewScheme(), managedAuthorizer{allow, resource})
					old = &sdn.VPCGateway{ObjectMeta: metadata, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "vpc-test"}}}
				}
				if errs := strategy.Validate(ctx, old); (len(errs) == 0) != allow {
					t.Fatalf("managed create allow=%v errors=%v", allow, errs)
				}
				updated := old.DeepCopyObject()
				if obj, ok := updated.(*sdn.SecurityGroup); ok {
					obj.Labels = map[string]string{}
				} else {
					updated.(*sdn.VPCGateway).Labels = map[string]string{}
				}
				if errs := strategy.ValidateUpdate(ctx, updated, old); (len(errs) == 0) != allow {
					t.Fatalf("strip marker allow=%v errors=%v", allow, errs)
				}
				if errs := strategy.ValidateUpdate(ctx, old.DeepCopyObject(), old); (len(errs) == 0) != allow {
					t.Fatalf("main resource update ownership mismatch: %v", errs)
				}
			})
		}
	}
}
