package securitygroup

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

func TestManagedOwnershipRequiresBoundaryAuthority(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "test-principal"})
	for _, action := range []string{"create", "spec", "metadata", "strip", "replace", "add"} {
		for _, allow := range []bool{false, true} {
			t.Run(action+map[bool]string{true: "/allowed", false: "/denied"}[allow], func(t *testing.T) {
				calls := 0
				auth := authorizer.AuthorizerFunc(func(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
					calls++
					if attrs.GetVerb() != "manage-boundary" || attrs.GetResource() != "securitygroups" || attrs.GetNamespace() != "team-a" || attrs.GetName() != "managed" || attrs.GetAPIGroup() != sdn.GroupName || attrs.GetUser().GetName() != "test-principal" {
						t.Fatalf("wrong authority check: %+v", attrs)
					}
					if allow {
						return authorizer.DecisionAllow, "", nil
					}
					return authorizer.DecisionDeny, "denied", nil
				})
				old := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: "team-a", Labels: map[string]string{authz.ManagedByLabel: authz.PortalManager}}}
				old.Spec.VPCRef.Name = "vpc-a"
				updated := old.DeepCopy()
				switch action {
				case "spec":
					updated.Spec.VPCRef.Name = "vpc-b"
				case "metadata":
					updated.Annotations = map[string]string{"note": "changed"}
				case "strip":
					updated.Labels = nil
				case "replace":
					updated.Labels[authz.ManagedByLabel] = "other-controller"
				case "add":
					old.Labels = nil
				}
				strategy := NewStrategy(scheme, auth)
				errs := strategy.Validate(ctx, updated)
				if action != "create" {
					calls = 0
					errs = strategy.ValidateUpdate(ctx, updated, old)
				}
				// Group VPC references remain immutable even for an authorized operator.
				expected := allow && !(action == "spec" && "securitygroup" == "securitygroup")
				if (len(errs) == 0) != expected || calls != 1 {
					t.Fatalf("allow=%v errors=%v calls=%d", allow, errs, calls)
				}
			})
		}
	}
}

func TestStatusPreservesManagedOwnershipAndGeneration(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	for _, managed := range []bool{false, true} {
		old := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Generation: 7}}
		old.Spec.VPCRef.Name = "vpc-a"
		if managed {
			old.Labels = map[string]string{authz.ManagedByLabel: authz.PortalManager}
		}
		updated := old.DeepCopy()
		updated.Spec.VPCRef.Name = "forged"
		updated.Generation = 99
		updated.Labels = map[string]string{authz.ManagedByLabel: "forged"}
		NewStatusStrategy(NewStrategy(scheme, nil)).PrepareForUpdate(context.Background(), updated, old)
		if updated.Spec.VPCRef != old.Spec.VPCRef || updated.Generation != old.Generation || updated.Labels[authz.ManagedByLabel] != old.Labels[authz.ManagedByLabel] {
			t.Fatalf("status changed protected ownership: %+v", updated)
		}
	}
}
