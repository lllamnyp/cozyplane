package vpcpeering

import (
	"context"
	"errors"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type managedAuthorizer struct {
	allow bool
	calls []authorizer.Attributes
}

func (a *managedAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	a.calls = append(a.calls, attrs)
	if attrs.GetVerb() == PeerVerb || a.allow {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "boundary management denied", nil
}

func managedContext() context.Context {
	return request.WithUser(context.Background(), &user.DefaultInfo{Name: "test-principal"})
}
func managedPeering() *sdn.VPCPeering {
	p := peering("team-a", "vpc-a", "team-b", "vpc-b")
	p.Labels = map[string]string{PortalManagedByLabel: PortalManagedBy}
	return p
}
func managedStrategy(a authorizer.Authorizer) vpcPeeringStrategy {
	s := runtime.NewScheme()
	install.Install(s)
	return NewStrategy(s, a)
}
func assertManagedCheck(t *testing.T, a *managedAuthorizer) {
	t.Helper()
	last := a.calls[len(a.calls)-1]
	if last.GetVerb() != "manage-boundary" || last.GetResource() != "vpcpeerings" || last.GetAPIGroup() != sdn.GroupName || last.GetNamespace() != "team-a" || last.GetName() != "p" || !last.IsResourceRequest() || last.GetUser().GetName() != "test-principal" {
		t.Fatalf("unexpected authorization attributes: %+v", last)
	}
}

func TestManagedPeeringCreateRequiresSeparateBoundaryVerb(t *testing.T) {
	for _, allow := range []bool{false, true} {
		a := &managedAuthorizer{allow: allow}
		errs := managedStrategy(a).Validate(managedContext(), managedPeering())
		if (len(errs) == 0) != allow {
			t.Fatalf("allow=%v errors=%v", allow, errs)
		}
		if len(a.calls) != 2 {
			t.Fatalf("checks=%d want peer and manage-boundary", len(a.calls))
		}
		assertManagedCheck(t, a)
	}
}

func TestManagedPeeringUpdatesCannotStripOrAddOwnership(t *testing.T) {
	for _, action := range []string{"metadata", "strip", "replace-marker", "add"} {
		for _, allow := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/denied", true: "/allowed"}[allow], func(t *testing.T) {
				old := managedPeering()
				updated := old.DeepCopy()
				switch action {
				case "metadata":
					updated.Annotations = map[string]string{"note": "test"}
				case "strip":
					updated.Labels = nil
				case "replace-marker":
					updated.Labels[PortalManagedByLabel] = "other-controller"
				case "add":
					old.Labels = nil
				}
				a := &managedAuthorizer{allow: allow}
				errs := managedStrategy(a).ValidateUpdate(managedContext(), updated, old)
				if (len(errs) == 0) != allow {
					t.Fatalf("allow=%v errors=%v", allow, errs)
				}
				if len(a.calls) != 1 {
					t.Fatalf("checks=%d", len(a.calls))
				}
				assertManagedCheck(t, a)
			})
		}
	}
}

func TestManagedPeeringStatusPreservesOwnership(t *testing.T) {
	for _, wasManaged := range []bool{false, true} {
		old := managedPeering()
		if !wasManaged {
			old.Labels = nil
		}
		updated := old.DeepCopy()
		updated.Labels = map[string]string{PortalManagedByLabel: "forged-controller"}
		updated.Spec.PeerRef.Name = "forged-vpc"
		updated.Status.Phase = sdn.VPCPeeringPhaseReady
		NewStatusStrategy(managedStrategy(&managedAuthorizer{})).PrepareForUpdate(managedContext(), updated, old)
		if updated.Labels[PortalManagedByLabel] != old.Labels[PortalManagedByLabel] || updated.Spec != old.Spec || updated.Status.Phase != sdn.VPCPeeringPhaseReady {
			t.Fatalf("status crossed protected fields: %+v", updated)
		}
	}
}

func TestManagedPeeringDeletionValidatesStoredObjectAndCaller(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, allow := range []bool{false, true} {
			p := managedPeering()
			if !managed {
				p.Labels = nil
			}
			a := &managedAuthorizer{allow: allow}
			r := &ManagedREST{auth: a}
			called := false
			want := errors.New("caller validation")
			err := r.deletionCheck(func(_ context.Context, obj runtime.Object) error {
				called = true
				if obj != p {
					t.Fatal("wrong stored object")
				}
				return want
			})(managedContext(), p)
			if managed && !allow {
				if !apierrors.IsForbidden(err) || called {
					t.Fatalf("denied deletion err=%v called=%v", err, called)
				}
			} else if !errors.Is(err, want) || !called {
				t.Fatalf("caller validation err=%v called=%v", err, called)
			}
			if managed {
				assertManagedCheck(t, a)
			} else if len(a.calls) != 0 {
				t.Fatal("legacy peering unexpectedly requires boundary authority")
			}
		}
	}
}
