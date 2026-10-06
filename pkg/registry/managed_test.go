package registry

import (
	"context"
	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"testing"
)

type denyManaged struct{}

func (denyManaged) Authorize(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionDeny, "", nil
}
func TestManagedDeletionUsesStoredMarkerForSingleAndCollectionValidation(t *testing.T) {
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "tenant-test"})
	r := &ManagedREST{Auth: denyManaged{}, Resource: "securitygroups"}
	obj := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: "group-test", Namespace: "tenant-test", Labels: map[string]string{authz.ManagedByLabel: authz.PortalManager}}}
	if err := r.deletionCheck(nil)(ctx, obj); err == nil {
		t.Fatal("managed stored object deletion allowed")
	}
	obj.Labels = nil
	if err := r.deletionCheck(nil)(ctx, obj); err != nil {
		t.Fatalf("ordinary tenant object deletion blocked: %v", err)
	}
}
