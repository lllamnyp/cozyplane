package vpcpeering

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
)

func TestPeeringReferenceAdmissionBeforeAuthorization(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "tenant-admin"})
	for _, target := range []string{"local", "remote", "namespace"} {
		for _, input := range []string{strings.Repeat("x", 128<<10), "bad/name", ""} {
			t.Run(fmt.Sprintf("%s/%d", target, len(input)), func(t *testing.T) {
				p := peering("tenant-a", "net-a", "tenant-b", "net-b")
				switch target {
				case "local":
					p.Spec.VPCRef.Name = input
				case "remote":
					p.Spec.PeerRef.Name = input
				case "namespace":
					p.Spec.PeerRef.Namespace = input
				}
				auth := &recordingAuthorizer{allow: true}
				errs := NewStrategy(scheme, auth).Validate(ctx, p)
				if len(errs) == 0 || auth.last != nil {
					t.Fatalf("invalid reference admitted or authorized: errors=%d authorization=%v", len(errs), auth.last != nil)
				}
				body, err := json.Marshal(apierrors.NewInvalid(sdn.Kind("VPCPeering"), p.Name, errs).Status())
				if err != nil || len(body) > 2048 {
					t.Fatalf("unbounded diagnostic: bytes=%d error=%v", len(body), err)
				}
			})
		}
	}
	valid := peering("tenant-a", strings.Repeat("a", 253), strings.Repeat("b", 63), strings.Repeat("c", 253))
	auth := &recordingAuthorizer{allow: true}
	if errs := NewStrategy(scheme, auth).Validate(ctx, valid); len(errs) != 0 || auth.last == nil || auth.last.GetName() != valid.Spec.VPCRef.Name {
		t.Fatalf("valid boundary or authorization changed: %v", errs)
	}
	legacy := peering("tenant-a", "net-a", "tenant-b", strings.Repeat("x", 128<<10))
	updated := legacy.DeepCopy()
	updated.Labels = map[string]string{"cleanup": "true"}
	if errs := NewStrategy(scheme, nil).ValidateUpdate(ctx, updated, legacy); len(errs) != 0 {
		t.Fatal("unchanged legacy metadata cleanup blocked", errs)
	}
}
