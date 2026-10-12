package vpcbinding

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
)

func TestBindingReferenceAdmissionAndRetargetDiagnosticBudget(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "tenant-admin"})
	old := binding("tenant-a", "tenant-a", "net")
	for _, target := range []string{"name", "namespace"} {
		for _, input := range []string{strings.Repeat("x", 128<<10), "bad/name"} {
			t.Run(fmt.Sprintf("%s/%d", target, len(input)), func(t *testing.T) {
				p := old.DeepCopy()
				if target == "name" {
					p.Spec.VPCRef.Name = input
				} else {
					p.Spec.VPCRef.Namespace = input
				}
				auth := &recordingAuthorizer{allow: true}
				s := NewStrategy(scheme, auth)
				for _, errs := range []field.ErrorList{s.Validate(ctx, p), s.ValidateUpdate(ctx, p, old)} {
					if len(errs) == 0 {
						t.Error("invalid reference admitted")
						continue
					}
					body, err := json.Marshal(apierrors.NewInvalid(sdn.Kind("VPCBinding"), p.Name, errs).Status())
					if err != nil || len(body) > 2048 {
						t.Fatalf("unbounded rejection: bytes=%d error=%v", len(body), err)
					}
				}
				if auth.calls != 0 {
					t.Fatal("invalid reference reached authorization", auth.calls)
				}
			})
		}
	}
}

func TestBindingReferenceBoundariesAndLegacyWithdrawal(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "tenant-admin"})
	for _, namespace := range []string{"", strings.Repeat("a", 63)} {
		p := binding("tenant-a", namespace, strings.Repeat("b", 253))
		auth := &recordingAuthorizer{allow: true}
		if errs := NewStrategy(scheme, auth).Validate(ctx, p); len(errs) != 0 || auth.calls != 1 {
			t.Fatal("valid reference rejected", errs)
		}
		wantNS := namespace
		if wantNS == "" {
			wantNS = p.Namespace
		}
		if auth.last.GetNamespace() != wantNS || auth.last.GetName() != p.Spec.VPCRef.Name {
			t.Fatal("reference/default changed before authorization")
		}
	}
	for _, p := range []*sdn.VPCBinding{binding("tenant-a", "tenant-a", ""), binding("tenant-a", "tenant-a", strings.Repeat("x", 254)), binding("tenant-a", strings.Repeat("x", 64), "net")} {
		if errs := NewStrategy(scheme, nil).Validate(ctx, p); len(errs) == 0 {
			t.Fatal("invalid boundary accepted")
		}
	}
	legacy := binding("tenant-a", "tenant-a", strings.Repeat("x", 128<<10))
	legacy.Spec.AllowForwarding = true
	legacy.Finalizers = []string{"sdn.cozystack.io/reap-ports"}
	for _, mode := range []string{"metadata", "withdraw", "finalizer"} {
		updated := legacy.DeepCopy()
		switch mode {
		case "metadata":
			updated.Labels = map[string]string{"cleanup": "true"}
		case "withdraw":
			updated.Spec.AllowForwarding = false
		case "finalizer":
			updated.Finalizers = nil
		}
		for _, allow := range []bool{false, true} {
			auth := &recordingAuthorizer{allow: allow}
			errs := NewStrategy(scheme, auth).ValidateUpdate(ctx, updated, legacy)
			wantAllowed := mode == "metadata" || allow
			if (len(errs) == 0) != wantAllowed {
				t.Fatalf("legacy mode=%s allow=%v errs=%d", mode, allow, len(errs))
			}
			if len(errs) != 0 {
				body, err := json.Marshal(apierrors.NewInvalid(sdn.Kind("VPCBinding"), updated.Name, errs).Status())
				if err != nil || len(body) > 2048 {
					t.Fatalf("legacy denial unbounded: bytes=%d err=%v", len(body), err)
				}
			}
			if mode == "metadata" && auth.calls != 0 {
				t.Fatal("metadata cleanup unexpectedly needs owner authority")
			}
		}
	}
}
