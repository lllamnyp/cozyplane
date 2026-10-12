package floatingip

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestFloatingInputAdmissionBudget(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	strategy := NewStrategy(scheme)
	valid := &sdn.FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "tenant-a"}, Spec: sdn.FloatingIPSpec{VPCRef: sdn.LocalVPCRef{Name: "net"}, Target: "192.0.2.5"}}
	for _, field := range []string{"vpc", "target", "class", "claim"} {
		for _, value := range []string{strings.Repeat("x", 128<<10), "bad/name/extra"} {
			t.Run(fmt.Sprintf("%s/%d", field, len(value)), func(t *testing.T) {
				obj := valid.DeepCopy()
				switch field {
				case "vpc":
					obj.Spec.VPCRef.Name = value
				case "target":
					obj.Spec.Target = value
				case "class":
					obj.Spec.LoadBalancerClass = value
				case "claim":
					obj.Spec.AddressClaimName = value
				}
				errs := strategy.Validate(t.Context(), obj)
				if len(errs) == 0 {
					t.Fatal("unusable input admitted on create")
				}
				if len(strategy.ValidateUpdate(t.Context(), obj, valid)) == 0 {
					t.Fatal("unusable input admitted on update")
				}
				body, err := json.Marshal(apierrors.NewInvalid(sdn.Kind("FloatingIP"), obj.Name, errs).Status())
				if err != nil || len(body) > 2048 {
					t.Fatalf("diagnostic bytes=%d err=%v", len(body), err)
				}
			})
		}
	}
	for _, target := range []string{"192.0.2.5", "2001:db8::5", "2001:db8:0:0:0:0:0:5", "::ffff:192.0.2.5"} {
		obj := valid.DeepCopy()
		obj.Spec.Target = target
		obj.Spec.VPCRef.Name = strings.Repeat("a", 253)
		obj.Spec.AddressClaimName = strings.Repeat("b", 253)
		obj.Spec.LoadBalancerClass = strings.Repeat("c", 253) + "/" + strings.Repeat("D", 63)
		if errs := strategy.Validate(t.Context(), obj); len(errs) != 0 {
			t.Fatal("valid boundaries rejected", errs)
		}
		if errs := strategy.ValidateUpdate(t.Context(), obj, valid); len(errs) != 0 {
			t.Fatal("valid retarget rejected", errs)
		}
	}
	legacy := valid.DeepCopy()
	legacy.Spec.VPCRef.Name = strings.Repeat("x", 128<<10)
	updated := legacy.DeepCopy()
	updated.Labels = map[string]string{"cleanup": "true"}
	if errs := strategy.ValidateUpdate(t.Context(), updated, legacy); len(errs) != 0 {
		t.Fatal("legacy metadata cleanup blocked", errs)
	}
	if errs := strategy.ValidateUpdate(t.Context(), valid, legacy); len(errs) != 0 {
		t.Fatal("valid recovery blocked", errs)
	}
}
