package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestEffectiveFloatingIPUsesIdentityAndAge(t *testing.T) {
	older := FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: "z-old", CreationTimestamp: metav1.NewTime(time.Unix(1, 0))}, Spec: FloatingIPSpec{VPCRef: LocalVPCRef{Name: "net"}, Target: "fd00::5"}}
	newer := older
	newer.Name = "a-new"
	newer.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	newer.Spec.Target = "fd00:0:0:0:0:0:0:5"
	other := older
	other.Name = "a-other"
	other.Spec.VPCRef.Name = "other"
	items := []FloatingIP{newer, other, older}
	if got := EffectiveFloatingIP(items, "net", "fd00::5"); got == nil || got.Name != older.Name {
		t.Fatalf("wrong winner: %+v", got)
	}
	now := metav1.Now()
	items[2].DeletionTimestamp = &now
	if got := EffectiveFloatingIP(items, "net", "fd00::5"); got == nil || got.Name != newer.Name {
		t.Fatalf("wrong successor: %+v", got)
	}
	if got := EffectiveFloatingIP(items, "net", "invalid"); got != nil {
		t.Fatal("invalid target selected")
	}
}
