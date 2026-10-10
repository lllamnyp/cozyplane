package v1alpha1_test

import (
	"reflect"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	v1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

func TestPortMembershipProofSurvivesAPICodecAndDeepCopy(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	port := &v1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2"}, Status: v1.PortStatus{Groups: []int32{1}, GroupPodUID: "pod-uid", GroupRefs: []v1.SecurityGroupMembership{{ID: 1, UID: "group-uid"}}}}
	internal := &sdn.Port{}
	if err := scheme.Convert(port, internal, nil); err != nil {
		t.Fatal(err)
	}
	codec := serializer.NewCodecFactory(scheme).LegacyCodec(v1.SchemeGroupVersion)
	data, err := runtime.Encode(codec, internal)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &sdn.Port{}
	if err := runtime.DecodeInto(codec, data, decoded); err != nil {
		t.Fatal(err)
	}
	back := &v1.Port{}
	if err := scheme.Convert(decoded, back, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Status, port.Status) {
		t.Fatal("membership proof lost through API serialization", back.Status)
	}
	copy := back.DeepCopy()
	copy.Status.GroupRefs[0].UID = "replacement"
	if back.Status.GroupRefs[0].UID != "group-uid" {
		t.Fatal("copied status shares mutable group proof")
	}
}
