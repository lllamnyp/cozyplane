package sdn

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	annotationvalidation "k8s.io/apimachinery/pkg/api/validation"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Mirror the API's annotation size validation, rather than allowing the fake
// client to accept a Port that the real server would reject.
type annotationCheckingClient struct {
	client.Client
	updates int
}

func (c *annotationCheckingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if err := annotationvalidation.ValidateAnnotationsSize(obj.GetAnnotations()); err != nil {
		return err
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestPersistentCutoverRejectsOversizedLabelsBeforeUpdate(t *testing.T) {
	port := persistentPort("vm", "192.168.0.2", "node-a")
	port.Spec.PodName = "source"
	port.Annotations = map[string]string{sdnv1alpha1.AnnotationPodLabels: `{"role":"source"}`}
	src := launcher("source", "node-a", "vm", "10.244.0.5", "uid-src")
	dst := launcher("target", "node-b", "vm", "10.244.1.9", "uid-dst")
	for i := range 15000 {
		dst.Labels[fmt.Sprintf("label%05d", i)] = strings.Repeat("x", 63)
	}
	if errs := metavalidation.ValidateLabels(dst.Labels, field.NewPath("metadata", "labels")); len(errs) != 0 {
		t.Fatal("fixture labels must be valid", errs)
	}
	encoded, err := json.Marshal(dst)
	if err != nil || len(encoded) >= 1536*1024 {
		t.Fatal("fixture must fit the default etcd request budget", len(encoded), err)
	}
	c := &annotationCheckingClient{Client: fake.NewClientBuilder().WithScheme(ppScheme(t)).WithObjects(
		port, src, dst, node("node-a", "192.0.2.1"), node("node-b", "192.0.2.2"), vmi("vm", "node-b"),
	).Build()}
	r := &PersistentPortReconciler{Client: c, watchVMI: true}
	for range 3 {
		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}}); err == nil {
			t.Fatal("oversized selector snapshot must be rejected")
		}
	}
	got := &sdnv1alpha1.Port{}
	if err := c.Get(t.Context(), types.NamespacedName{Name: port.Name}, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Spec, port.Spec) || !reflect.DeepEqual(got.Annotations, port.Annotations) || !reflect.DeepEqual(got.Labels, port.Labels) {
		t.Fatal("rejected cutover changed the source binding or pinned identity")
	}
	if c.updates != 0 {
		t.Fatalf("oversized snapshot reached API Update %d times; reject before serialization/update", c.updates)
	}
}
