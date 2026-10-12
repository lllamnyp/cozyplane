package server

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

func TestVerifiedRegistrationRevokesPreviousTLSBypass(t *testing.T) {
	existing := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService",
		"metadata": map[string]any{"name": apiServiceName},
		"spec":     map[string]any{"insecureSkipTLSVerify": true, "caBundle": "dHJ1c3RlZC1jYQ=="},
	}}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), existing)
	spec, annotations := apiServiceDesired("system", "apiserver", "system/serving", false)
	if _, err := ensureAPIServiceOnce(t.Context(), client.Resource(apiServiceGVR), spec, annotations); err != nil {
		t.Fatal(err)
	}
	got, err := client.Resource(apiServiceGVR).Get(t.Context(), apiServiceName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bypass, found, err := unstructured.NestedBool(got.Object, "spec", "insecureSkipTLSVerify")
	if err != nil || !found || bypass {
		t.Fatal("TLS bypass survived verified registration", got, err)
	}
	ca, _, _ := unstructured.NestedString(got.Object, "spec", "caBundle")
	if ca != "dHJ1c3RlZC1jYQ==" || got.GetAnnotations()["cert-manager.io/inject-ca-from"] != "system/serving" {
		t.Fatal("CA injection was damaged", got)
	}
	spec, annotations = apiServiceDesired("system", "apiserver", "", true)
	if _, err := ensureAPIServiceOnce(t.Context(), client.Resource(apiServiceGVR), spec, annotations); err != nil {
		t.Fatal(err)
	}
	got, err = client.Resource(apiServiceGVR).Get(t.Context(), apiServiceName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bypass, _, err = unstructured.NestedBool(got.Object, "spec", "insecureSkipTLSVerify")
	if err != nil || !bypass {
		t.Fatal("explicit development registration was not honoured", err)
	}
}
