/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func fakeAPIServices(t *testing.T) dynamic.ResourceInterface {
	t.Helper()
	scheme := runtime.NewScheme()
	c := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{apiServiceGVR: "APIServiceList"})
	return c.Resource(apiServiceGVR)
}

func getAPIService(t *testing.T, c dynamic.ResourceInterface) (found bool) {
	t.Helper()
	_, err := c.Get(context.Background(), apiServiceName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get APIService: %v", err)
	}
	return true
}

// A registration asserted once at startup is not maintained. On an in-place
// switch to the cozyplane networking variant, the previous owner's Helm release
// was upgraded with the APIService no longer in its manifest, Helm deleted the
// object, and the whole aggregated group vanished until this pod was restarted
// by hand. A pass after the delete must put it back.
func TestEnsureAPIServiceRecreatesAfterDelete(t *testing.T) {
	ctx := context.Background()
	c := fakeAPIServices(t)
	spec, annotations := apiServiceDesired("cozy-cozyplane", "cozyplane-apiserver", "", true)

	created, err := ensureAPIServiceOnce(ctx, c, spec, annotations)
	if err != nil {
		t.Fatalf("initial ensure: %v", err)
	}
	if !created {
		t.Fatal("initial ensure did not create the APIService")
	}
	if !getAPIService(t, c) {
		t.Fatal("APIService missing after the initial ensure")
	}

	// Something outside this server removes it — Helm, in the incident.
	if err := c.Delete(ctx, apiServiceName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if getAPIService(t, c) {
		t.Fatal("test setup: the APIService survived the delete")
	}

	created, err = ensureAPIServiceOnce(ctx, c, spec, annotations)
	if err != nil {
		t.Fatalf("ensure after delete: %v", err)
	}
	if !created {
		t.Error("ensure after delete reported no creation; the deletion went unrepaired")
	}
	if !getAPIService(t, c) {
		t.Fatal("APIService was not recreated after being deleted")
	}
}

// Every pass after the first must be a no-op patch, not a recreate: `created`
// is what the reconcile loop logs on, so a false positive would cry wolf every
// interval.
func TestEnsureAPIServiceIsIdempotent(t *testing.T) {
	ctx := context.Background()
	c := fakeAPIServices(t)
	spec, annotations := apiServiceDesired("cozy-cozyplane", "cozyplane-apiserver", "", true)

	if _, err := ensureAPIServiceOnce(ctx, c, spec, annotations); err != nil {
		t.Fatalf("initial ensure: %v", err)
	}
	for i := range 3 {
		created, err := ensureAPIServiceOnce(ctx, c, spec, annotations)
		if err != nil {
			t.Fatalf("ensure %d: %v", i, err)
		}
		if created {
			t.Fatalf("ensure %d reported a creation for an object that already exists", i)
		}
	}
}

// The desired spec is what the aggregator routes on; drift here sends the group
// at the wrong Service.
func TestAPIServiceDesired(t *testing.T) {
	spec, annotations := apiServiceDesired("cozy-cozyplane", "cozyplane-apiserver", "cozy-cozyplane/serving-cert", false)

	svc, _ := spec["service"].(map[string]any)
	if svc["namespace"] != "cozy-cozyplane" || svc["name"] != "cozyplane-apiserver" || svc["port"] != int64(443) {
		t.Errorf("service ref = %v, want cozy-cozyplane/cozyplane-apiserver:443", svc)
	}
	if spec["group"] != sdnGroup || spec["version"] != sdnVersion {
		t.Errorf("group/version = %v/%v, want %s/%s", spec["group"], spec["version"], sdnGroup, sdnVersion)
	}
	if _, ok := spec["insecureSkipTLSVerify"]; ok {
		t.Error("insecureSkipTLSVerify set although CA injection was requested")
	}
	if annotations["cert-manager.io/inject-ca-from"] != "cozy-cozyplane/serving-cert" {
		t.Errorf("ca injection annotation = %v", annotations["cert-manager.io/inject-ca-from"])
	}

	// The dev/CI path: no cainjector, so the aggregator is told not to pin a CA.
	spec, annotations = apiServiceDesired("ns", "svc", "", true)
	if spec["insecureSkipTLSVerify"] != true {
		t.Error("insecureSkipTLSVerify not set without CA injection")
	}
	if len(annotations) != 0 {
		t.Errorf("annotations = %v, want none", annotations)
	}
}
