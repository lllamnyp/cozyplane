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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// The group/version this server serves; the APIService it registers.
const (
	sdnGroup       = "sdn.cozystack.io"
	sdnVersion     = "v1alpha1"
	apiServiceName = sdnVersion + "." + sdnGroup
)

// sdnPlurals are the group's resources — the bootstrap CRDs named
// "<plural>.sdn.cozystack.io". Keep in step with internal/setup/sdn's storage
// map; a missing entry just leaves one CRD behind (and its OpenAPI collision).
var sdnPlurals = []string{
	"vpcs", "vpcbindings", "vpcpeerings", "ports", "externalpools",
	"floatingips", "servicevips", "securitygroups", "hostfirewalls",
}

var apiServiceGVR = schema.GroupVersionResource{
	Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices",
}

// EnsureAPIService registers (or takes over) the APIService for the group this
// server serves, pointing it at the given Service. This cannot be a chart
// manifest: when the group bootstraps as CRDs, the kube-apiserver has already
// auto-registered a local APIService for it, and Helm refuses to adopt an
// object it does not own. Create-or-patch from the server itself is ownerless
// and idempotent; dropping the autoregistration label stops the CRD controller
// from reconciling the object back to local serving. caInjection, when set
// ("namespace/certificate"), lets cert-manager's cainjector maintain the
// caBundle, exactly as the manifest flow did.
func EnsureAPIService(ctx context.Context, cfg *rest.Config, svcNamespace, svcName, caInjection string, insecureSkipTLS bool) error {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("dynamic client: %w", err)
	}
	c := dyn.Resource(apiServiceGVR)

	spec := map[string]any{
		"group":                sdnGroup,
		"version":              sdnVersion,
		"groupPriorityMinimum": int64(1000),
		"versionPriority":      int64(15),
		"service": map[string]any{
			"namespace": svcNamespace,
			"name":      svcName,
			"port":      int64(443),
		},
	}
	if insecureSkipTLS {
		// The server self-signed its serving cert (dev/CI: no cert-manager), so
		// the aggregator has no CA to pin. Production installs inject one.
		spec["insecureSkipTLSVerify"] = true
	}
	annotations := map[string]any{}
	if caInjection != "" {
		annotations["cert-manager.io/inject-ca-from"] = caInjection
	}

	// Retry across startup races (RBAC propagation, transient apiserver blips).
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := c.Get(ctx, apiServiceName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apiregistration.k8s.io/v1",
				"kind":       "APIService",
				"metadata": map[string]any{
					"name":        apiServiceName,
					"annotations": annotations,
				},
				"spec": spec,
			}}
			if _, err := c.Create(ctx, obj, metav1.CreateOptions{FieldManager: "cozyplane-apiserver"}); err != nil {
				klog.Warningf("create APIService %s: %v (retrying)", apiServiceName, err)
				return false, nil
			}
			klog.Infof("registered APIService %s -> %s/%s", apiServiceName, svcNamespace, svcName)
			return true, nil
		case err != nil:
			klog.Warningf("get APIService %s: %v (retrying)", apiServiceName, err)
			return false, nil
		}

		// Exists from a previous run of ours: merge-patch the desired spec in.
		// (Nothing else creates this object anymore. The group has no CRDs, so
		// the kube-apiserver's CRD autoregistration never sees it — the whole
		// takeover dance, and the label fight it needed, is gone.)
		patch := map[string]any{
			"metadata": map[string]any{
				"annotations": annotations,
			},
			"spec": spec,
		}
		body, err := json.Marshal(patch)
		if err != nil {
			return false, err
		}
		if _, err := c.Patch(ctx, apiServiceName, types.MergePatchType, body, metav1.PatchOptions{FieldManager: "cozyplane-apiserver"}); err != nil {
			klog.Warningf("patch APIService %s: %v (retrying)", apiServiceName, err)
			return false, nil
		}
		klog.V(2).Infof("APIService %s ensured -> %s/%s", apiServiceName, svcNamespace, svcName)
		return true, nil
	})
}

// splitServiceRef parses "namespace/name".
func splitServiceRef(ref string) (ns, name string, err error) {
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected namespace/name, got %q", ref)
	}
	return parts[0], parts[1], nil
}

// crdGVR is apiextensions' CRD resource — the bootstrap surface this server
// supersedes.
var crdGVR = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions",
}

// RemoveBootstrapCRDs deletes CRDs for this server's group.
//
// Since the API-group split (docs/api-groups.md) the tenant kinds have no CRDs
// at all — the group is aggregated-only, so nothing here should exist. This
// stays as the cleanup for a cluster installed BEFORE the split, where the old
// single-group CRDs are still present and still poisoning the group's OpenAPI.
//
// Leaving them breaks the group. A CRD keeps publishing
// its OpenAPI paths after the APIService takes over serving, so the
// kube-apiserver tries to merge two specs describing the same paths and fails:
//
//	Error in OpenAPI handler: failed to build merge specs: unable to merge:
//	duplicated path /apis/sdn.cozystack.io/v1alpha1/namespaces/{namespace}/vpcs/{name}
//
// The group's OpenAPI then never serves, and every `kubectl apply` of one of
// our objects dies client-side with "failed to download openapi" — while every
// core type keeps working, which is what made this so easy to miss. The CRDs
// are shadowed for *routing*, never for OpenAPI.
//
// Deleting a CRD deletes the objects in ITS store. That is safe here precisely
// because the takeover is storage-disjoint (docs/control-plane.md §0): the
// aggregated server keeps its objects in its own etcd, the CRD store's copies
// were never migrated, and the documented migration path is export → install →
// re-apply. Anything still sitting in the CRD store is already invisible —
// requests have been answered by the aggregated server since the takeover.
func RemoveBootstrapCRDs(ctx context.Context, cfg *rest.Config, plurals []string) error {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("dynamic client: %w", err)
	}
	c := dyn.Resource(crdGVR)
	for _, plural := range plurals {
		name := plural + "." + sdnGroup
		err := c.Delete(ctx, name, metav1.DeleteOptions{})
		switch {
		case apierrors.IsNotFound(err):
			// The common case once the handoff has happened.
		case err != nil:
			// Not fatal: the group still SERVES correctly, only its OpenAPI is
			// degraded. Say so loudly rather than refusing to start.
			klog.Warningf("could not remove bootstrap CRD %s: %v — while it exists, "+
				"OpenAPI for %s cannot merge and `kubectl apply` of its objects will "+
				"fail client-side validation", name, err, sdnGroup)
		default:
			klog.Infof("removed bootstrap CRD %s (superseded by the aggregated APIService)", name)
		}
	}
	return nil
}
