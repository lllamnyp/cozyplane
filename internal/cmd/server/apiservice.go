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

	// The label the kube-apiserver's CRD autoregistration controller stamps on
	// APIServices it manages. While it is present, that controller reconciles
	// the object back to local (CRD) serving — removing it is what makes the
	// takeover stick.
	autoManagedLabel = "kube-aggregator.kubernetes.io/automanaged"
)

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
func EnsureAPIService(ctx context.Context, cfg *rest.Config, svcNamespace, svcName, caInjection string) error {
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
	annotations := map[string]any{}
	if caInjection != "" {
		annotations["cert-manager.io/inject-ca-from"] = caInjection
	}

	// Retry across startup races (RBAC propagation, transient apiserver blips).
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		existing, err := c.Get(ctx, apiServiceName, metav1.GetOptions{})
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

		// Exists (ours from a previous run, or the CRD autoregistration's):
		// merge-patch the desired spec in and strip the automanaged label so the
		// autoregistration controller stops fighting for it.
		patch := map[string]any{
			"metadata": map[string]any{
				"labels":      map[string]any{autoManagedLabel: nil},
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
		if _, wasAuto := existing.GetLabels()[autoManagedLabel]; wasAuto {
			klog.Infof("took over APIService %s from CRD autoregistration -> %s/%s", apiServiceName, svcNamespace, svcName)
		} else {
			klog.V(2).Infof("APIService %s ensured -> %s/%s", apiServiceName, svcNamespace, svcName)
		}
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
