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

package sdn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// readClaim reads an IPAddressClaim's phase and bound addresses with a plain
// GET. A claim API that is not installed yields apiMissing.
func readClaim(ctx context.Context, rd client.Reader, namespace, name string) (natClaimInfo, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ipAddressClaimGVK)
	err := rd.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, u)
	switch {
	case meta.IsNoMatchError(err):
		return natClaimInfo{apiMissing: true}, nil
	case apierrors.IsNotFound(err):
		return natClaimInfo{}, nil
	case err != nil:
		return natClaimInfo{}, fmt.Errorf("get IPAddressClaim %s/%s: %w", namespace, name, err)
	}
	info := natClaimInfo{found: true}
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	info.bound = phase == "Bound"
	addrs, _, _ := unstructured.NestedSlice(u.Object, "status", "addresses")
	info.addresses = map[corev1.IPFamily]string{}
	for _, a := range addrs {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		s, _ := m["address"].(string)
		if ip, err := netip.ParseAddr(s); err == nil {
			f := corev1.IPv6Protocol
			if ip.Is4() || ip.Is4In6() {
				f = corev1.IPv4Protocol
			}
			if info.addresses[f] == "" {
				info.addresses[f] = ip.Unmap().String()
			}
		}
	}
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		if info.addresses[f] != "" {
			info.families = append(info.families, f)
		}
	}
	return info, nil
}

// FieldOwner is the field manager of every sdn controller write. annotationOwnedByOthers
// checks ownership against it, so the writer and the check cannot drift. The
// value is the name the manager had before it was set explicitly, so the
// annotations it wrote then are still its own.
const FieldOwner = "sdn-controller"

// annotationOwnedByOthers reports whether a field manager other than FieldOwner
// owns the annotation key on obj.
func annotationOwnedByOthers(obj metav1.Object, key string) bool {
	for _, mf := range obj.GetManagedFields() {
		if mf.Manager == FieldOwner || mf.FieldsV1 == nil {
			continue
		}
		var fields struct {
			Metadata struct {
				Annotations map[string]json.RawMessage `json:"f:annotations"`
			} `json:"f:metadata"`
		}
		if json.Unmarshal(mf.FieldsV1.Raw, &fields) != nil {
			continue
		}
		if _, ok := fields.Metadata.Annotations["f:"+key]; ok {
			return true
		}
	}
	return false
}

// syncClaimAnnotation moves the Service's claim annotation to want, unless
// another field manager owns it: cozyplane changes and removes only what it
// wrote. A foreign annotation stays when want is empty (the address-controller's
// auto-claim sets one on a Service that names no claim); replace reports that
// want names a different claim, which the Service can carry only if it is
// replaced.
func syncClaimAnnotation(svc *corev1.Service, want string) (changed, replace bool) {
	cur := svc.Annotations[addressClaimAnnotation]
	if cur == want {
		return false, false
	}
	if cur != "" && annotationOwnedByOthers(svc, addressClaimAnnotation) {
		return false, want != ""
	}
	return reconcileClaimAnnotation(svc, want), false
}
