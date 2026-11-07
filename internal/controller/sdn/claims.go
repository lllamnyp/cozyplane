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

// keepAutoClaim is the claim annotation a Service should carry: claim, or, when
// claim is empty, the claim the address-controller's auto-claim
// created for this Service (one it controls), so the platform's auto-claim
// policy applies to cozyplane's Services too.
func keepAutoClaim(ctx context.Context, rd client.Reader, svc *corev1.Service, claim string) string {
	cur := svc.Annotations[addressClaimAnnotation]
	if claim != "" || cur == "" {
		return claim
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ipAddressClaimGVK)
	if err := rd.Get(ctx, types.NamespacedName{Namespace: svc.Namespace, Name: cur}, u); err != nil {
		return claim
	}
	if c := metav1.GetControllerOf(u); c != nil && c.UID == svc.UID {
		return cur
	}
	return claim
}
