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

// Package claim wires the cross-kind address-claim check between the Port and
// ServiceVIP registries: a create is rejected when its twin name (the same
// <vni>.<ip> claim under the other kind's prefix) already exists. See
// services-in-vpc.md, "VIP allocation" layer 2.
package claim

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
)

// Twin is a late-bound handle to the other claim kind's storage: the Port
// registry checks ServiceVIPs and vice versa. Both stores must exist before
// either handle can be filled, so the field is set after construction (see
// internal/setup/sdn).
type Twin struct {
	// Exists reports whether the twin claim name is already taken. A create
	// fails closed on a lookup error.
	Exists func(ctx context.Context, name string) (bool, error)
}

// StoreExists adapts a registry store into a Twin.Exists func.
func StoreExists(store *genericregistry.Store) func(ctx context.Context, name string) (bool, error) {
	return func(ctx context.Context, name string) (bool, error) {
		if _, err := store.Get(ctx, name, &metav1.GetOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
}

// FinishNothing is the no-op FinishFunc for BeginCreate hooks that only gate.
func FinishNothing(context.Context, bool) {}
