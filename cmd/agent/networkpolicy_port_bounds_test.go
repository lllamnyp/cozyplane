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

package main

import (
	"math"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

func TestNetworkPolicyExplicitPortsFailClosed(t *testing.T) {
	for _, port := range []int{-1, 0, 65536, 65537, math.MaxInt32} {
		var warns []string
		got := npCompilePorts("test", []networkingv1.NetworkPolicyPort{{Port: ptrIntOrString(port)}}, &warns)
		if len(got) != 0 || len(warns) == 0 {
			t.Fatalf("invalid port %d compiled to %v warnings %v", port, got, warns)
		}
	}
	end := int32(80)
	var warns []string
	if got := npCompilePorts("test", []networkingv1.NetworkPolicyPort{{EndPort: &end}}, &warns); len(got) != 0 || len(warns) == 0 {
		t.Fatalf("endPort without start became wildcard: %v %v", got, warns)
	}
}
