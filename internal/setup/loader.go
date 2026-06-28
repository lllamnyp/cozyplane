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

package setup

import (
	"maps"
	"time"

	"k8s.io/kube-openapi/pkg/common"
)

// DefaultInformerResyncPeriod is the resync interval passed to every
// SharedInformerFactory built for the cozyplane apiserver. It is a default
// relist cadence to resurface drift, not a request timeout.
const DefaultInformerResyncPeriod = 5 * time.Minute

// MergeOpenAPIDefinitions merges multiple OpenAPI definition getters into a single getter.
func MergeOpenAPIDefinitions(getters ...common.GetOpenAPIDefinitions) common.GetOpenAPIDefinitions {
	return func(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition {
		allDefinitions := make(map[string]common.OpenAPIDefinition)

		for _, getter := range getters {
			if getter == nil {
				continue
			}

			maps.Copy(allDefinitions, getter(ref))
		}

		return allDefinitions
	}
}
