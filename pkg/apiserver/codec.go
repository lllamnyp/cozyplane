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

package apiserver

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// JSONCodecFactory wraps a CodecFactory and excludes protobuf from content
// negotiation. Use this for API groups whose types don't implement the
// protobuf marshalling interface (i.e. lack protobuf struct tags and
// generated Marshal/Unmarshal methods).
//
// Without this wrapper the aggregation proxy's Accept header
// ("application/vnd.kubernetes.protobuf, application/json") causes the
// apiserver to pick the protobuf serializer, which then fails at runtime
// with "does not implement the protobuf marshalling interface".
type JSONCodecFactory struct {
	serializer.CodecFactory
}

// SupportedMediaTypes returns only JSON and YAML serializers,
// filtering out protobuf so content negotiation falls back to JSON.
func (f JSONCodecFactory) SupportedMediaTypes() []runtime.SerializerInfo {
	all := f.CodecFactory.SupportedMediaTypes()
	filtered := make([]runtime.SerializerInfo, 0, len(all))

	for _, info := range all {
		if info.MediaType != runtime.ContentTypeProtobuf {
			filtered = append(filtered, info)
		}
	}

	return filtered
}
