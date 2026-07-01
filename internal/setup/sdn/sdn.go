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
	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnopenapi "github.com/lllamnyp/cozyplane/pkg/generated/sdn/openapi"
	defaultregistry "github.com/lllamnyp/cozyplane/pkg/registry"
	portstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/port"
	vpcstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpc"
	vpcbindingstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcbinding"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericregistry "k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/kube-openapi/pkg/common"
)

// InstallScheme installs the sdn API group types into the given scheme.
func InstallScheme(scheme *runtime.Scheme) {
	install.Install(scheme)
}

// GetOpenAPIDefinitions returns the OpenAPI definitions for the sdn API group.
func GetOpenAPIDefinitions(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition {
	return sdnopenapi.GetOpenAPIDefinitions(ref)
}

// APIGroupInfo builds the APIGroupInfo for the sdn API group.
func APIGroupInfo(scheme *runtime.Scheme, codec serializer.CodecFactory, restOptionsGetter genericregistry.RESTOptionsGetter) *genericapiserver.APIGroupInfo {
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(sdn.GroupName, scheme, metav1.ParameterCodec, codec)

	vpcREST, vpcStatusREST, err := vpcstorage.NewREST(scheme, restOptionsGetter)
	if err != nil {
		panic(err)
	}

	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["vpcs"] = vpcREST
	v1alpha1storage["vpcs/status"] = vpcStatusREST
	v1alpha1storage["ports"] = defaultregistry.RESTInPeace(portstorage.NewREST(scheme, restOptionsGetter))
	v1alpha1storage["vpcbindings"] = defaultregistry.RESTInPeace(vpcbindingstorage.NewREST(scheme, restOptionsGetter))
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	return &apiGroupInfo
}
