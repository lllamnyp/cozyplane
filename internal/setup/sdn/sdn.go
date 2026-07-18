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
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/claim"
	floatingipstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/floatingip"
	hostfirewallstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/hostfirewall"
	portstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/port"
	securitygroupstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/securitygroup"
	servicevipstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/servicevip"
	vpcstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpc"
	vpcbindingstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcbinding"
	vpcgatewaystorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcgateway"
	vpcpeeringstorage "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcpeering"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
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

// APIGroupInfo builds the APIGroupInfo for the sdn API group. auth is the
// delegated authorizer, consumed by the strategies that enforce the virtual
// VPC verbs (export on VPCBinding, peer on VPCPeering) — aggregated-API
// requests bypass kube-apiserver admission, so the CRD-mode
// ValidatingAdmissionPolicies cannot cover this server.
func APIGroupInfo(scheme *runtime.Scheme, codec serializer.CodecFactory, restOptionsGetter genericregistry.RESTOptionsGetter, auth authorizer.Authorizer) *genericapiserver.APIGroupInfo {
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(sdn.GroupName, scheme, metav1.ParameterCodec, codec)

	vpcREST, vpcStatusREST, err := vpcstorage.NewREST(scheme, restOptionsGetter)
	if err != nil {
		panic(err)
	}
	vpcGatewayREST, vpcGatewayStatusREST, err := vpcgatewaystorage.NewREST(scheme, restOptionsGetter)
	if err != nil {
		panic(err)
	}
	vpcPeeringREST, vpcPeeringStatusREST, err := vpcpeeringstorage.NewREST(scheme, restOptionsGetter, auth)
	if err != nil {
		panic(err)
	}
	floatingIPREST, floatingIPStatusREST, err := floatingipstorage.NewREST(scheme, restOptionsGetter)
	if err != nil {
		panic(err)
	}
	// Ports and ServiceVIPs cross-check each other's address claims at create
	// (services-in-vpc.md, "VIP allocation" layer 2). The twin handles are
	// late-bound: both stores must exist before either can look the other up.
	portTwin, vipTwin := &claim.Twin{}, &claim.Twin{}
	serviceVIPREST, serviceVIPStatusREST, err := servicevipstorage.NewREST(scheme, restOptionsGetter, vipTwin)
	if err != nil {
		panic(err)
	}
	portREST, portStatusREST, err := portstorage.NewREST(scheme, restOptionsGetter, portTwin)
	if err != nil {
		panic(err)
	}
	portTwin.Exists = claim.StoreExists(serviceVIPREST.Store)
	vipTwin.Exists = claim.StoreExists(portREST.Store)
	securityGroupREST, securityGroupStatusREST, err := securitygroupstorage.NewREST(scheme, restOptionsGetter)
	if err != nil {
		panic(err)
	}
	hostFirewallREST, hostFirewallStatusREST, err := hostfirewallstorage.NewREST(scheme, restOptionsGetter)
	if err != nil {
		panic(err)
	}

	v1alpha1storage := map[string]rest.Storage{}
	v1alpha1storage["vpcs"] = vpcREST
	v1alpha1storage["vpcs/status"] = vpcStatusREST
	v1alpha1storage["ports"] = portREST
	v1alpha1storage["ports/status"] = portStatusREST
	v1alpha1storage["vpcbindings"] = defaultregistry.RESTInPeace(vpcbindingstorage.NewREST(scheme, restOptionsGetter, auth))
	v1alpha1storage["vpcgateways"] = vpcGatewayREST
	v1alpha1storage["vpcgateways/status"] = vpcGatewayStatusREST
	v1alpha1storage["vpcpeerings"] = vpcPeeringREST
	v1alpha1storage["vpcpeerings/status"] = vpcPeeringStatusREST
	v1alpha1storage["floatingips"] = floatingIPREST
	v1alpha1storage["floatingips/status"] = floatingIPStatusREST
	v1alpha1storage["servicevips"] = serviceVIPREST
	v1alpha1storage["servicevips/status"] = serviceVIPStatusREST
	v1alpha1storage["securitygroups"] = securityGroupREST
	v1alpha1storage["securitygroups/status"] = securityGroupStatusREST
	v1alpha1storage["hostfirewalls"] = hostFirewallREST
	v1alpha1storage["hostfirewalls/status"] = hostFirewallStatusREST
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	return &apiGroupInfo
}
