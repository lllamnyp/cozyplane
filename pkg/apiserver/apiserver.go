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
	sdnsetup "github.com/lllamnyp/cozyplane/internal/setup/sdn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericapiserver "k8s.io/apiserver/pkg/server"
)

var (
	// Scheme defines methods for serializing and deserializing API objects.
	Scheme = runtime.NewScheme()
	// Codecs provides methods for retrieving codecs and serializers for specific
	// versions and content types.
	Codecs = serializer.NewCodecFactory(Scheme)
)

// Init registers the unversioned meta types the generic apiserver expects.
func Init() {
	// we need to add the options to empty v1
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	// keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	Scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

// ExtraConfig holds custom apiserver config. Add a Serve<Group> toggle here
// when wiring an additional API group, following the sdn pattern.
type ExtraConfig struct {
	ServeSDN bool
}

// Config defines the config for the apiserver.
type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

// CozyplaneServer contains state for the cozyplane aggregated API server.
type CozyplaneServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

// CompletedConfig embeds a private pointer that cannot be instantiated outside of this package.
type CompletedConfig struct {
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (cfg *Config) Complete() CompletedConfig {
	c := completedConfig{
		cfg.GenericConfig.Complete(),
		&cfg.ExtraConfig,
	}

	return CompletedConfig{&c}
}

// New returns a new instance of CozyplaneServer from the given config.
func (c completedConfig) New() (*CozyplaneServer, error) {
	genericServer, err := c.GenericConfig.New("cozyplane-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	s := &CozyplaneServer{
		GenericAPIServer: genericServer,
	}

	// API groups without protobuf support use JSONCodecFactory to avoid
	// "does not implement the protobuf marshalling interface" errors when
	// the aggregation proxy requests protobuf encoding.
	jsonCodecs := JSONCodecFactory{Codecs}

	apiGroupInfos := make([]*genericapiserver.APIGroupInfo, 0, 1)
	if c.ExtraConfig.ServeSDN {
		sdnAPIGroupInfo := sdnsetup.APIGroupInfo(Scheme, Codecs, c.GenericConfig.RESTOptionsGetter, c.GenericConfig.Authorization.Authorizer)
		sdnAPIGroupInfo.NegotiatedSerializer = jsonCodecs
		apiGroupInfos = append(apiGroupInfos, sdnAPIGroupInfo)
	}

	if err := s.GenericAPIServer.InstallAPIGroups(apiGroupInfos...); err != nil {
		return nil, err
	}

	return s, nil
}
