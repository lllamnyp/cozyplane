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
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/setup"
	sdnsetup "github.com/lllamnyp/cozyplane/internal/setup/sdn"
	"github.com/lllamnyp/cozyplane/internal/version"
	"github.com/lllamnyp/cozyplane/pkg/apiserver"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/util/compatibility"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	basecompatibility "k8s.io/component-base/compatibility"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register" // register JSON log format for --logging-format=json
	baseversion "k8s.io/component-base/version"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/spec3"
	"k8s.io/kube-openapi/pkg/util"
	"k8s.io/kube-openapi/pkg/validation/spec"
	netutils "k8s.io/utils/net"
)

const defaultEtcdPathPrefix = "/registry/cozystack.io"

// CozyplaneServerOptions contains state for the cozyplane aggregated API server.
type CozyplaneServerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions
	// ComponentGlobalsRegistry stores effective versions and feature gates for all components.
	ComponentGlobalsRegistry basecompatibility.ComponentGlobalsRegistry

	// Logging holds the --logging-format / --v / --vmodule configuration.
	// Defaults to JSON so logs are structured for shipping.
	Logging *logsapi.LoggingConfiguration

	StdOut io.Writer
	StdErr io.Writer

	AlternateDNS []string

	ServeSDN bool

	// EnsureAPIServiceService ("namespace/name", empty = off) makes the server
	// register/take over the group's APIService at startup, pointed at that
	// Service. EnsureAPIServiceCAInjection ("namespace/certificate") adds the
	// cert-manager cainjector annotation. See EnsureAPIService for why this is
	// done here and not in a chart manifest.
	EnsureAPIServiceService     string
	EnsureAPIServiceCAInjection string
	// EnsureAPIServiceInsecureSkipTLS registers the APIService with
	// insecureSkipTLSVerify — for installs where the server self-signs its
	// serving cert (dev, CI). Production injects a CA instead.
	EnsureAPIServiceInsecureSkipTLS bool
	// RemoveBootstrapCRDs deletes leftover CRDs for this group. Since the
	// API-group split the group has none; this only cleans up clusters
	// installed before it (docs/api-groups.md).
	RemoveBootstrapCRDs bool
}

// NewCozyplaneServerOptions returns a new CozyplaneServerOptions.
func NewCozyplaneServerOptions(out, errOut io.Writer) *CozyplaneServerOptions {
	o := &CozyplaneServerOptions{
		RecommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(sdnv1alpha1.SchemeGroupVersion),
		),
		ComponentGlobalsRegistry: compatibility.DefaultComponentGlobalsRegistry,
		Logging:                  defaultLoggingConfiguration(),
		StdOut:                   out,
		StdErr:                   errOut,
		ServeSDN:                 true,
		RemoveBootstrapCRDs:      true,
	}

	return o
}

// defaultLoggingConfiguration returns a LoggingConfiguration defaulting to JSON.
func defaultLoggingConfiguration() *logsapi.LoggingConfiguration {
	c := logsapi.NewLoggingConfiguration()
	c.Format = logsapi.JSONLogFormat

	return c
}

// NewCommandStartCozyplaneServer provides a CLI handler for the apiserver.
func NewCommandStartCozyplaneServer(ctx context.Context, defaults *CozyplaneServerOptions, skipDefaultComponentGlobalsRegistrySet bool) *cobra.Command {
	o := *defaults
	cmd := &cobra.Command{
		Short:   "Launch the cozyplane API server",
		Long:    "Launch the cozyplane aggregated API server",
		Version: version.String(),
		PersistentPreRunE: func(*cobra.Command, []string) error {
			if err := logsapi.ValidateAndApply(o.Logging, nil); err != nil {
				return err
			}

			if skipDefaultComponentGlobalsRegistrySet {
				return nil
			}

			return defaults.ComponentGlobalsRegistry.Set()
		},
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}

			if err := o.Validate(args); err != nil {
				return err
			}

			return o.RunCozyplaneServer(c.Context())
		},
	}
	cmd.SetContext(ctx)

	flags := cmd.Flags()
	o.RecommendedOptions.AddFlags(flags)
	logsapi.AddFlags(o.Logging, flags)

	flags.BoolVar(&o.ServeSDN, "serve-sdn", o.ServeSDN, "Serve the sdn.cozystack.io API group from this server.")
	flags.StringVar(&o.EnsureAPIServiceService, "ensure-apiservice-service", o.EnsureAPIServiceService,
		"namespace/name of this server's Service; when set, register (or take over from CRD autoregistration) the group's APIService pointing at it.")
	flags.BoolVar(&o.EnsureAPIServiceInsecureSkipTLS, "ensure-apiservice-insecure-skip-tls-verify", o.EnsureAPIServiceInsecureSkipTLS,
		"Register the APIService with insecureSkipTLSVerify (the server self-signs its serving cert; dev/CI only).")
	flags.BoolVar(&o.RemoveBootstrapCRDs, "remove-bootstrap-crds", o.RemoveBootstrapCRDs,
		"After taking the group over, delete the CRDs that bootstrapped it. Leaving them "+
			"installed makes OpenAPI for the group fail to merge (duplicated paths), which "+
			"breaks client-side validation for every object in it.")
	flags.StringVar(&o.EnsureAPIServiceCAInjection, "ensure-apiservice-ca-injection", o.EnsureAPIServiceCAInjection,
		"namespace/certificate for the cert-manager.io/inject-ca-from annotation on the ensured APIService.")

	// Register the default kube component if not already present in the global registry.
	_, _ = defaults.ComponentGlobalsRegistry.ComponentGlobalsOrRegister(basecompatibility.DefaultKubeComponent,
		basecompatibility.NewEffectiveVersionFromString(baseversion.DefaultKubeBinaryVersion, "", ""), utilfeature.DefaultMutableFeatureGate)

	apiserver.Init()

	defaults.ComponentGlobalsRegistry.AddFlags(flags)

	return cmd
}

// Validate validates CozyplaneServerOptions.
func (o CozyplaneServerOptions) Validate(args []string) error {
	errs := []error{}
	errs = append(errs, o.RecommendedOptions.Validate()...)
	errs = append(errs, o.ComponentGlobalsRegistry.Validate()...)

	return utilerrors.NewAggregate(errs)
}

// Complete fills in fields required to have valid data.
func (o *CozyplaneServerOptions) Complete() error {
	if o.ServeSDN {
		sdnsetup.InstallScheme(apiserver.Scheme)
	}

	return nil
}

// Config returns config for the api server given CozyplaneServerOptions.
func (o *CozyplaneServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", o.AlternateDNS, []net.IP{netutils.ParseIPSloppy("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %w", err)
	}

	o.RecommendedOptions.ExtraAdmissionInitializers = func(*genericapiserver.RecommendedConfig) ([]admission.PluginInitializer, error) {
		return []admission.PluginInitializer{}, nil
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)

	var openAPIDefinitionGetters []common.GetOpenAPIDefinitions
	if o.ServeSDN {
		openAPIDefinitionGetters = append(openAPIDefinitionGetters, sdnsetup.GetOpenAPIDefinitions)
	}

	getAllOpenAPIDefinitions := setup.MergeOpenAPIDefinitions(openAPIDefinitionGetters...)

	v2Config, v3Config := buildOpenAPIConfigs(getAllOpenAPIDefinitions, apiserver.Scheme)
	v2Config.Info = &spec.Info{InfoProps: spec.InfoProps{Title: "Cozyplane", Version: "0.1"}}
	v3Config.Info = &spec.Info{InfoProps: spec.InfoProps{Title: "Cozyplane", Version: "0.1"}}
	serverConfig.OpenAPIConfig = v2Config
	serverConfig.OpenAPIV3Config = v3Config

	serverConfig.FeatureGate = o.ComponentGlobalsRegistry.FeatureGateFor(basecompatibility.DefaultKubeComponent)
	serverConfig.EffectiveVersion = o.ComponentGlobalsRegistry.EffectiveVersionFor(basecompatibility.DefaultKubeComponent)

	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			ServeSDN: o.ServeSDN,
		},
	}

	return config, nil
}

// RunCozyplaneServer starts a new CozyplaneServer given CozyplaneServerOptions.
func (o CozyplaneServerOptions) RunCozyplaneServer(ctx context.Context) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New()
	if err != nil {
		return err
	}

	server.GenericAPIServer.AddPostStartHookOrDie("start-cozyplane-informers", func(hookCtx genericapiserver.PostStartHookContext) error {
		config.GenericConfig.SharedInformerFactory.Start(hookCtx.Done())

		return nil
	})

	if o.EnsureAPIServiceService != "" {
		svcNS, svcName, err := splitServiceRef(o.EnsureAPIServiceService)
		if err != nil {
			return fmt.Errorf("--ensure-apiservice-service: %w", err)
		}
		clientConfig := config.GenericConfig.ClientConfig
		removeCRDs := o.RemoveBootstrapCRDs
		server.GenericAPIServer.AddPostStartHookOrDie("ensure-apiservice", func(hookCtx genericapiserver.PostStartHookContext) error {
			if err := EnsureAPIService(hookCtx, clientConfig, svcNS, svcName, o.EnsureAPIServiceCAInjection, o.EnsureAPIServiceInsecureSkipTLS); err != nil {
				return err
			}
			if !removeCRDs {
				return nil
			}
			// The handoff is only complete once the bootstrap CRDs are gone:
			// they keep publishing OpenAPI paths for a group we now serve, and
			// the merge collision kills the group's schema (see
			// RemoveBootstrapCRDs).
			return RemoveBootstrapCRDs(hookCtx, clientConfig, sdnPlurals)
		})
	}

	return server.GenericAPIServer.PrepareRun().RunWithContext(ctx)
}

// buildOpenAPIConfigs constructs V2 and V3 OpenAPI configs with consistent
// REST-friendly definition naming for both keys and $ref values.
func buildOpenAPIConfigs(getAllDefinitions common.GetOpenAPIDefinitions, scheme *runtime.Scheme) (*common.Config, *common.OpenAPIV3Config) {
	defNamer := openapi.NewDefinitionNamer(scheme)
	restFriendlyName := restFriendlyDefinitionName(defNamer)

	return &common.Config{
			ProtocolList:   []string{"https"},
			IgnorePrefixes: []string{},
			DefaultResponse: &spec.Response{
				ResponseProps: spec.ResponseProps{
					Description: "Default Response.",
				},
			},
			GetOperationIDAndTags: openapi.GetOperationIDAndTags,
			GetDefinitionName:     restFriendlyName,
			GetDefinitions:        getAllDefinitions,
		}, &common.OpenAPIV3Config{
			IgnorePrefixes: []string{},
			DefaultResponse: &spec3.Response{
				ResponseProps: spec3.ResponseProps{
					Description: "Default Response.",
				},
			},
			GetOperationIDAndTags: openapi.GetOperationIDAndTags,
			GetDefinitionName:     restFriendlyName,
			GetDefinitions:        getAllDefinitions,
		}
}

// restFriendlyDefinitionName wraps a DefinitionNamer to produce slash-free
// definition names while preserving x-kubernetes-group-version-kind extensions.
func restFriendlyDefinitionName(defNamer *openapi.DefinitionNamer) func(string) (string, spec.Extensions) {
	return func(name string) (string, spec.Extensions) {
		friendly := util.ToRESTFriendlyName(name)
		_, ext := defNamer.GetDefinitionName(friendly)

		return friendly, ext
	}
}
