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
	"crypto/tls"
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	localsdnctrl "github.com/lllamnyp/cozyplane/internal/controller/localsdn"
	sdncontroller "github.com/lllamnyp/cozyplane/internal/controller/sdn"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sdnv1alpha1.AddToScheme(scheme))
	utilruntime.Must(localv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		enableLeaderElection bool
		probeAddr            string
		secureMetrics        bool
		enableHTTP2          bool
		gatewayImage         string
		gatewayNamespace     string
		internalCIDRs        string
		clusterDNS           string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
	flag.StringVar(&gatewayImage, "gateway-image", "",
		"cozyplane image for VPC egress gateway pods; empty disables gateway reconciliation")
	flag.StringVar(&gatewayNamespace, "gateway-namespace", os.Getenv("POD_NAMESPACE"),
		"system namespace for gateway Deployments (must match the agents' namespace; defaults to POD_NAMESPACE)")
	flag.StringVar(&internalCIDRs, "internal-cidrs", "",
		"comma-separated cluster-internal CIDRs gateways must not forward tenant traffic to (pod, service, node networks)")
	flag.StringVar(&clusterDNS, "cluster-dns", "",
		"cluster DNS ClusterIP gateways allow on :53")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	var tlsOpts []func(*tls.Config)
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			setupLog.Info("disabling http/2")

			c.NextProtos = []string{"http/1.1"}
		})
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "sdn-controller.cozystack.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// VNI allocation must read live, never the lagging informer cache —
		// a stale read hands two VPCs the same network id (isolation break).
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPC")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCBindingReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPCBinding")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCPeeringReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPCPeering")
		os.Exit(1)
	}

	if err := (&sdncontroller.PortGCReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// Claimant-gone checks confirm against the API server directly — a
		// stale cache read must not GC a just-created pod's newborn Port.
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PortGC")
		os.Exit(1)
	}

	if err := (&sdncontroller.FloatingIPReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FloatingIP")
		os.Exit(1)
	}

	if err := (&sdncontroller.PersistentPortReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PersistentPort")
		os.Exit(1)
	}

	if err := (&sdncontroller.ServiceVIPReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ServiceVIP")
		os.Exit(1)
	}

	if err := (&sdncontroller.SecurityGroupReconciler{
		Client: mgr.GetClient(),
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecurityGroup")
		os.Exit(1)
	}

	if err := (&sdncontroller.PortMembershipReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PortMembership")
		os.Exit(1)
	}

	if gatewayImage != "" {
		if gatewayNamespace == "" {
			setupLog.Error(nil, "--gateway-namespace (or POD_NAMESPACE) is required with --gateway-image")
			os.Exit(1)
		}
		if err := (&sdncontroller.GatewayReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Config: sdncontroller.GatewayConfig{
				Image:         gatewayImage,
				Namespace:     gatewayNamespace,
				InternalCIDRs: internalCIDRs,
				ClusterDNS:    clusterDNS,
			},
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Gateway")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting sdn-controller")

	// The local layer's GC: reclaim underlay addresses whose pod is gone
	// (docs/api-groups.md). It reconciles a CRD-served kind, so it works on a
	// cluster with no aggregated apiserver at all.
	if err := (&localsdnctrl.FabricIPReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricIP")
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
