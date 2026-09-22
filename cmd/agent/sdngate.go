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
	"context"
	"fmt"
	"log/slog"

	"github.com/go-logr/logr"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/apigate"
)

// sdnGatePollInterval is how often an absent sdn.cozystack.io group is
// re-probed. It matches cmd/sdn-controller's: discovery for an aggregated group
// is a proxied round-trip, the wait is minutes long, and nobody is watching the
// seconds. A variable so tests can drive the loop without waiting on it.
var sdnGatePollInterval = apigate.DefaultInterval

// sdnGateResources are the sdn.cozystack.io kinds this agent's informers watch.
// Requiring the resource list (rather than merely the group) keeps a
// half-registered apiserver — group advertised, registries not installed — from
// opening the gate.
var sdnGateResources = []string{
	"vpcs", "vpcgateways", "vpcpeerings", "ports",
	"floatingips", "servicevips", "securitygroups", "hostfirewalls",
}

// gateSDNInformers defers starting the agent's sdn.cozystack.io informers until
// discovery says the group is actually served, then calls register once.
//
// Running the informers against an absent group is not fatal — the reflectors
// retry and the datapath is unaffected, which is why the agent starts them
// best-effort — but each of the eight kinds logs its own "failed to list
// *v1alpha1.X: the server could not find the requested resource" every few
// seconds. On a fresh install that window lasts as long as it takes
// cert-manager, etcd, a StorageClass and the aggregated apiserver to land, and
// those are ordinary pods that need this agent's CNI first. The result is a
// per-kind error stream through the exact window an operator is reading the
// agent's logs to diagnose something else.
//
// The gate turns that into one line: the group is not served yet, retrying.
// It mirrors what cmd/sdn-controller does with the same apigate.Gate, for the
// same group and the same reason (internal/apigate).
//
// It returns only on a wiring failure; the polling itself runs in the
// background, because nothing in agent startup — least of all the CNI
// configuration that admits pod ADDs — may wait on this group.
func gateSDNInformers(ctx context.Context, cfg *rest.Config, register func(context.Context) error, log *slog.Logger) error {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return fmt.Errorf("discovery client: %w", err)
	}

	startSDNGate(ctx, &apigate.DiscoveryProber{
		Client:    discoveryClient,
		GV:        sdnv1alpha1.SchemeGroupVersion,
		Resources: sdnGateResources,
	}, register, log)
	return nil
}

// startSDNGate runs the gate in the background. It must return to its caller
// immediately: agent startup continues past it to install the CNI
// configuration, which is what admits pod ADDs.
func startSDNGate(ctx context.Context, prober apigate.Prober, register func(context.Context) error, log *slog.Logger) {
	gate := &apigate.Gate{
		Name:     sdnv1alpha1.SchemeGroupVersion.String(),
		Prober:   prober,
		Register: register,
		Interval: sdnGatePollInterval,
		Log:      logr.FromSlogHandler(log.Handler()).WithName("sdngate"),
	}

	go func() {
		// Start only returns on ctx cancellation or a register failure, and
		// register here never fails (the watches log their own errors).
		if err := gate.Start(ctx); err != nil {
			log.Error("sdn api gate stopped", "err", err)
		}
	}()
}
