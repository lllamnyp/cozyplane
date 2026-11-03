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
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/orggateway"
)

type orgGatewayRecorder struct {
	calls []map[uint32][]netip.Addr
	fail  bool
}

func (r *orgGatewayRecorder) SyncOrgGateways(want map[uint32][]netip.Addr, _ map[netip.AddrPort]netip.AddrPort) error {
	r.calls = append(r.calls, want)
	if r.fail && want != nil {
		return errors.New("desired state exceeds map capacity 16384")
	}
	return nil
}

func TestDesiredOrgGatewaysKeysEachVPCNetwork(t *testing.T) {
	cfg := orggateway.Config{
		Enabled: true, GatewayLabel: "gw", ApexLabel: "host", ServiceSelector: map[string]string{"owner": orggateway.NamespacePlaceholder},
		AddressCIDRs: []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}, ApexSuffixes: []string{"example.test"},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-org", Labels: map[string]string{"gw": "tenant-org"}}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-org", Name: "envoy-tenant-org", Labels: map[string]string{"owner": "tenant-org"}}}
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.240.0.5"}}
	vpc := func(ns string, vni int32) *sdnv1alpha1.VPC {
		v := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vpc"}}
		v.Status.VNI = vni
		return v
	}
	deleting := vpc("tenant-org", 103)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	got := desiredOrgGateways(cfg, []*sdnv1alpha1.VPC{vpc("tenant-org", 101), vpc("tenant-org", 0), vpc("tenant-other", 102), deleting},
		func(name string) *corev1.Namespace {
			if name == ns.Name {
				return ns
			}
			return nil
		}, []*corev1.Service{svc})
	if len(got) != 1 || len(got[101]) != 1 || got[101][0] != netip.MustParseAddr("10.240.0.5") {
		t.Fatalf("got %v, want only VNI 101 -> 10.240.0.5", got)
	}
}

func TestSyncOrgGatewaysFailsClosed(t *testing.T) {
	sink := &orgGatewayRecorder{fail: true}
	syncOrgGateways(sink, map[uint32][]netip.Addr{101: {netip.MustParseAddr("10.240.0.5")}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(sink.calls) != 2 || sink.calls[1] != nil {
		t.Fatalf("an unprogrammable snapshot must clear the map, calls=%v", sink.calls)
	}
}
