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

package sdn_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/floatingip"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/hostfirewall"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/natgateway"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/port"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/portclaim"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/route"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/routetable"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/securitygroup"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/servicevip"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpc"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcbinding"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcgateway"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcpeering"
)

type preparer interface {
	PrepareForCreate(context.Context, runtime.Object)
	PrepareForUpdate(context.Context, runtime.Object, runtime.Object)
}

type object interface {
	runtime.Object
	metav1.Object
}

type updateCase struct {
	name   string
	s      preparer
	mutate func(runtime.Object)
	want   int64
}

var cond = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}

// TestGeneration checks every kind's strategies keep metadata.generation the way
// the built-in registries do: 1 on create, +1 on a spec change, untouched by
// anything else.
func TestGeneration(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	fip := floatingip.NewStrategy(scheme)
	hf := hostfirewall.NewStrategy(scheme)
	ngw := natgateway.NewStrategy(scheme)
	p := port.NewStrategy(scheme)
	pc := portclaim.NewStrategy(scheme)
	rt := route.NewStrategy(scheme)
	tbl := routetable.NewStrategy(scheme)
	sg := securitygroup.NewStrategy(scheme)
	svip := servicevip.NewStrategy(scheme)
	v := vpc.NewStrategy(scheme)
	gw := vpcgateway.NewStrategy(scheme)
	peer := vpcpeering.NewStrategy(scheme, nil)

	kinds := []struct {
		name     string
		strategy preparer
		status   preparer // nil: the kind has no /status
		obj      object
		spec     func(runtime.Object)
		setState func(runtime.Object)
	}{
		{"FloatingIP", fip, floatingip.NewStatusStrategy(fip), &sdn.FloatingIP{},
			func(o runtime.Object) { o.(*sdn.FloatingIP).Spec.Target = "10.0.0.6" },
			func(o runtime.Object) { o.(*sdn.FloatingIP).Status.Phase = sdn.FloatingIPPhaseReady }},
		{"HostFirewall", hf, hostfirewall.NewStatusStrategy(hf), &sdn.HostFirewall{},
			func(o runtime.Object) {
				o.(*sdn.HostFirewall).Spec.PolicyTypes = []sdn.HostFirewallPolicyType{"Ingress"}
			},
			func(o runtime.Object) { o.(*sdn.HostFirewall).Status.Conditions = cond }},
		{"NATGateway", ngw, natgateway.NewStatusStrategy(ngw), &sdn.NATGateway{},
			func(o runtime.Object) { o.(*sdn.NATGateway).Spec.AddressClaimName = "c" },
			func(o runtime.Object) { o.(*sdn.NATGateway).Status.Conditions = cond }},
		{"Port", p, port.NewStatusStrategy(p), &sdn.Port{},
			func(o runtime.Object) { o.(*sdn.Port).Spec.Node = "node-2" },
			func(o runtime.Object) { o.(*sdn.Port).Status.Groups = []int32{1} }},
		{"PortClaim", pc, portclaim.NewStatusStrategy(pc), &sdn.PortClaim{},
			func(o runtime.Object) { o.(*sdn.PortClaim).Spec.IP = "10.0.0.6" },
			func(o runtime.Object) { o.(*sdn.PortClaim).Status.Conditions = cond }},
		{"Route", rt, route.NewStatusStrategy(rt), &sdn.Route{},
			func(o runtime.Object) { o.(*sdn.Route).Spec.Destination = "0.0.0.0/0" },
			func(o runtime.Object) { o.(*sdn.Route).Status.Conditions = cond }},
		{"RouteTable", tbl, routetable.NewStatusStrategy(tbl), &sdn.RouteTable{},
			func(o runtime.Object) { o.(*sdn.RouteTable).Spec.Default = true },
			func(o runtime.Object) { o.(*sdn.RouteTable).Status.Conditions = cond }},
		{"SecurityGroup", sg, securitygroup.NewStatusStrategy(sg), &sdn.SecurityGroup{},
			func(o runtime.Object) { o.(*sdn.SecurityGroup).Spec.VPCRef.Name = "vpc-b" },
			func(o runtime.Object) { o.(*sdn.SecurityGroup).Status.Conditions = cond }},
		{"ServiceVIP", svip, servicevip.NewStatusStrategy(svip), &sdn.ServiceVIP{},
			func(o runtime.Object) { o.(*sdn.ServiceVIP).Spec.SessionAffinity = "ClientIP" },
			func(o runtime.Object) { o.(*sdn.ServiceVIP).Status.Conditions = cond }},
		{"VPC", v, vpc.NewStatusStrategy(v), &sdn.VPC{},
			func(o runtime.Object) { o.(*sdn.VPC).Spec.MTU = 1400 },
			func(o runtime.Object) { o.(*sdn.VPC).Status.Conditions = cond }},
		{"VPCBinding", vpcbinding.NewStrategy(scheme, nil), nil, &sdn.VPCBinding{},
			func(o runtime.Object) { o.(*sdn.VPCBinding).Spec.VPCRef.Name = "vpc-b" },
			nil},
		{"VPCGateway", gw, vpcgateway.NewStatusStrategy(gw), &sdn.VPCGateway{},
			func(o runtime.Object) { o.(*sdn.VPCGateway).Spec.LoadBalancerClass = "lb" },
			func(o runtime.Object) { o.(*sdn.VPCGateway).Status.Conditions = cond }},
		{"VPCPeering", peer, vpcpeering.NewStatusStrategy(peer), &sdn.VPCPeering{},
			func(o runtime.Object) { o.(*sdn.VPCPeering).Spec.PeerRef.Name = "vpc-b" },
			func(o runtime.Object) { o.(*sdn.VPCPeering).Status.Conditions = cond }},
	}

	ctx := context.Background()
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			created := k.obj.DeepCopyObject().(object)
			created.SetName("x")
			created.SetNamespace("team-a")
			created.SetGeneration(7)
			k.strategy.PrepareForCreate(ctx, created)
			if g := created.GetGeneration(); g != 1 {
				t.Fatalf("create: generation = %d, want 1", g)
			}

			// The generic store resets a request's generation to the stored one
			// before PrepareForUpdate, so every update starts from the old value.
			update := func(s preparer, mutate func(runtime.Object)) int64 {
				next := created.DeepCopyObject().(object)
				mutate(next)
				s.PrepareForUpdate(ctx, next, created)
				return next.GetGeneration()
			}
			cases := []updateCase{
				{"spec change bumps", k.strategy, k.spec, 2},
				{"no-op update keeps", k.strategy, func(runtime.Object) {}, 1},
				{"metadata-only update keeps", k.strategy,
					func(o runtime.Object) { o.(object).SetLabels(map[string]string{"a": "b"}) }, 1},
			}
			if k.status != nil {
				cases = append(cases,
					updateCase{"status in a main update keeps", k.strategy, k.setState, 1},
					updateCase{"status update keeps", k.status, k.setState, 1},
					updateCase{"spec in a status update keeps", k.status, k.spec, 1})
			}
			for _, c := range cases {
				if got := update(c.s, c.mutate); got != c.want {
					t.Errorf("%s: generation = %d, want %d", c.name, got, c.want)
				}
			}
		})
	}
}
