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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func gwObj(ns, name, vpc string, lb bool, age time.Duration) *sdnv1alpha1.VPCGateway {
	return &sdnv1alpha1.VPCGateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			CreationTimestamp: metav1.NewTime(time.Unix(1000, 0).Add(age)),
		},
		Spec: sdnv1alpha1.VPCGatewaySpec{
			VPCRef:  sdnv1alpha1.LocalVPCRef{Name: vpc},
			Ingress: sdnv1alpha1.VPCGatewayIngress{LoadBalancer: lb},
		},
	}
}

func vpcObj(ns, name string, vni int32) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

// Tenet 7: nothing crosses by default. A VPC only admits LoadBalancer ingress if
// its own boundary says so — a Service cannot open a door into a tenant's VPC.
func TestDesiredVPCIngress(t *testing.T) {
	vpcs := []*sdnv1alpha1.VPC{
		vpcObj("team-a", "open", 101),   // gateway admits LB
		vpcObj("team-a", "closed", 102), // gateway, but LB not admitted
		vpcObj("team-a", "nodoor", 103), // no gateway at all
		vpcObj("team-b", "open", 104),   // same VPC name, other namespace
	}
	gws := []*sdnv1alpha1.VPCGateway{
		gwObj("team-a", "door", "open", true, 0),
		gwObj("team-a", "door", "closed", false, 0),
		gwObj("team-b", "door", "open", true, 0),
	}
	got := desiredVPCIngress(gws, vpcs)
	if !got[101] {
		t.Error("a VPC whose gateway admits LB must be open")
	}
	if got[102] {
		t.Error("a VPC whose gateway does NOT admit LB must stay closed")
	}
	if got[103] {
		t.Error("a VPC with NO gateway must stay closed — that is the default")
	}
	if !got[104] {
		t.Error("gateways must resolve per namespace")
	}
}

// A VPC's boundary is its OLDEST gateway. A second gateway cannot open a door the
// first one left shut — otherwise "one boundary per VPC" is not a property, and a
// tenant could bypass its own closed door by creating another.
func TestDesiredVPCIngressOldestWins(t *testing.T) {
	vpcs := []*sdnv1alpha1.VPC{vpcObj("team-a", "va", 101)}

	shutFirst := []*sdnv1alpha1.VPCGateway{
		gwObj("team-a", "original", "va", false, 0),
		gwObj("team-a", "sneaky", "va", true, time.Hour), // newer, tries to open
	}
	if desiredVPCIngress(shutFirst, vpcs)[101] {
		t.Error("a newer gateway must not open a door the VPC's real boundary left shut")
	}

	openFirst := []*sdnv1alpha1.VPCGateway{
		gwObj("team-a", "original", "va", true, 0),
		gwObj("team-a", "later", "va", false, time.Hour),
	}
	if !desiredVPCIngress(openFirst, vpcs)[101] {
		t.Error("a newer gateway must not close the real boundary's door either")
	}
}
