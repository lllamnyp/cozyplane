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
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// applianceGateway is a VPC door pointed at a workload of the tenant's own.
func applianceGateway(ns, name, vpcName string, sel map[string]string) *sdnv1alpha1.VPCGateway {
	gw := natGateway(ns, name, vpcName)
	gw.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{
		PodSelector: metav1.LabelSelector{MatchLabels: sel},
	}
	return gw
}

func appliancePod(ns, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}}
}

// vpcPort is the Port the CNI made when the workload attached to the VPC.
func vpcPort(name, vpcNS, vpcName, podNS, podName string, gateway bool) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				sdnv1alpha1.LabelVPCNamespace: vpcNS,
				sdnv1alpha1.LabelVPC:          vpcName,
			},
		},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef:       sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpcName},
			PodNamespace: podNS,
			PodName:      podName,
			Gateway:      gateway,
		},
	}
}

func portGateway(t *testing.T, c client.Client, name string) bool {
	t.Helper()
	var p sdnv1alpha1.Port
	if err := c.Get(context.Background(), types.NamespacedName{Name: name}, &p); err != nil {
		t.Fatalf("get port %s: %v", name, err)
	}
	return p.Spec.Gateway
}

// The door is a Port flag, and that is the whole mechanism: gateways[vni] is
// built from Ports carrying spec.gateway, so designating an appliance is exactly
// "move that flag onto its Port".
func TestApplianceBecomesTheVPCDoor(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		applianceGateway("team-a", "door", "vpc-a", map[string]string{"app": "fw"}),
		appliancePod("team-a", "fw-1", map[string]string{"app": "fw"}),
		vpcPort("v100.10-10-0-9", "team-a", "vpc-a", "team-a", "fw-1", false),
	)
	gw := reconcileGateway(t, c, "team-a", "door")

	if !portGateway(t, c, "v100.10-10-0-9") {
		t.Error("the appliance's Port was not made the VPC's door")
	}
	if gw.Status.AppliancePort != "v100.10-10-0-9" {
		t.Errorf("status.appliancePort = %q, want the chosen Port", gw.Status.AppliancePort)
	}
	cond := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPCGatewayConditionApplianceResolved)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("ApplianceResolved = %v, want True", cond)
	}
}

// A selector that matches nothing is an ordinary state on the way up — the
// appliance may simply not be scheduled yet. It must report, not wedge.
func TestApplianceUnresolvedIsReportedNotFatal(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		applianceGateway("team-a", "door", "vpc-a", map[string]string{"app": "fw"}),
	)
	gw := reconcileGateway(t, c, "team-a", "door")

	if gw.Status.AppliancePort != "" {
		t.Errorf("status.appliancePort = %q, want empty", gw.Status.AppliancePort)
	}
	cond := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPCGatewayConditionApplianceResolved)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("ApplianceResolved = %v, want False", cond)
	}
	if cond.Message == "" {
		t.Error("an unresolved appliance must say why")
	}
}

// Selecting a workload that is not attached to this VPC is a different mistake
// from selecting nothing, and the message has to distinguish them or the
// operator edits the wrong thing.
func TestApplianceWithoutAPortInThisVPCSaysSo(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		applianceGateway("team-a", "door", "vpc-a", map[string]string{"app": "fw"}),
		appliancePod("team-a", "fw-1", map[string]string{"app": "fw"}),
	)
	gw := reconcileGateway(t, c, "team-a", "door")

	cond := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPCGatewayConditionApplianceResolved)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("ApplianceResolved = %v, want False", cond)
	}
	if !strings.Contains(cond.Message, "no Port") {
		t.Errorf("message %q should point at the missing attachment, not at the selector", cond.Message)
	}
}

// Re-pointing the appliance must MOVE the door. gateways[vni] holds one entry;
// leaving two Ports flagged would make the winner whichever agent resynced last.
func TestRepointingTheApplianceMovesTheDoor(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		applianceGateway("team-a", "door", "vpc-a", map[string]string{"app": "new"}),
		appliancePod("team-a", "old-1", map[string]string{"app": "old"}),
		appliancePod("team-a", "new-1", map[string]string{"app": "new"}),
		vpcPort("v100.10-10-0-8", "team-a", "vpc-a", "team-a", "old-1", true), // yesterday's door
		vpcPort("v100.10-10-0-9", "team-a", "vpc-a", "team-a", "new-1", false),
	)
	reconcileGateway(t, c, "team-a", "door")

	if portGateway(t, c, "v100.10-10-0-8") {
		t.Error("the previous door was left flagged: the VPC would have two")
	}
	if !portGateway(t, c, "v100.10-10-0-9") {
		t.Error("the new appliance did not become the door")
	}
}

// Dropping spec.appliance must release the door too, or the tenant's workload
// keeps receiving the VPC's egress after being told to stop.
func TestDroppingTheApplianceReleasesTheDoor(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"), // no appliance
		appliancePod("team-a", "fw-1", map[string]string{"app": "fw"}),
		vpcPort("v100.10-10-0-9", "team-a", "vpc-a", "team-a", "fw-1", true),
	)
	reconcileGateway(t, c, "team-a", "door")

	if portGateway(t, c, "v100.10-10-0-9") {
		t.Error("the door was not released when spec.appliance went away")
	}
}

// cozyplane must not ALSO run a gateway pod while a tenant appliance is the
// door. There is one gateways[vni] entry; two claimants would race for it and
// the winner would be whichever agent resynced last.
func TestApplianceMeansNoCozyplaneGatewayPod(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		applianceGateway("team-a", "door", "vpc-a", map[string]string{"app": "fw"}),
		appliancePod("team-a", "fw-1", map[string]string{"app": "fw"}),
		vpcPort("v100.10-10-0-9", "team-a", "vpc-a", "team-a", "fw-1", false),
	)
	r := &GatewayReconciler{Client: c, Scheme: gatewayScheme(t),
		Config: GatewayConfig{Image: "cozyplane:test", Namespace: "cozy-system"}}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var deps appsv1.DeploymentList
	if err := c.List(context.Background(), &deps, client.InNamespace("cozy-system")); err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	if len(deps.Items) != 0 {
		t.Errorf("cozyplane spawned %d gateway deployment(s) alongside the tenant appliance", len(deps.Items))
	}
}
