package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	internalapi "github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	gatewayregistry "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcgateway"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVPCGatewayNamespaceCacheRejectsUnusableReferences(t *testing.T) {
	for _, appliance := range []bool{false, true} {
		gw := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", ResourceVersion: "1"}}
		gw.Spec.VPCRef.Name = "net"
		set := func(name string) {
			if appliance {
				gw.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{Namespace: name}
			} else {
				gw.Spec.Routes = []sdnv1alpha1.VPCGatewayRoute{{Via: sdnv1alpha1.VPCGatewayVia{Namespace: name}, CIDRs: []string{"203.0.113.0/24"}}}
			}
		}
		large := strings.Repeat("a", 128<<10)
		set(large)
		list := &sdnv1alpha1.VPCGatewayList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []sdnv1alpha1.VPCGateway{*gw}}
		cached, index := vpnObjectCache(t, gw, list, gatewayPodNamespaceIndex, gatewayPodNamespaceKeys)
		lookup := func(name string, want int) {
			t.Helper()
			if err := cached.List(t.Context(), list, client.InNamespace(gw.Namespace), client.MatchingFields{gatewayPodNamespaceIndex: name}); err != nil {
				t.Fatal(err)
			}
			if len(list.Items) != want {
				t.Fatalf("appliance=%v: namespace index rows=%d want=%d for %d-byte name", appliance, len(list.Items), want, len(name))
			}
		}
		lookup(large, 0)
		set("") // own namespace is the optional reference default
		if err := index.Update(gw.DeepCopyObject()); err != nil {
			t.Fatal(err)
		}
		lookup(gw.Namespace, 1)
		set("other-tenant")
		if err := index.Update(gw.DeepCopyObject()); err != nil {
			t.Fatal(err)
		}
		lookup(gw.Namespace, 0)
		lookup("other-tenant", 1)
	}
}

type namespaceListCounter struct {
	client.Client
	invalidPodLists int
}

func (c *namespaceListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	options := (&client.ListOptions{}).ApplyOptions(opts)
	if _, ok := list.(*corev1.PodList); ok && len(options.Namespace) > 63 {
		c.invalidPodLists++
		return fmt.Errorf("invalid namespace reached pod lookup")
	}
	return c.Client.List(ctx, list, opts...)
}

func TestVPCGatewayLegacyInvalidNamespaceRetainsBlackholeAndRecovers(t *testing.T) {
	r, gw, vpc := routeSecurityFixture(t, "203.0.113.0/24")
	c := &namespaceListCounter{Client: r.Client}
	r.Client = c
	gw.Spec.Routes[0].Via.Namespace = strings.Repeat("a", 128<<10)
	out, problem, err := r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil || c.invalidPodLists != 0 || len(out) != 1 || len(out[0].CIDRs) != 1 || out[0].CIDRs[0] != "203.0.113.0/24" || out[0].Port != "" || problem == "" || len(problem) > 1024 {
		t.Fatalf("invalid namespace lost protection or reached lookup: rows=%d invalidLists=%d problemBytes=%d err=%v", len(out), c.invalidPodLists, len(problem), err)
	}
	gw.Spec.Routes[0].Via.Namespace = ""
	out, problem, err = r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil || problem != "" || len(out) != 1 || out[0].Port == "" {
		t.Fatal("valid route namespace did not recover")
	}
	gw.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{Namespace: strings.Repeat("a", 128<<10), PodSelector: gw.Spec.Routes[0].Via.PodSelector}
	chosen, problem, err := r.reconcileAppliance(t.Context(), gw, vpc)
	if err != nil || c.invalidPodLists != 0 || chosen != "" || problem == "" || len(problem) > 1024 {
		t.Fatal("invalid appliance namespace accepted or reached lookup")
	}
	gw.Spec.Appliance.Namespace = ""
	chosen, problem, err = r.reconcileAppliance(t.Context(), gw, vpc)
	if err != nil || problem != "" || chosen == "" {
		t.Fatal("valid appliance namespace did not recover")
	}
}

func TestVPCGatewayRouteCountAdmissionBeforeIndexExpansion(t *testing.T) {
	strategy := gatewayregistry.NewStrategy(runtime.NewScheme(), nil)
	old := &internalapi.VPCGateway{Spec: internalapi.VPCGatewaySpec{VPCRef: internalapi.LocalVPCRef{Name: "net"}}}
	current := old.DeepCopy()
	current.Spec.Routes = make([]internalapi.VPCGatewayRoute, 4097)
	if len(strategy.Validate(t.Context(), current)) == 0 || len(strategy.ValidateUpdate(t.Context(), current, old)) == 0 {
		t.Fatal("4097 route inputs admitted before namespace index expansion")
	}
}

func TestVPCGatewayOversizedRouteNamespaceIndexDoesNotExpand(t *testing.T) {
	gw := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", ResourceVersion: "1"}}
	gw.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{}
	gw.Spec.Routes = make([]sdnv1alpha1.VPCGatewayRoute, 4097)
	for i := range gw.Spec.Routes {
		gw.Spec.Routes[i].Via.Namespace = fmt.Sprintf("tenant-%04d", i)
	}
	list := &sdnv1alpha1.VPCGatewayList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []sdnv1alpha1.VPCGateway{*gw}}
	cached, index := vpnObjectCache(t, gw, list, gatewayPodNamespaceIndex, gatewayPodNamespaceKeys)
	check := func(ns string, want int) {
		t.Helper()
		if err := cached.List(t.Context(), list, client.InNamespace(gw.Namespace), client.MatchingFields{gatewayPodNamespaceIndex: ns}); err != nil {
			t.Fatal(err)
		}
		if len(list.Items) != want {
			t.Fatalf("namespace=%s index rows=%d want=%d", ns, len(list.Items), want)
		}
	}
	check(gw.Namespace, 1) // A valid appliance reference still receives events.
	for _, i := range []int{0, 2048, 4096} {
		check(gw.Spec.Routes[i].Via.Namespace, 0)
	}
	gw.Spec.Routes = gw.Spec.Routes[:1]
	if err := index.Update(gw.DeepCopyObject()); err != nil {
		t.Fatal(err)
	}
	check(gw.Spec.Routes[0].Via.Namespace, 1)
	check(gw.Namespace, 1)
}
