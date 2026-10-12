package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	apis "github.com/lllamnyp/cozyplane/api/sdn"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	registry "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcgateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRouteWatcherOversizedOwnerCannotConsumeGlobalCompileBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := sdnfake.NewSimpleClientset()
	strategy := registry.NewStrategy(runtime.NewScheme(), nil)
	prefixes := make([]string, 4096)
	for i := range prefixes {
		prefixes[i] = "203.0.113.0/24"
	}
	// Each object fits the existing per-gateway candidate limit. Only this
	// one owner's combined demand is excessive; duplicates are candidates too.
	for i := 0; i < 258; i++ {
		ns, name := "tenant-a", fmt.Sprintf("net-%03d", i)
		cidrs := prefixes
		if i == 257 {
			ns = "tenant-b"
			cidrs = []string{"198.51.100.0/24"}
		}
		vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Status: sdn.VPCStatus{VNI: int32(101 + i)}}
		if _, err := client.SdnV1alpha1().VPCs(ns).Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		gw := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: name}}, Status: sdn.VPCGatewayStatus{Routes: []sdn.VPCGatewayRouteStatus{{CIDRs: cidrs}}}}
		gw.Spec.Routes = []sdn.VPCGatewayRoute{{CIDRs: cidrs}}
		apiObject := &apis.VPCGateway{Spec: apis.VPCGatewaySpec{VPCRef: apis.LocalVPCRef{Name: name}, Routes: []apis.VPCGatewayRoute{{CIDRs: cidrs}}}}
		if errs := strategy.Validate(ctx, apiObject); len(errs) != 0 {
			t.Fatalf("fixture not admitted: %v", errs)
		}
		if _, err := client.SdnV1alpha1().VPCGateways(ns).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	sink := &routeSnapshotSink{capacity: 4096, writes: make(chan []datapath.RouteEntry, 8)}
	watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	select {
	case routes := <-sink.writes:
		if len(routes) != 1 || routes[0].Scope != 358 {
			t.Fatalf("unrelated owner lost its complete route: %+v", routes)
		}
		sink.mu.Lock()
		global := sink.blocked
		scopes := len(sink.blockedScopes)
		sink.mu.Unlock()
		if global || scopes != 257 {
			t.Fatalf("oversized owner escaped scoped denial: global=%v scopes=%d", global, scopes)
		}
	case <-time.After(5 * time.Second):
		sink.mu.Lock()
		global := sink.blocked
		sink.mu.Unlock()
		t.Fatalf("single oversized owner prevented complete publication; global blocked=%v", global)
	}
}
