package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRouteWatcherHubScopesMissingLegAndRejectsForeignPort(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := sdnfake.NewSimpleClientset()
	for i, name := range []string{"net-a", "net-b"} {
		vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: name}, Status: sdn.VPCStatus{VNI: int32(101 + i)}}
		if _, err := client.SdnV1alpha1().VPCs("tenant").Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-1"}, Spec: sdn.PortSpec{IP: "10.0.0.1", Node: "node-a", VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net-a"}}}
	if _, err := client.SdnV1alpha1().Ports().Create(ctx, port, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "gateway"}, Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net-a"}, AdditionalVPCRefs: []sdn.LocalVPCRef{{Name: "net-b"}}}}
	gw.Status.Routes = []sdn.VPCGatewayRouteStatus{
		{CIDRs: []string{"203.0.113.0/24"}, Port: port.Name},
		{VPCRef: sdn.LocalVPCRef{Name: "net-b"}, CIDRs: []string{"203.0.113.0/24"}, Port: port.Name},
	}
	if _, err := client.SdnV1alpha1().VPNGateways("tenant").Create(ctx, gw, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	sink := &routeSnapshotSink{writes: make(chan []datapath.RouteEntry, 8)}
	watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	select {
	case routes := <-sink.writes:
		if len(routes) != 2 {
			t.Fatalf("missing scoped prefix: %+v", routes)
		}
		seen := map[uint32]bool{}
		for _, route := range routes {
			seen[route.Scope] = true
			if route.Scope == 101 && len(route.NextHops) != 1 {
				t.Fatalf("healthy leg lost: %+v", route)
			}
			if route.Scope == 102 && len(route.NextHops) != 0 {
				t.Fatalf("foreign Port became a hub next hop: %+v", route)
			}
		}
		if !seen[101] || !seen[102] {
			t.Fatal("VPC ownership lost")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hub routes were not published")
	}
}

func TestRouteWatcherInvalidHubPreservesOtherOwners(t *testing.T) {
	for _, fault := range []string{"oversized", "undeclared"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := sdnfake.NewSimpleClientset()
			for i, ns := range []string{"tenant-a", "tenant-b"} {
				vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "net"}, Status: sdn.VPCStatus{VNI: int32(101 + i)}}
				if _, err := client.SdnV1alpha1().VPCs(ns).Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gateway"}, Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}, Status: sdn.VPNGatewayStatus{Routes: []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}}}}}
				if i == 0 {
					if fault == "oversized" {
						gw.Status.Routes = make([]sdn.VPCGatewayRouteStatus, 4097)
					} else {
						gw.Status.Routes[0].VPCRef.Name = "foreign"
					}
				}
				if _, err := client.SdnV1alpha1().VPNGateways(ns).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			factory := sdninformers.NewSharedInformerFactory(client, 0)
			sink := &routeSnapshotSink{writes: make(chan []datapath.RouteEntry, 8)}
			watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
			factory.Start(ctx.Done())
			defer func() { cancel(); factory.Shutdown() }()
			select {
			case routes := <-sink.writes:
				if len(routes) != 1 || routes[0].Scope != 102 {
					t.Fatalf("other owner lost: %+v", routes)
				}
				sink.mu.Lock()
				defer sink.mu.Unlock()
				if sink.blocked || len(sink.blockedScopes) != 1 || sink.blockedScopes[0] != 101 {
					t.Fatalf("invalid hub denial leaked: global=%v scopes=%v", sink.blocked, sink.blockedScopes)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("invalid hub prevented route publication")
			}
		})
	}
}
