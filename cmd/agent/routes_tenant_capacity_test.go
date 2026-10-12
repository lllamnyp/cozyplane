package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

func TestRouteWatcherIsolatesTenantCapacityAndMalformedRoutes(t *testing.T) {
	for _, fault := range []string{"capacity", "invalid-cidr", "oversized-array"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := sdnfake.NewSimpleClientset()
			var noisy []*sdn.VPCGateway
			// Two VPCs of one owner must share one budget. A small second
			// owner must retain both its route and ordinary egress permission.
			for i, ns := range []string{"tenant-a", "tenant-a", "tenant-b"} {
				name := []string{"net-a", "net-b", "net"}[i]
				vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Status: sdn.VPCStatus{VNI: int32(101 + i)}}
				if _, err := client.SdnV1alpha1().VPCs(ns).Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				gw := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: name}}, Status: sdn.VPCGatewayStatus{Routes: []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}}}}}
				if i == 0 {
					switch fault {
					case "invalid-cidr":
						gw.Status.Routes[0].CIDRs = []string{"invalid"}
					case "oversized-array":
						gw.Status.Routes = make([]sdn.VPCGatewayRouteStatus, 4097)
					}
				}
				if _, err := client.SdnV1alpha1().VPCGateways(ns).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				if ns == "tenant-a" {
					noisy = append(noisy, gw)
				}
			}
			factory := sdninformers.NewSharedInformerFactory(client, 0)
			sink := &routeSnapshotSink{capacity: 2, writes: make(chan []datapath.RouteEntry, 32)}
			watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
			factory.Start(ctx.Done())
			defer func() { cancel(); factory.Shutdown() }()
			select {
			case routes := <-sink.writes:
				if len(routes) != 1 || routes[0].Scope != 103 {
					t.Fatalf("unrelated owner route lost: %+v", routes)
				}
				sink.mu.Lock()
				blocked := append([]uint32(nil), sink.blockedScopes...)
				global := sink.blocked
				sink.mu.Unlock()
				if global || len(blocked) != 2 || (blocked[0] != 101 && blocked[0] != 102) || blocked[0]+blocked[1] != 203 {
					t.Fatalf("owner scopes not isolated: global=%v scopes=%v", global, blocked)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("isolated snapshot missing")
			}
			// Withdraw the offending owner's intent completely: no history or
			// old denial may survive a successful snapshot.
			for _, gw := range noisy {
				gw.Status.Routes = nil
				if _, err := client.SdnV1alpha1().VPCGateways(gw.Namespace).UpdateStatus(ctx, gw, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.After(5 * time.Second)
			for {
				select {
				case <-sink.writes:
					sink.mu.Lock()
					recovered := len(sink.blockedScopes) == 0 && !sink.blocked
					sink.mu.Unlock()
					if recovered {
						return
					}
				case <-deadline:
					t.Fatal("owner withdrawal did not clear scoped denial")
				}
			}
		})
	}
}
