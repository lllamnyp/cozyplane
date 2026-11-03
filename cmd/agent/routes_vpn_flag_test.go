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

// Only a route a VPNGateway publishes carries the managed boundary's transit exception; a VPCGateway route in the
// same VPC, toward the same Port, never does.
func TestRouteWatcherMarksOnlyVPNGatewayRoutes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := sdnfake.NewSimpleClientset()
	vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net"}, Status: sdn.VPCStatus{VNI: 101}}
	if _, err := client.SdnV1alpha1().VPCs("tenant").Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-1"}, Spec: sdn.PortSpec{IP: "10.0.0.1", Node: "node-a", VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}}}
	if _, err := client.SdnV1alpha1().Ports().Create(ctx, port, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	vpcGW := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "router"}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}}
	vpcGW.Status.Routes = []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"198.51.100.0/24"}, Port: port.Name}}
	if _, err := client.SdnV1alpha1().VPCGateways("tenant").Create(ctx, vpcGW, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	vpnGW := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "vpn"}, Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}}
	vpnGW.Status.Routes = []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"10.250.0.1/32"}, Port: port.Name}}
	if _, err := client.SdnV1alpha1().VPNGateways("tenant").Create(ctx, vpnGW, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	sink := &routeSnapshotSink{writes: make(chan []datapath.RouteEntry, 8)}
	watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case routes := <-sink.writes:
			if len(routes) != 2 {
				continue // an informer has not synced yet
			}
			vpn := map[string]bool{}
			for _, route := range routes {
				vpn[route.CIDR] = route.VPN
			}
			if !vpn["10.250.0.1/32"] || vpn["198.51.100.0/24"] {
				t.Fatalf("VPN flags = %v, want only the VPNGateway route marked", vpn)
			}
			return
		case <-deadline:
			t.Fatal("routes were not published")
		}
	}
}
