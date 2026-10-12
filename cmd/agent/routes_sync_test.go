package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

type routeSnapshotSink struct {
	mu            sync.Mutex
	snapshot      []datapath.RouteEntry
	writes        chan []datapath.RouteEntry
	capacity      uint32
	blocked       bool
	blockedScopes []uint32
}

func (s *routeSnapshotSink) BlockRoutes() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = true
	return nil
}

func (s *routeSnapshotSink) RouteCapacity() uint32 {
	if s.capacity != 0 {
		return s.capacity
	}
	return 4096
}

func (s *routeSnapshotSink) SyncRoutes(routes []datapath.RouteEntry) error {
	return s.SyncRoutesScoped(routes, nil)
}

func (s *routeSnapshotSink) SyncRoutesScoped(routes []datapath.RouteEntry, scopes []uint32) error {
	s.mu.Lock()
	s.snapshot = append([]datapath.RouteEntry(nil), routes...)
	s.blockedScopes = append([]uint32(nil), scopes...)
	s.blocked = false
	s.mu.Unlock()
	s.writes <- routes
	return nil
}

func TestRouteWatcherPreservesPinnedSnapshotUntilAllInitialListsComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-1"}, Spec: sdn.PortSpec{IP: "10.0.0.1", Node: "node-a", VPCRef: sdn.VPCRef{Namespace: "tenant-a", Name: "net"}}}
	gw := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}, Status: sdn.VPCGatewayStatus{
		Routes: []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}, Ports: []string{port.Name}}},
	}}
	client := sdnfake.NewSimpleClientset(port)
	seedRouteWatcherVPC(t, client)
	// Seed through the typed resource: ObjectTracker guesses the plural of a
	// Gateway kind incorrectly when initialized directly with that object.
	if _, err := client.SdnV1alpha1().VPCGateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	var releasePorts atomic.Bool
	client.PrependReactor("list", "ports", func(ktesting.Action) (bool, runtime.Object, error) {
		if !releasePorts.Load() {
			return true, nil, errors.New("initial Port list unavailable")
		}
		return false, nil, nil
	})
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	old := []datapath.RouteEntry{{Scope: 101, CIDR: "203.0.113.0/24", GwIP: []byte{10, 0, 0, 1}}}
	sink := &routeSnapshotSink{snapshot: old, writes: make(chan []datapath.RouteEntry, 8)}
	watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	if !cache.WaitForCacheSync(ctx.Done(), factory.Sdn().V1alpha1().VPCGateways().Informer().HasSynced) {
		t.Fatal("gateway cache failed to synchronize")
	}
	select {
	case routes := <-sink.writes:
		t.Fatalf("incomplete Port cache replaced pinned routes: %#v", routes)
	case <-time.After(200 * time.Millisecond):
	}
	sink.mu.Lock()
	preserved := reflect.DeepEqual(sink.snapshot, old)
	sink.mu.Unlock()
	if !preserved {
		t.Fatal("pinned snapshot changed before every initial list completed")
	}
	sink.mu.Lock()
	blocked := sink.blocked
	sink.mu.Unlock()
	if !blocked {
		t.Fatal("incomplete initial cache allowed off-VPC egress")
	}
	releasePorts.Store(true)
	select {
	case routes := <-sink.writes:
		if len(routes) != 1 || routes[0].Scope != 101 || routes[0].CIDR != "203.0.113.0/24" || len(routes[0].NextHops) != 1 || routes[0].NextHops[0].GwIP.String() != "10.0.0.1" {
			t.Fatalf("complete route snapshot not replayed: %#v", routes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("complete caches were not applied")
	}
}

func TestRouteWatcherRejectsOversizedSnapshotAndRecovers(t *testing.T) {
	for _, tooManyPorts := range []bool{false, true} {
		t.Run(fmt.Sprint("tooManyPorts=", tooManyPorts), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-1"}, Spec: sdn.PortSpec{IP: "10.0.0.1", Node: "node-a", VPCRef: sdn.VPCRef{Namespace: "tenant-a", Name: "net"}}}
			route := sdn.VPCGatewayRouteStatus{CIDRs: []string{"203.0.113.0/24", "198.51.100.0/24"}, Ports: []string{port.Name}}
			if tooManyPorts {
				route.CIDRs = route.CIDRs[:1]
				route.Ports = []string{port.Name, port.Name, port.Name}
			}
			gw := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}, Status: sdn.VPCGatewayStatus{Routes: []sdn.VPCGatewayRouteStatus{route}}}
			client := sdnfake.NewSimpleClientset(port)
			seedRouteWatcherVPC(t, client)
			if _, err := client.SdnV1alpha1().VPCGateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			factory := sdninformers.NewSharedInformerFactory(client, 0)
			old := []datapath.RouteEntry{{Scope: 101, CIDR: "192.0.2.0/24", GwIP: []byte{10, 0, 0, 1}}}
			sink := &routeSnapshotSink{snapshot: old, capacity: 1, writes: make(chan []datapath.RouteEntry, 8)}
			watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
			factory.Start(ctx.Done())
			defer func() { cancel(); factory.Shutdown() }()
			if !cache.WaitForCacheSync(ctx.Done(), factory.Sdn().V1alpha1().VPCGateways().Informer().HasSynced,
				factory.Sdn().V1alpha1().VPNGateways().Informer().HasSynced, factory.Sdn().V1alpha1().Ports().Informer().HasSynced) {
				t.Fatal("route caches failed to synchronize")
			}
			select {
			case routes := <-sink.writes:
				if len(routes) != 0 {
					t.Fatalf("partial invalid owner snapshot published: %#v", routes)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("scoped denial not published")
			}
			sink.mu.Lock()
			blocked := sink.blocked
			scoped := reflect.DeepEqual(sink.blockedScopes, []uint32{101})
			sink.mu.Unlock()
			if blocked || !scoped {
				t.Fatal("invalid owner did not receive isolated scoped denial")
			}
			gw.Status.Routes[0].CIDRs = []string{"203.0.113.0/24"}
			gw.Status.Routes[0].Ports = []string{port.Name}
			if _, err := client.SdnV1alpha1().VPCGateways(gw.Namespace).UpdateStatus(ctx, gw, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			select {
			case routes := <-sink.writes:
				if len(routes) != 1 || routes[0].CIDR != "203.0.113.0/24" {
					t.Fatalf("valid recovery snapshot incomplete: %#v", routes)
				}
				sink.mu.Lock()
				recovered := len(sink.blockedScopes) == 0 && !sink.blocked
				sink.mu.Unlock()
				if !recovered {
					t.Fatal("recovered owner remains blocked")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("valid recovery snapshot not applied")
			}
		})
	}
}

func TestRouteWatcherIgnoresLosingGatewayAndPromotesSuccessor(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-1"}, Spec: sdn.PortSpec{IP: "10.0.0.1", Node: "node-a", VPCRef: sdn.VPCRef{Namespace: "tenant-a", Name: "net"}}}
	winner := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "a-winner"}}
	winner.Spec.VPCRef.Name = "net"
	loser := winner.DeepCopy()
	loser.Name = "z-loser"
	loser.Status.Routes = []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}, Port: port.Name}}
	client := sdnfake.NewSimpleClientset(port)
	seedRouteWatcherVPC(t, client)
	for _, gw := range []*sdn.VPCGateway{winner, loser} {
		if _, err := client.SdnV1alpha1().VPCGateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	sink := &routeSnapshotSink{writes: make(chan []datapath.RouteEntry, 16)}
	watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	select {
	case routes := <-sink.writes:
		if len(routes) != 0 {
			t.Fatalf("loser routed despite winner without routes: %+v", routes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initial snapshot missing")
	}
	if err := client.SdnV1alpha1().VPCGateways(winner.Namespace).Delete(ctx, winner.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case routes := <-sink.writes:
			if len(routes) == 1 && routes[0].CIDR == "203.0.113.0/24" {
				return
			}
		case <-deadline:
			t.Fatal("successor routes not applied")
		}
	}
}

func TestRouteWatcherRejectsStaleVPCScope(t *testing.T) {
	for _, mutation := range []string{"old-vni", "wrong-vpc", "wrong-address", "terminating-port", "terminating-vpc", "missing-vpc", "unresolved-port"} {
		for _, vpn := range []bool{false, true} {
			t.Run(fmt.Sprint(mutation, "/vpn=", vpn), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdn.VPCStatus{VNI: 101}}
				port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-1"}, Spec: sdn.PortSpec{IP: "10.0.0.1", Node: "node-a", VPCRef: sdn.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}}}
				switch mutation {
				case "old-vni":
					vpc.Status.VNI = 102
				case "wrong-vpc":
					port.Spec.VPCRef.Name = "other"
				case "wrong-address":
					port.Spec.IP = "10.0.0.99"
				case "terminating-port":
					now := metav1.Now()
					port.DeletionTimestamp = &now
				case "terminating-vpc":
					now := metav1.Now()
					vpc.DeletionTimestamp = &now
				}
				client := sdnfake.NewSimpleClientset(port)
				if mutation != "missing-vpc" {
					if _, err := client.SdnV1alpha1().VPCs(vpc.Namespace).Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				routes := []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}, Port: port.Name}}
				if mutation == "unresolved-port" {
					routes[0].Port = ""
				}
				if vpn {
					gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: vpc.Namespace, Name: "gateway"}, Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: vpc.Name}}, Status: sdn.VPNGatewayStatus{Routes: routes}}
					if _, err := client.SdnV1alpha1().VPNGateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
						t.Fatal(err)
					}
				} else {
					gw := &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: vpc.Namespace, Name: "gateway"}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: vpc.Name}}, Status: sdn.VPCGatewayStatus{Routes: routes}}
					if _, err := client.SdnV1alpha1().VPCGateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				factory := sdninformers.NewSharedInformerFactory(client, 0)
				sink := &routeSnapshotSink{writes: make(chan []datapath.RouteEntry, 16)}
				watchRoutes(ctx, factory, sink, "node-a", slog.New(slog.NewTextHandler(io.Discard, nil)))
				factory.Start(ctx.Done())
				defer func() { cancel(); factory.Shutdown() }()
				select {
				case got := <-sink.writes:
					blackhole := mutation != "missing-vpc" && mutation != "terminating-vpc"
					if (!blackhole && len(got) != 0) || (blackhole && (len(got) != 1 || len(got[0].NextHops) != 0 || got[0].CIDR != "203.0.113.0/24")) {
						t.Fatalf("stale VPC route admitted: %+v", got)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("route snapshot not published")
				}
			})
		}
	}
}

func seedRouteWatcherVPC(t *testing.T, c *sdnfake.Clientset) {
	t.Helper()
	vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdn.VPCStatus{VNI: 101}}
	if _, err := c.SdnV1alpha1().VPCs(vpc.Namespace).Create(t.Context(), vpc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}
