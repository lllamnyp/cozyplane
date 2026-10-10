package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	claim "github.com/lllamnyp/cozyplane/api/sdn"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type gatewaySnapshotSink struct {
	mu      sync.Mutex
	current map[uint32]bool
	writes  chan struct{}
}

func (s *gatewaySnapshotSink) Gateways() (map[uint32]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[uint32]bool{}
	for vni := range s.current {
		out[vni] = true
	}
	return out, nil
}
func (s *gatewaySnapshotSink) SetGateway(vni uint32, _, _ net.IP) error {
	s.mu.Lock()
	s.current[vni] = true
	s.mu.Unlock()
	s.notify()
	return nil
}
func (s *gatewaySnapshotSink) DelGateway(vni uint32) error {
	s.mu.Lock()
	delete(s.current, vni)
	s.mu.Unlock()
	s.notify()
	return nil
}
func (s *gatewaySnapshotSink) notify() {
	select {
	case s.writes <- struct{}{}:
	default:
	}
}
func awaitGatewayCount(t *testing.T, s *gatewaySnapshotSink, count int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		current, _ := s.Gateways()
		if len(current) == count {
			return
		}
		select {
		case <-s.writes:
		case <-timer.C:
			t.Fatalf("gateway count=%d want=%d state=%v", len(current), count, current)
		}
	}
}

func TestGatewayWatcherWithdrawsRetiredVPCWithoutPortEvent(t *testing.T) {
	for _, change := range []string{"delete", "termination", "new-vni"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			port := gatewayPort("v101.10-0-0-1", "10.0.0.1", "self", "192.0.2.1", true)
			port.Spec.VPCRef = sdn.VPCRef{Namespace: "tenant-a", Name: "net"}
			vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdn.VPCStatus{VNI: 101}}
			boundary := fallbackBoundary(vpc, "10.0.0.0/24")
			c := sdnfake.NewSimpleClientset(port, vpc)
			if _, err := c.SdnV1alpha1().VPCGateways(boundary.Namespace).Create(ctx, boundary, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			factory := sdninformers.NewSharedInformerFactory(c, 0)
			sink := &gatewaySnapshotSink{current: map[uint32]bool{}, writes: make(chan struct{}, 16)}
			watchGateways(ctx, factory, sink, "self", slog.New(slog.NewTextHandler(io.Discard, nil)))
			factory.Start(ctx.Done())
			defer func() { cancel(); factory.Shutdown() }()
			awaitGatewayCount(t, sink, 1)
			switch change {
			case "delete":
				if err := c.SdnV1alpha1().VPCs(vpc.Namespace).Delete(ctx, vpc.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			case "termination":
				now := metav1.Now()
				vpc.DeletionTimestamp = &now
				if _, err := c.SdnV1alpha1().VPCs(vpc.Namespace).Update(ctx, vpc, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "new-vni":
				vpc.Status.VNI = 102
				if _, err := c.SdnV1alpha1().VPCs(vpc.Namespace).UpdateStatus(ctx, vpc, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			awaitGatewayCount(t, sink, 0)
			if change == "new-vni" {
				current := port.DeepCopy()
				current.Name = "v102.10-0-0-1"
				if _, err := c.SdnV1alpha1().Ports().Create(ctx, current, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				awaitGatewayCount(t, sink, 1)
				got, _ := sink.Gateways()
				if !got[102] || got[101] {
					t.Fatal("current claim did not recover new VPC scope", got)
				}
			}
		})
	}
}

func TestDesiredGatewaysRejectsStalePortClaims(t *testing.T) {
	for _, mutation := range []string{"terminating", "address-name", "missing-ref", "wrong-namespace", "missing-vpc"} {
		t.Run(mutation, func(t *testing.T) {
			p := gatewayPort("v101.10-0-0-1", "10.0.0.1", "self", "192.0.2.1", true)
			p.Spec.VPCRef = sdn.VPCRef{Namespace: "tenant-a", Name: "net"}
			switch mutation {
			case "terminating":
				now := metav1.Now()
				p.DeletionTimestamp = &now
			case "address-name":
				p.Spec.IP = "10.0.0.99"
			case "missing-ref":
				p.Spec.VPCRef = sdn.VPCRef{}
			case "wrong-namespace":
				p.Spec.VPCRef.Namespace = "tenant-b"
			}
			vpc := vpcObj("tenant-a", "net", 101)
			boundary := fallbackBoundary(vpc, "10.0.0.0/24")
			vpcs := []*sdn.VPC{vpc}
			if mutation == "missing-vpc" {
				vpcs = nil
			}
			if got := desiredGateways([]*sdn.Port{p}, vpcs, []*sdn.VPCGateway{boundary}, "self"); len(got) != 0 {
				t.Fatalf("stale %s gateway claim accepted: %v", mutation, got)
			}
		})
	}
}

func TestGatewayWatcherWithdrawsRemovedBoundaryWithoutPortEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	port := gatewayPort("v101.10-0-0-1", "10.0.0.1", "self", "192.0.2.1", true)
	port.Spec.VPCRef = sdn.VPCRef{Namespace: "tenant-a", Name: "net"}
	vpc := vpcObj("tenant-a", "net", 101)
	boundary := fallbackBoundary(vpc, "10.0.0.0/24")
	c := sdnfake.NewSimpleClientset(port, vpc)
	if _, err := c.SdnV1alpha1().VPCGateways(boundary.Namespace).Create(ctx, boundary, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	factory := sdninformers.NewSharedInformerFactory(c, 0)
	sink := &gatewaySnapshotSink{current: map[uint32]bool{}, writes: make(chan struct{}, 16)}
	watchGateways(ctx, factory, sink, "self", slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	awaitGatewayCount(t, sink, 1)
	if err := c.SdnV1alpha1().VPCGateways(boundary.Namespace).Delete(ctx, boundary.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	awaitGatewayCount(t, sink, 0)
}

func fallbackBoundary(vpc *sdn.VPC, cidr string) *sdn.VPCGateway {
	vpc.Spec.CIDRs = []string{cidr}
	return &sdn.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: vpc.Namespace, Name: "door-" + vpc.Name}, Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: vpc.Name}, NAT: sdn.VPCGatewayNAT{Enabled: true}}}
}

func TestDesiredGatewaysRequiresCurrentBoundaryAuthority(t *testing.T) {
	for _, change := range []string{"live", "missing", "terminated", "disabled", "wrong-vpc", "wrong-namespace", "older-disabled", "appliance", "unresolved-appliance", "wrong-appliance", "retired-appliance"} {
		t.Run(change, func(t *testing.T) {
			port := gatewayPort("v101.10-0-0-1", "10.0.0.1", "self", "192.0.2.1", true)
			port.Spec.VPCRef = sdn.VPCRef{Namespace: "tenant-a", Name: "net"}
			vpc := vpcObj("tenant-a", "net", 101)
			boundary := fallbackBoundary(vpc, "10.0.0.0/24")
			gws := []*sdn.VPCGateway{boundary}
			switch change {
			case "missing":
				gws = nil
			case "terminated":
				now := metav1.Now()
				boundary.DeletionTimestamp = &now
			case "disabled":
				boundary.Spec.NAT.Enabled = false
			case "wrong-vpc":
				boundary.Spec.VPCRef.Name = "other"
			case "wrong-namespace":
				boundary.Namespace = "tenant-b"
			case "older-disabled":
				older := boundary.DeepCopy()
				older.Name, older.Spec.NAT.Enabled = "a-disabled", false
				gws = append(gws, older)
			case "appliance", "unresolved-appliance", "wrong-appliance":
				port.Name, port.Spec.IP = "v101.10-0-0-2", "10.0.0.2"
				boundary.Spec.Appliance = &sdn.VPCGatewayAppliance{}
				boundary.Spec.NAT.Enabled = false // the appliance door does not require NAT allocation
				if change == "appliance" {
					boundary.Status.AppliancePort = port.Name
				} else if change == "wrong-appliance" {
					boundary.Status.AppliancePort = "v101.10-0-0-3"
				}
			case "retired-appliance":
				port.Name, port.Spec.IP = "v101.10-0-0-2", "10.0.0.2"
			}
			got := desiredGateways([]*sdn.Port{port}, []*sdn.VPC{vpc}, gws, "self")
			want := change == "live" || change == "appliance"
			if (len(got) == 1) != want {
				t.Fatalf("boundary %s projected=%v", change, got)
			}
		})
	}
}

func TestDesiredFallbackGatewayAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		cidr, address string
		want          bool
	}{
		{"10.0.0.9/24", "10.0.0.1", true},
		{"fd00:1::9/64", "fd00:1::1", true},
		{"::ffff:10.0.0.0/120", "10.0.0.1", true},
		{"10.0.0.0/32", "10.0.0.1", false},
		{"fd00:1::/128", "fd00:1::1", false},
		{"bad", "10.0.0.1", false},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			vpc := vpcObj("tenant", "net", 101)
			boundary := fallbackBoundary(vpc, tc.cidr)
			port := gatewayPort(claim.PortName(vpc.Status.VNI, tc.address), tc.address, "self", "192.0.2.1", true)
			port.Spec.VPCRef = sdn.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}
			got := desiredGateways([]*sdn.Port{port}, []*sdn.VPC{vpc}, []*sdn.VPCGateway{boundary}, "self")
			if (len(got) == 1) != tc.want {
				t.Fatalf("reserved fallback %s projected=%v", tc.cidr, got)
			}
		})
	}
}

func TestDesiredGatewaysUsesOnlyResolvedApplianceDespiteRetainedFlags(t *testing.T) {
	vpc := vpcObj("tenant", "net", 101)
	boundary := fallbackBoundary(vpc, "10.0.0.0/24")
	boundary.Spec.Appliance = &sdn.VPCGatewayAppliance{}
	old := gatewayPort("v101.10-0-0-2", "10.0.0.2", "self", "192.0.2.1", true)
	current := gatewayPort("v101.10-0-0-3", "10.0.0.3", "self", "192.0.2.1", true)
	old.Spec.VPCRef, current.Spec.VPCRef = sdn.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}, sdn.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}
	boundary.Status.AppliancePort = current.Name
	for _, ports := range [][]*sdn.Port{{old, current}, {current, old}} {
		got := desiredGateways(ports, []*sdn.VPC{vpc}, []*sdn.VPCGateway{boundary}, "self")
		if len(got) != 1 || got[101].ip.String() != current.Spec.IP {
			t.Fatal("retained predecessor flag replaced resolved appliance", got)
		}
	}
}
