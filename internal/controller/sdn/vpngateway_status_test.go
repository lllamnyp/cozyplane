package sdn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestIPsecStartAction(t *testing.T) {
	tests := []struct {
		name string
		spec sdnv1alpha1.VPNConnectionIPsec
		want string
	}{
		{name: "legacy initiator", spec: sdnv1alpha1.VPNConnectionIPsec{PeerAddress: "192.0.2.10"}, want: "start"},
		{name: "legacy responder", spec: sdnv1alpha1.VPNConnectionIPsec{}, want: "none"},
		{name: "explicit responder", spec: sdnv1alpha1.VPNConnectionIPsec{PeerAddress: "192.0.2.10", StartAction: sdnv1alpha1.VPNIPsecStartActionNone}, want: "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipsecStartAction(&tt.spec); got != tt.want {
				t.Fatalf("ipsecStartAction() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectionStatusReason(t *testing.T) {
	tests := []struct {
		name                 string
		routes, reported, up bool
		err                  error
		want                 string
	}{
		{name: "routes pending", want: "RoutesPending"},
		{name: "status unavailable", routes: true, err: errors.New("unreachable"), want: "StatusUnavailable"},
		{name: "not reported", routes: true, want: "ConnectionNotReported"},
		{name: "down", routes: true, reported: true, want: "TunnelDown"},
		{name: "established", routes: true, reported: true, up: true, want: "TunnelEstablished"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, _ := connectionStatusReason(tt.routes, tt.reported, tt.up, tt.err)
			if reason != tt.want {
				t.Fatalf("reason = %q, want %q", reason, tt.want)
			}
		})
	}
}

func TestHardenedVPNDeployment(t *testing.T) {
	r := &VPNGatewayReconciler{Config: VPNGatewayConfig{Image: "example.invalid/cozyplane:test", HardenedAppliance: true}}
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name = "gateway"
	gw.Namespace = "tenant"
	gw.Spec.VPCRef.Name = "vpc"
	deployment := r.deployment(gw, backendWireGuard, "checksum")
	podSecurity := deployment.Spec.Template.Spec.SecurityContext
	if podSecurity == nil || len(podSecurity.Sysctls) != 2 {
		t.Fatalf("pod sysctls = %#v, want IPv4 and IPv6 forwarding", podSecurity)
	}
	security := deployment.Spec.Template.Spec.Containers[0].SecurityContext
	if security == nil || security.Privileged != nil || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation {
		t.Fatalf("unexpected hardened security context: %#v", security)
	}
	if len(security.Capabilities.Drop) != 1 || security.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("capability drop = %v, want ALL", security.Capabilities.Drop)
	}
}

func TestActiveActiveVPNStatefulSet(t *testing.T) {
	r := &VPNGatewayReconciler{Config: VPNGatewayConfig{Image: "registry.invalid/cozyplane:test", HardenedAppliance: true}}
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name, gw.Namespace, gw.Spec.VPCRef.Name = "gateway", "tenant", "vpc"
	gw.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{}
	gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeActiveActive, ActiveActive: &sdnv1alpha1.VPNGatewayActiveActive{
		LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"}, BFD: true,
	}}
	statefulSet := r.statefulSet(gw, backendWireGuard, "checksum")
	if statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 2 || statefulSet.Spec.ServiceName != "gateway-vpn-headless" {
		t.Fatalf("unexpected active-active StatefulSet: replicas=%v service=%q", statefulSet.Spec.Replicas, statefulSet.Spec.ServiceName)
	}
	containers := statefulSet.Spec.Template.Spec.Containers
	if len(containers) != 2 || containers[1].Name != "vpn-routing" {
		t.Fatalf("active-active routing sidecar missing: %+v", containers)
	}
	if containers[1].ReadinessProbe == nil {
		t.Fatal("routing sidecar has no readiness probe")
	}
	if len(containers[0].Env) != 1 || containers[0].Env[0].Name != "POD_NAME" || containers[0].Env[0].ValueFrom.FieldRef.FieldPath != "metadata.name" {
		t.Fatalf("gateway does not receive its stable ordinal: %+v", containers[0].Env)
	}
}

func TestActiveActiveEndpointOrderFollowsStatefulSetOrdinal(t *testing.T) {
	resolved := []applianceResolution{
		{PodName: "gateway-vpn-1", Port: "older", CreatedAt: metav1.NewTime(time.Unix(1, 0))},
		{PodName: "gateway-vpn-0", Port: "newer", CreatedAt: metav1.NewTime(time.Unix(2, 0))},
	}
	sortApplianceResolutions(resolved, true)
	if resolved[0].PodName != "gateway-vpn-0" {
		t.Fatalf("active-active endpoint order = %+v", resolved)
	}
}

func TestMergeVPNSnapshots(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	merged := mergeVPNSnapshots(backendWireGuard, []*vpnstatus.Snapshot{
		{Backend: backendWireGuard, ObservedAt: now.Add(-time.Second), Connections: map[string]vpnstatus.Connection{
			"connection": {Up: false, RXBytes: 10, AssignedAddresses: []string{"10.250.0.10"}},
		}},
		{Backend: backendWireGuard, ObservedAt: now, Connections: map[string]vpnstatus.Connection{
			"connection": {Up: true, TXBytes: 20, LastHandshakeUnix: now.Unix(), AssignedAddresses: []string{"10.250.0.11"}},
		}},
	})
	got := merged.Connections["connection"]
	if !got.Up || got.RXBytes != 10 || got.TXBytes != 20 || got.LastHandshakeUnix != now.Unix() || len(got.AssignedAddresses) != 2 {
		t.Fatalf("unexpected merged snapshot: %+v", merged)
	}
}

func TestVPNCloudInitContainsEncodedConfig(t *testing.T) {
	got := vpnCloudInit(backendIPsec, []byte(`{"peers":[]}`))
	if !strings.Contains(got, "VPN_BACKEND=ipsec") || !strings.Contains(got, "eyJwZWVycyI6W119") {
		t.Fatalf("unexpected cloud-init:\n%s", got)
	}
}

func TestLiveMigrationVirtualMachineContract(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name, gw.Namespace, gw.Spec.VPCRef.Name = "gateway", "tenant", "vpc"
	gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeLiveMigration, VirtualMachine: &sdnv1alpha1.VPNGatewayVirtualMachine{
		Image: "registry.invalid/vpn-appliance@sha256:0123456789abcdef", StateClaimName: "gateway-state",
	}}
	vm := (&VPNGatewayReconciler{}).virtualMachine(gw, "checksum")
	if got, _, _ := unstructured.NestedString(vm.Object, "spec", "template", "spec", "evictionStrategy"); got != "LiveMigrate" {
		t.Fatalf("evictionStrategy = %q, want LiveMigrate", got)
	}
	if got, _, _ := unstructured.NestedString(vm.Object, "spec", "template", "metadata", "annotations", vpnConfigChecksumAnnotation); got != "checksum" {
		t.Fatalf("config checksum = %q", got)
	}
	volumes, _, _ := unstructured.NestedSlice(vm.Object, "spec", "template", "spec", "volumes")
	if len(volumes) != 3 {
		t.Fatalf("volumes = %+v, want containerDisk, RWX state and cloud-init", volumes)
	}
}

func TestTunnelMTU(t *testing.T) {
	if got := tunnelMTU(1400, backendWireGuard); got != 1320 {
		t.Fatalf("WireGuard tunnel MTU = %d, want 1320", got)
	}
	if got := tunnelMTU(1400, backendIPsec); got != 1272 {
		t.Fatalf("IPsec tunnel MTU = %d, want 1272", got)
	}
	if got := tunnelMTU(0, backendWireGuard); got != 0 {
		t.Fatalf("unspecified VPC MTU produced %d, want 0", got)
	}
}

func TestVPNStatusPollInterval(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{}
	if got := vpnStatusPollInterval(gw); got != 15*time.Second {
		t.Fatalf("single-appliance poll = %s, want 15s", got)
	}
	gw.Spec.HighAvailability = true
	if got := vpnStatusPollInterval(gw); got != time.Second {
		t.Fatalf("HA poll = %s, want 1s", got)
	}
}

func TestReadApplianceStatusValidatesContract(t *testing.T) {
	body := `{"backend":"wireguard","observedAt":"2026-09-01T00:00:00Z","connections":{"connection":{"up":true}}}`
	r := &VPNGatewayReconciler{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://192.0.2.10:9410/status" {
			t.Fatalf("unexpected URL %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	snapshot, err := r.readApplianceStatus(context.Background(), "192.0.2.10", backendWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Connections["connection"].Up {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}

	body = `{"backend":"ipsec","observedAt":"2026-09-01T00:00:00Z","connections":{}}`
	if _, err := r.readApplianceStatus(context.Background(), "192.0.2.10", backendWireGuard); err == nil {
		t.Fatal("backend mismatch was accepted")
	}
}
