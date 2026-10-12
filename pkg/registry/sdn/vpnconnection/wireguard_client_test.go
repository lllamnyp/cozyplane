package vpnconnection

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func clientFixture() *sdn.VPNConnection {
	return &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
		GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
		WireGuard: &sdn.VPNConnectionWireGuard{
			PeerPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Client:        &sdn.VPNWireGuardClient{AddressPools: []string{"workstations"}, VPCRefs: []sdn.LocalVPCRef{{Name: "app"}}},
		},
	}}
}

func TestWireGuardClientAdmission(t *testing.T) {
	strategy := NewStrategy(nil)
	if errs := strategy.Validate(t.Context(), clientFixture()); len(errs) != 0 {
		t.Fatal("valid client rejected", errs)
	}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.VPNConnection)
	}{
		{"remote CIDRs", func(c *sdn.VPNConnection) { c.Spec.RemoteCIDRs = []string{"198.18.0.0/24"} }},
		{"missing public key", func(c *sdn.VPNConnection) { c.Spec.WireGuard.PeerPublicKey = "" }},
		{"fixed endpoint", func(c *sdn.VPNConnection) { c.Spec.WireGuard.PeerEndpoint = "192.0.2.1:51820" }},
		{"paired keys", func(c *sdn.VPNConnection) { c.Spec.WireGuard.PeerPublicKeys = []string{c.Spec.WireGuard.PeerPublicKey} }},
		{"missing pool", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client.AddressPools = nil }},
		{"missing VPC", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client.VPCRefs = nil }},
		{"duplicate VPC", func(c *sdn.VPNConnection) {
			c.Spec.WireGuard.Client.VPCRefs = []sdn.LocalVPCRef{{Name: "app"}, {Name: "app"}}
		}},
		{"too many VPCs", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client.VPCRefs = make([]sdn.LocalVPCRef, 11) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := clientFixture()
			test.mutate(c)
			if errs := strategy.Validate(t.Context(), c); len(errs) == 0 {
				t.Fatal("invalid client admitted")
			}
		})
	}
}

func TestWireGuardClientImmutableAllocationIdentity(t *testing.T) {
	strategy := NewStrategy(nil)
	for _, test := range []struct {
		name    string
		mutate  func(*sdn.VPNConnection)
		allowed bool
	}{
		{"unchanged", func(*sdn.VPNConnection) {}, true},
		{"gateway", func(c *sdn.VPNConnection) { c.Spec.GatewayRef.Name = "replacement" }, false},
		{"pools", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client.AddressPools = []string{"replacement"} }, false},
		{"mode", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client = nil }, false},
		{"key rotation", func(c *sdn.VPNConnection) {
			c.Spec.WireGuard.PeerPublicKey = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}, true},
		{"VPC permissions", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client.VPCRefs = []sdn.LocalVPCRef{{Name: "db"}} }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := clientFixture()
			test.mutate(c)
			errs := strategy.ValidateUpdate(t.Context(), c, clientFixture())
			if (len(errs) == 0) != test.allowed {
				t.Fatal("unexpected immutability result", errs)
			}
		})
	}
	old := clientFixture()
	old.Spec.WireGuard.Client = nil
	if errs := strategy.ValidateUpdate(t.Context(), clientFixture(), old); len(errs) == 0 {
		t.Fatal("site-to-site connection converted to client in place")
	}
}

func TestWireGuardClientBoundedAPIStatus(t *testing.T) {
	c := clientFixture()
	c.Spec.WireGuard.Client.VPCRefs[0].Name = "input-canary-" + strings.Repeat("a", 1<<20)
	errs := NewStrategy(nil).Validate(t.Context(), c)
	if len(errs) != 1 {
		t.Fatal("expected a bounded error", len(errs))
	}
	status := apierrors.NewInvalid(schema.GroupKind{Group: sdn.GroupName, Kind: "VPNConnection"}, "workstation", errs).Status()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 2048 || strings.Contains(string(raw), "input-canary") {
		t.Fatal("APIStatus amplified the invalid input")
	}
}

func TestWireGuardClientGeneration(t *testing.T) {
	strategy := NewStrategy(nil)
	created := clientFixture()
	created.Generation = 99
	strategy.PrepareForCreate(t.Context(), created)
	if created.Generation != 1 {
		t.Fatal("new client generation was not initialized")
	}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.VPNConnection)
		want   int64
	}{
		{"unchanged", func(*sdn.VPNConnection) {}, 7},
		{"metadata", func(c *sdn.VPNConnection) { c.Finalizers = []string{"example.invalid/revoke"} }, 7},
		{"key rotation", func(c *sdn.VPNConnection) {
			c.Spec.WireGuard.PeerPublicKey = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}, 8},
		{"permissions", func(c *sdn.VPNConnection) { c.Spec.WireGuard.Client.VPCRefs = []sdn.LocalVPCRef{{Name: "db"}} }, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			old, current := clientFixture(), clientFixture()
			old.Generation, current.Generation = 7, 99
			test.mutate(current)
			strategy.PrepareForUpdate(t.Context(), current, old)
			if current.Generation != test.want {
				t.Fatal("unexpected generation", current.Generation)
			}
		})
	}
	old, current := clientFixture(), clientFixture()
	old.Generation, current.Generation = 7, 99
	NewStatusStrategy(strategy).PrepareForUpdate(t.Context(), current, old)
	if current.Generation != 7 {
		t.Fatal("status update changed generation")
	}
	legacy := clientFixture()
	legacy.Spec.WireGuard.Client = nil
	legacy.Generation = 99
	strategy.PrepareForCreate(t.Context(), legacy)
	if legacy.Generation != 99 {
		t.Fatal("legacy site-to-site generation behavior changed")
	}
}

func TestWireGuardClientMalformedLegacyCleanup(t *testing.T) {
	old, current := clientFixture(), clientFixture()
	old.Spec.WireGuard.Client.VPCRefs[0].Name = "invalid/reference"
	current.Spec.WireGuard.Client.VPCRefs[0].Name = "invalid/reference"
	current.Finalizers = nil
	strategy := NewStrategy(nil)
	if errs := strategy.ValidateUpdate(t.Context(), current, old); len(errs) != 0 {
		t.Fatal("unchanged malformed legacy client blocks metadata cleanup", errs)
	}
	current.Spec.WireGuard.PeerPublicKey = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if errs := strategy.ValidateUpdate(t.Context(), current, old); len(errs) == 0 {
		t.Fatal("changed malformed client bypasses validation")
	}
}
