package main

import (
	"reflect"
	"testing"

	"github.com/strongswan/govici/vici"
)

func TestSharedPoolUsesOneInterfaceAndDistinctTrafficSelectors(t *testing.T) {
	cfg := config{LocalID: "vpn.example.invalid", Credentials: &ikeCredentials{LocalID: "legacy.example.invalid"}, Pools: []addressPool{{Name: "clients", CIDR: "10.200.0.0/24"}}, Peers: []peer{
		{Name: "peer-a", IfID: 7, AddressPool: "clients", AuthMode: "eap", EAPIdentity: "peer-a.example.invalid", EAPPassword: "test-key", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.200.0.0/24", "10.20.0.0/24"}},
		{Name: "peer-b", IfID: 7, AddressPool: "clients", AuthMode: "eap", EAPIdentity: "peer-b.example.invalid", EAPPassword: "test-key", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.200.0.0/24", "10.30.0.0/24"}},
	}}
	peers, err := configuredPeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := groupXfrmPeers(peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || !reflect.DeepEqual(groups[0].RemoteCIDRs, []string{"10.20.0.0/24", "10.200.0.0/24", "10.30.0.0/24"}) {
		t.Fatal("shared route overwritten or lost", groups)
	}
	for index, p := range peers {
		if p.LocalID != cfg.LocalID {
			t.Fatal("global identity ignored")
		}
		s := &recordingVICI{}
		if err := loadPeer(s, p); err != nil {
			t.Fatal(err)
		}
		conn := s.requests[1].Get(p.Name).(*vici.Message)
		children := conn.Get("children").(*vici.Message)
		child := children.Get(p.Name).(*vici.Message)
		if selectors := child.Get("remote_ts"); !reflect.DeepEqual(selectors, []string{"dynamic", p.RemoteCIDRs[1]}) {
			t.Fatal("pool source authorization broadened", index, selectors)
		}
	}
	if cfg.Peers[0].poolCIDR != "" || cfg.Peers[0].LocalID != "" {
		t.Fatal("config input mutated")
	}
	for _, bad := range []peer{
		{IfID: 7, AddressPool: "other", LocalCIDRs: []string{"10.1.0.0/24"}},
		{IfID: 7, LocalCIDRs: []string{"10.1.0.0/24"}},
		{IfID: 7, AddressPool: "clients", LocalCIDRs: []string{"10.2.0.0/24"}},
	} {
		if _, err := groupXfrmPeers([]peer{peers[0], bad}); err == nil {
			t.Fatal("independent policies shared interface")
		}
	}
}

func TestPoolAuthenticationParityBeforeVICI(t *testing.T) {
	for _, p := range []peer{
		{Name: "peer", AuthMode: "psk", RemoteID: "peer.example.invalid", PSK: "test-key", AddressPool: "clients", poolCIDR: "10.200.0.0/24", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.200.0.0/24"}},
		{Name: "peer", AuthMode: "eap", EAPIdentity: "peer.example.invalid", EAPPassword: "test-key", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.200.0.0/24"}},
	} {
		s := &recordingVICI{}
		if err := loadPeer(s, p); err == nil || len(s.commands) != 0 {
			t.Fatal("unsupported pool/auth combination reached VICI", err)
		}
	}
}

func TestEAPUsesPackagedMethodAndExactIKEProfileIdentity(t *testing.T) {
	for _, identity := range []string{"peer-a.example.invalid", "peer-b.example.invalid"} {
		p := peer{Name: "peer", AuthMode: "eap", LocalID: "vpn.example.invalid", EAPIdentity: identity, EAPPassword: "fixture-password", AddressPool: "clients", poolCIDR: "10.200.0.0/24", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.200.0.0/24"}}
		s := &recordingVICI{}
		if err := loadPeer(s, p); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(s.commands, []string{"load-shared", "load-conn"}) {
			t.Fatal("unexpected EAP load sequence", s.commands)
		}
		secret := s.requests[0]
		if secret.Get("type") != "EAP" || !reflect.DeepEqual(secret.Get("owners"), []string{identity}) {
			t.Fatal("EAP credential not restricted to this identity")
		}
		conn := s.requests[1].Get(p.Name).(*vici.Message)
		remote := conn.Get("remote").(*vici.Message)
		if remote.Get("auth") != "eap-mschapv2" || remote.Get("id") != identity || remote.Get("eap_id") != identity {
			t.Fatal("EAP profile must use the packaged method and exact IKE/EAP identities")
		}
		local := conn.Get("local").(*vici.Message)
		if local.Get("auth") != "pubkey" || local.Get("id") != p.LocalID {
			t.Fatal("EAP responder certificate identity lost")
		}
	}
}

func TestPooledSelectorRequiresResolutionBeforeVICI(t *testing.T) {
	p := peer{Name: "peer", AddressPool: "clients", RemoteID: "peer.example.invalid", PSK: "test-key", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.200.0.0/24"}}
	s := &recordingVICI{}
	if err := loadPeer(s, p); err == nil || len(s.commands) != 0 {
		t.Fatal("unresolved pool reached VICI")
	}
	if _, err := configuredPeers(config{Peers: []peer{p}}); err == nil {
		t.Fatal("unknown pool accepted")
	}
}
