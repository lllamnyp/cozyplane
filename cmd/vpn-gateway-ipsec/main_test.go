package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

func TestCollectIPsecMetricsAggregatesRekeyedSAs(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	events := []*vici.Message{
		ipsecSAEvent(t, "connection-a", "INSTALLED", 100, 200, 3, 4, 30),
		ipsecSAEvent(t, "connection-a", "INSTALLED", 10, 20, 1, 2, 5),
	}

	got := collectIPsecMetrics(events, []peer{{Name: "connection-a"}, {Name: "connection-b"}}, now)
	if got["connection-a"].RXBytes != 110 || got["connection-a"].TXBytes != 220 {
		t.Fatalf("unexpected byte counters: %+v", got["connection-a"])
	}
	if got["connection-a"].RXPackets != 4 || got["connection-a"].TXPackets != 6 {
		t.Fatalf("unexpected packet counters: %+v", got["connection-a"])
	}
	if got["connection-a"].Up != 1 || got["connection-a"].LastHandshakeSec != now.Add(-5*time.Second).Unix() {
		t.Fatalf("unexpected state metrics: %+v", got["connection-a"])
	}
	if len(got["connection-a"].AssignedAddresses) != 1 || got["connection-a"].AssignedAddresses[0] != "10.250.0.10" {
		t.Fatalf("unexpected assigned addresses: %+v", got["connection-a"].AssignedAddresses)
	}
	if !reflect.DeepEqual(got["connection-b"], ipsecConnectionMetrics{}) {
		t.Fatalf("connection without an SA must remain zero: %+v", got["connection-b"])
	}

	text := formatIPsecMetrics(got)
	for _, want := range []string{
		`cozyplane_vpn_connection_up{connection="connection-a",backend="ipsec"} 1`,
		`cozyplane_vpn_connection_rx_bytes_total{connection="connection-b",backend="ipsec"} 0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, text)
		}
	}
}

func TestIPsecStartAction(t *testing.T) {
	tests := []struct {
		name string
		peer peer
		want string
	}{
		{name: "legacy initiator", peer: peer{PeerAddress: "192.0.2.10"}, want: "start"},
		{name: "legacy responder", peer: peer{}, want: "none"},
		{name: "explicit initiator", peer: peer{PeerAddress: "192.0.2.10", StartAction: "start"}, want: "start"},
		{name: "explicit responder with known address", peer: peer{PeerAddress: "192.0.2.10", StartAction: "none"}, want: "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipsecStartAction(tt.peer); got != tt.want {
				t.Fatalf("ipsecStartAction() = %q, want %q", got, tt.want)
			}
		})
	}
}

type recordingVICI struct {
	commands []string
	requests []*vici.Message
}

func TestPeerIdentityCollection(t *testing.T) {
	for _, mode := range []string{"psk", "certificate", "eap"} {
		peers := []peer{
			{Name: "peer-a", AuthMode: mode, RemoteID: "peer.example.invalid", EAPIdentity: "peer@example.invalid"},
			{Name: "peer-b", AuthMode: mode, RemoteID: "@PEER.example.invalid", EAPIdentity: "email:PEER@example.invalid"},
		}
		if err := validatePeerIdentities(peers); err == nil {
			t.Errorf("accepted duplicate %s authorization", mode)
		}
		peers[1].RemoteID = "other.example.invalid"
		peers[1].EAPIdentity = "other@example.invalid"
		if err := validatePeerIdentities(peers); err != nil {
			t.Errorf("rejected distinct %s identities: %v", mode, err)
		}
	}
}

func (s *recordingVICI) CommandRequest(command string, request *vici.Message) (*vici.Message, error) {
	s.commands = append(s.commands, command)
	s.requests = append(s.requests, request)
	response := vici.NewMessage()
	_ = response.Set("success", "yes")
	return response, nil
}

func TestPeerCredentialAndTrafficIsolation(t *testing.T) {
	s := &recordingVICI{}
	p := peer{Name: "peer-a", PSK: "test-credential", RemoteID: "192.0.2.10", LocalCIDRs: []string{"10.10.0.0/16"}, RemoteCIDRs: []string{"10.20.0.0/16"}, IfID: 7}
	if err := loadPeer(s, p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.commands, []string{"load-shared", "load-conn"}) {
		t.Fatalf("commands = %v", s.commands)
	}
	if owners := s.requests[0].Get("owners"); !reflect.DeepEqual(owners, []string{p.RemoteID}) {
		t.Fatalf("credential owners = %v", owners)
	}
	conn := s.requests[1].Get(p.Name).(*vici.Message)
	remote := conn.Get("remote").(*vici.Message)
	if remote.Get("id") != p.RemoteID {
		t.Fatalf("remote identity = %v", remote.Get("id"))
	}
	children := conn.Get("children").(*vici.Message)
	child := children.Get(p.Name).(*vici.Message)
	if selectors := child.Get("remote_ts"); !reflect.DeepEqual(selectors, p.RemoteCIDRs) {
		t.Fatalf("remote traffic selectors = %v", selectors)
	}
	for _, identity := range []string{"", "%any", "*.example.invalid", "^peer.*", "0.0.0.0", "::", "0::0", "10.0.0.0/8", "{0}:peer", "fqdn:^peer[0-9]+$", "\x00"} {
		p.RemoteID = identity
		if err := loadPeer(&recordingVICI{}, p); err == nil {
			t.Fatalf("accepted unrestricted identity %q", identity)
		}
	}
}

func ipsecSAEvent(t *testing.T, name, state string, rxBytes, txBytes, rxPackets, txPackets, established uint64) *vici.Message {
	t.Helper()
	child := vici.NewMessage()
	for key, value := range map[string]any{
		"name": name, "state": state, "bytes-in": rxBytes, "bytes-out": txBytes,
		"packets-in": rxPackets, "packets-out": txPackets,
	} {
		if err := child.Set(key, value); err != nil {
			t.Fatal(err)
		}
	}
	children := vici.NewMessage()
	if err := children.Set(name+"-1", child); err != nil {
		t.Fatal(err)
	}
	ike := vici.NewMessage()
	if err := ike.Set("established", established); err != nil {
		t.Fatal(err)
	}
	if err := ike.Set("child-sas", children); err != nil {
		t.Fatal(err)
	}
	if err := ike.Set("remote-vips", []string{"10.250.0.10"}); err != nil {
		t.Fatal(err)
	}
	event := vici.NewMessage()
	if err := event.Set(name, ike); err != nil {
		t.Fatal(err)
	}
	return event
}
