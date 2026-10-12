package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/strongswan/govici/vici"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func requireStartupCleanupCapability(t *testing.T) {
	t.Helper()
	if _, err := netlink.XfrmStateList(netlink.FAMILY_ALL); errors.Is(err, unix.EPERM) {
		t.Skip("mounted-config startup now revokes kernel state before reading; requires CAP_NET_ADMIN")
	} else if err != nil {
		t.Fatal(err)
	}
}

type replyVICI struct{ response *vici.Message }

func (s replyVICI) CommandRequest(string, *vici.Message) (*vici.Message, error) {
	return s.response, nil
}

func TestVICIRequiresExplicitAcknowledgement(t *testing.T) {
	for _, response := range []*vici.Message{nil, vici.NewMessage(), viciMessage(map[string]any{"success": "no", "errmsg": "secret-canary"}), viciMessage(map[string]any{"success": "YES"}), viciMessage(map[string]any{"success": []string{"yes"}})} {
		err := sendVICIMessage(replyVICI{response}, "load-key", vici.NewMessage())
		if err == nil || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("unacknowledged request accepted or secret leaked", err)
		}
	}
	if err := sendVICIMessage(replyVICI{viciMessage(map[string]any{"success": "yes"})}, "load-key", vici.NewMessage()); err != nil {
		t.Fatal(err)
	}
}

func viciMessage(values map[string]any) *vici.Message {
	m := vici.NewMessage()
	for k, v := range values {
		if err := m.Set(k, v); err != nil {
			panic(err)
		}
	}
	return m
}

func TestIPsecExpectedConfigRejectsStaleSecret(t *testing.T) {
	raw := []byte(`{"peers":[]}`)
	if err := checkExpectedConfig(raw, configChecksum([]byte(`{"peers":[{}]}`))); err == nil {
		t.Fatal("stale secret accepted")
	}
	for _, expected := range []string{"", configChecksum(raw)} {
		if err := checkExpectedConfig(raw, expected); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIPsecInvalidSelectorsDoNotLoadCredentials(t *testing.T) {
	base := peer{Name: "peer", RemoteID: "peer.example.invalid", PSK: "test-key", LocalCIDRs: []string{"10.1.0.0/24"}, RemoteCIDRs: []string{"10.2.0.0/24"}}
	for _, bad := range [][]string{nil, {"0.0.0.0/0"}, {"::/0"}, {"::ffff:10.1.0.0/120"}, {"secret-canary"}, {"224.0.0.0/4"}} {
		p := base
		p.LocalCIDRs = bad
		s := &recordingVICI{}
		if err := loadPeer(s, p); err == nil || len(s.commands) != 0 || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("invalid selectors reached VICI", err)
		}
	}
	s := &recordingVICI{}
	if err := loadPeer(s, base); err != nil {
		t.Fatal(err)
	}
	conn := s.requests[1].Get(base.Name).(*vici.Message)
	children := conn.Get("children").(*vici.Message)
	child := children.Get(base.Name).(*vici.Message)
	selectors := child.Get("local_ts").([]string)
	if len(selectors) != 1 || selectors[0] != base.LocalCIDRs[0] {
		t.Fatal("local selector was broadened", selectors)
	}
}
