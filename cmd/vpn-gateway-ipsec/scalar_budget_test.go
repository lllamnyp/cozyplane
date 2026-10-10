package main

import (
	"strings"
	"testing"
)

func TestIPsecScalarBudgetBeforeVICIAndRecovery(t *testing.T) {
	for _, field := range []string{"identity", "eap", "address", "local"} {
		p := peer{Name: "peer", RemoteID: "peer.example.invalid", PSK: "test-key", LocalCIDRs: []string{"10.10.0.0/16"}, RemoteCIDRs: []string{"203.0.113.0/24"}}
		large := "input-canary-" + strings.Repeat("a", 128<<10)
		switch field {
		case "identity":
			p.RemoteID = large
		case "eap":
			p.AuthMode, p.PSK, p.EAPIdentity, p.EAPPassword = "eap", "", large, "test-password"
		case "address":
			p.PeerAddress = large
		case "local":
			p.LocalID = large
		}
		sess := &recordingVICI{}
		for _, err := range []error{validatePeerIdentities([]peer{p}), loadPeer(sess, p)} {
			if err == nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") {
				t.Fatal("unbounded or absent scalar rejection")
			}
		}
		if len(sess.commands) != 0 {
			t.Fatal("invalid scalar reached VICI")
		}
	}
	p := peer{Name: "peer", RemoteID: "keyid:" + strings.Repeat("a", 4096-len("keyid:")), PeerAddress: strings.Repeat("a", 512), PSK: "test-key", LocalCIDRs: []string{"10.10.0.0/16"}, RemoteCIDRs: []string{"203.0.113.0/24"}}
	sess := &recordingVICI{}
	if err := validatePeerIdentities([]peer{p}); err != nil {
		t.Fatal(err)
	}
	if err := loadPeer(sess, p); err != nil || len(sess.commands) != 2 {
		t.Fatal("bounded identity did not recover")
	}
	if owners := sess.requests[0].Get("owners").([]string); len(owners) != 1 || owners[0] != p.RemoteID {
		t.Fatal("credential identity changed")
	}
	if err := loadIKECredentials(&recordingVICI{}, ikeCredentials{LocalID: strings.Repeat("a", 4097)}); err == nil {
		t.Fatal("oversized local identity reached certificate load")
	}
}
