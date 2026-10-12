package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
)

func TestIPsecSecretBudgetBeforeVICICommands(t *testing.T) {
	for _, eap := range []bool{false, true} {
		p := peer{Name: "peer", RemoteID: "peer.example.invalid", PSK: "test-key", LocalCIDRs: []string{"10.10.0.0/16"}, RemoteCIDRs: []string{"203.0.113.0/24"}}
		bad := "secret-canary-" + strings.Repeat("a", vpnlimits.IPsecAuthBytes)
		if eap {
			p.AuthMode, p.PSK, p.EAPIdentity, p.EAPPassword = "eap", "", "peer@example.invalid", bad
			p.AddressPool, p.poolCIDR = "clients", "203.0.113.0/24"
		} else {
			p.PSK = bad
		}
		sess := &recordingVICI{}
		for _, err := range []error{validatePeerIdentities([]peer{p}), loadPeer(sess, p)} {
			if err == nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("oversized credential accepted or exposed")
			}
		}
		if len(sess.commands) != 0 {
			t.Fatal("oversized credential reached VICI")
		}
		want := strings.Repeat("a", vpnlimits.IPsecAuthBytes-3) + "\r\nb"
		if eap {
			p.EAPPassword = want
		} else {
			p.PSK = want
		}
		if err := loadPeer(sess, p); err != nil {
			t.Fatal(err)
		}
		if sess.requests[0].Get("data") != want {
			t.Fatal("VICI credential was normalized or truncated")
		}
	}
}

func TestIPsecTLSBudgetBeforeAnyVICICommand(t *testing.T) {
	for _, field := range []string{"certificate", "private", "ca"} {
		creds := ikeCredentials{Certificate: "certificate", PrivateKey: "key", CA: "ca"}
		bad := "secret-canary-" + strings.Repeat("a", vpnlimits.IPsecTLSBytes)
		switch field {
		case "certificate":
			creds.Certificate = bad
		case "private":
			creds.PrivateKey = bad
		case "ca":
			creds.CA = bad
		}
		sess := &recordingVICI{}
		err := loadIKECredentials(sess, creds)
		if err == nil || len(sess.commands) != 0 || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("partial or oversized TLS tuple reached VICI")
		}
		want := strings.Repeat("a", vpnlimits.IPsecTLSBytes)
		switch field {
		case "certificate":
			creds.Certificate = want
		case "private":
			creds.PrivateKey = want
		case "ca":
			creds.CA = want
		}
		if err := loadIKECredentials(sess, creds); err != nil {
			t.Fatal(err)
		}
		if len(sess.commands) != 3 {
			t.Fatal("valid TLS tuple was not fully loaded")
		}
		if sess.requests[0].Get("data") != creds.Certificate || sess.requests[1].Get("data") != creds.PrivateKey || sess.requests[2].Get("data") != creds.CA {
			t.Fatal("TLS tuple was changed")
		}
	}
}

func TestIPsecOversizedCredentialConfigStopsBeforeKernel(t *testing.T) {
	requireStartupCleanupCapability(t)
	for _, tls := range []bool{false, true} {
		cfg := config{Peers: []peer{{Name: "peer", RemoteID: "peer.example.invalid", PSK: "test-key", RemoteCIDRs: []string{"203.0.113.0/24"}}}}
		if tls {
			cfg.Credentials = &ikeCredentials{Certificate: "certificate", PrivateKey: "key", CA: strings.Repeat("a", vpnlimits.IPsecTLSBytes+1)}
		} else {
			cfg.Peers[0].PSK = strings.Repeat("a", vpnlimits.IPsecAuthBytes+1)
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		err = run(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("invalid mounted config reached kernel/startup: %v", err)
		}
	}
}
