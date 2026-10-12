package vpnlimits

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWireGuardKeyAndEndpointBoundaries(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if !WireGuardKey(valid) {
		t.Fatal("canonical 32-byte key rejected")
	}
	for _, ending := range []string{"", "\n", "\r\n"} {
		if key, ok := WireGuardSecretKey(valid + ending); !ok || key != valid {
			t.Fatal("ordinary WireGuard key file changed identity")
		}
	}
	if _, ok := WireGuardSecretKey(strings.Repeat("A", 128<<10)); ok {
		t.Fatal("oversized secret key accepted")
	}
	for _, value := range []string{"", strings.Repeat("A", 128<<10), base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33)), strings.TrimSuffix(valid, "="), valid[:42] + "B=", valid + "\n"} {
		if WireGuardKey(value) {
			t.Fatal("invalid/noncanonical key accepted")
		}
	}
	for _, endpoint := range []string{"", "192.0.2.1:1", "[2001:db8::1]:65535", "peer.example.invalid:51820", "[fe80::1%eth0]:51820"} {
		if !WireGuardEndpoint(endpoint) {
			t.Fatalf("valid endpoint refused: %s", endpoint)
		}
	}
	for _, endpoint := range []string{strings.Repeat("a", 128<<10) + ":51820", "192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:-1", ":51820", "peer.example.invalid:http", "2001:db8::1:51820"} {
		if WireGuardEndpoint(endpoint) {
			t.Fatal("invalid endpoint accepted")
		}
	}
}
