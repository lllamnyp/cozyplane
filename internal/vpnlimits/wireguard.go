package vpnlimits

import (
	"encoding/base64"
	"net"
	"strconv"
	"strings"
)

// WireGuardKey rejects oversized input before the decoder can allocate.
func WireGuardKey(value string) bool {
	if len(value) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32
}

// WireGuardSecretKey preserves files produced by wg genkey/genpsk (one final
// newline). Bound the raw length before trimming or decoding any secret bytes.
func WireGuardSecretKey(value string) (string, bool) {
	if len(value) < 44 || len(value) > 46 {
		return "", false
	}
	value = strings.TrimSuffix(value, "\r\n")
	value = strings.TrimSuffix(value, "\n")
	if !WireGuardKey(value) {
		return "", false
	}
	return value, true
}

type WireGuardPeer struct {
	PublicKey  string
	PublicKeys []string
	Endpoint   string
	Endpoints  []string
	Keepalive  int64
}

func WireGuardEndpoint(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 512 {
		return false
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

// WireGuardPeerProblem is shared by admission and legacy rendering. It reports
// a single bounded diagnostic and never includes attacker-controlled values.
func WireGuardPeerProblem(in WireGuardPeer) string {
	if len(in.PublicKeys) > 2 || len(in.Endpoints) > 2 {
		return "WireGuard peer key and endpoint collections exceed two"
	}
	if in.PublicKey != "" && len(in.PublicKeys) != 0 {
		return "WireGuard single and paired public keys are mutually exclusive"
	}
	if in.PublicKey == "" && len(in.PublicKeys) != 2 {
		return "WireGuard requires a public key or exactly two paired keys"
	}
	if in.PublicKey != "" && !WireGuardKey(in.PublicKey) {
		return "WireGuard public key must encode exactly 32 bytes as canonical base64"
	}
	for _, key := range in.PublicKeys {
		if !WireGuardKey(key) {
			return "WireGuard paired public keys must encode exactly 32 bytes as canonical base64"
		}
	}
	if in.Endpoint != "" && (len(in.PublicKeys) != 0 || len(in.Endpoints) != 0) {
		return "WireGuard single and paired endpoints are mutually exclusive"
	}
	if len(in.Endpoints) != 0 && len(in.Endpoints) != len(in.PublicKeys) {
		return "WireGuard endpoints must match the paired public keys"
	}
	if !WireGuardEndpoint(in.Endpoint) {
		return "WireGuard endpoint must be host:port with a numeric UDP port and at most 512 bytes"
	}
	for _, endpoint := range in.Endpoints {
		if !WireGuardEndpoint(endpoint) {
			return "WireGuard paired endpoints must be host:port with a numeric UDP port and at most 512 bytes"
		}
	}
	if in.Keepalive < 0 || in.Keepalive > 65535 {
		return "WireGuard keepalive must be between 0 and 65535 seconds"
	}
	return ""
}
