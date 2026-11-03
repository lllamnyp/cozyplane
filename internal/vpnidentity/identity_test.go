package vpnidentity

import (
	"strings"
	"testing"
)

func TestIdentityByteBudgetBeforeParsing(t *testing.T) {
	boundary := "keyid:" + strings.Repeat("a", MaxIdentityBytes-len("keyid:"))
	if !Exact(boundary) || Key(boundary) != boundary {
		t.Fatal("bounded exact key-ID identity changed")
	}
	for _, identity := range []string{boundary + "a", "CN=" + strings.Repeat("a", 128<<10), strings.Repeat("a", 128<<10)} {
		if Exact(identity) {
			t.Fatal("oversized identity parsed as exact")
		}
	}
}

func TestExactStrongSwanIdentity(t *testing.T) {
	for _, identity := range []string{"", "%any", "0.0.0.0", "::", "0::0", "10.0.0.0/8", "192.0.2.1-192.0.2.20", "ipv4net:network", "IPV6range:range", "{0}:peer", "{0x0}:peer", "fqdn:^peer[0-9]+$", "fqdn:#2a", "\x00", "peer\x00ignored", "peer\t", " peer", "*.example.invalid"} {
		if Exact(identity) {
			t.Errorf("accepted non-exact identity %q", identity)
		}
	}
	for _, identity := range []string{"192.0.2.10", "2001:db8::10", "peer.example.invalid", "@peer.example.invalid", "peer@example.invalid", "CN=peer, O=example", "keyid:peer-a"} {
		if !Exact(identity) {
			t.Errorf("rejected exact identity %q", identity)
		}
	}
}

func TestEquivalentIdentityKeys(t *testing.T) {
	for _, pair := range [][2]string{
		{"peer.example.invalid", "@PEER.example.invalid"},
		{"@peer.example.invalid", "DNS:peer.example.invalid"},
		{"peer@example.invalid", "@@PEER@example.invalid"},
		{"email:peer@example.invalid", "userfqdn:PEER@example.invalid"},
		{"2001:db8::10", "2001:0db8:0:0:0:0:0:10"},
		{"opaque:peer", "KEYID:opaque:peer"},
		{"CN=peer, E=peer@example.invalid", "cn = PEER,emailAddress=PEER@example.invalid"},
		{"CN=peer, EN=42", "CN==peer, employeeNumber=42"},
	} {
		if Key(pair[0]) != Key(pair[1]) {
			t.Errorf("equivalent keys differ: %q %q", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"192.0.2.10", "ipv4:192.0.2.10"},
		{"192.0.2.10", "::ffff:192.0.2.10"},
		{"keyid:peer", "keyid:PEER"},
		{"fqdn:peer", "keyid:peer"},
		{"CN=peer@example.invalid", "CN=PEER@example.invalid"},
		{"UN=peer", "UN=PEER"},
	} {
		if Key(pair[0]) == Key(pair[1]) {
			t.Errorf("distinct keys collide: %q %q", pair[0], pair[1])
		}
	}
}

func TestDNGrammar(t *testing.T) {
	for _, identity := range []string{"CN=peer,", "CN=", "unknown=peer", "CN peer,O=example", "CN=peer,,O=example"} {
		if Exact(identity) {
			t.Errorf("accepted ambiguous DN %q", identity)
		}
	}
	for _, identity := range []string{"CN=peer, O=example", "keyid:unknown=peer", "fqdn:peer=example"} {
		if !Exact(identity) {
			t.Errorf("rejected exact identity %q", identity)
		}
	}
}
