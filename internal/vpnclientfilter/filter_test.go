package vpnclientfilter

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestCompileRejectsAmbiguousSources(t *testing.T) {
	tests := []struct {
		name  string
		peers []Peer
		local []netip.Addr
	}{
		{"subnet", []Peer{{Addresses: []string{"10.200.0.0/24"}, Destinations: []string{"10.1.0.0/24"}}}, nil},
		{"duplicate", []Peer{{Addresses: []string{"10.200.0.2/32"}, Destinations: []string{"10.1.0.0/24"}}, {Addresses: []string{"10.200.0.2/32"}, Destinations: []string{"10.2.0.0/24"}}}, nil},
		{"appliance", []Peer{{Addresses: []string{"10.200.0.2/32"}, Destinations: []string{"10.1.0.0/24"}}}, []netip.Addr{netip.MustParseAddr("10.200.0.2")}},
		{"mapped", []Peer{{Addresses: []string{"::ffff:10.200.0.2/128"}, Destinations: []string{"10.1.0.0/24"}}}, nil},
		{"missing grants", []Peer{{Addresses: []string{"10.200.0.2/32"}}}, nil},
		{"internet", []Peer{{Addresses: []string{"10.200.0.2/32"}, Destinations: []string{"0.0.0.0/0"}}}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := compile(test.peers, test.local); err == nil {
				t.Fatal("accepted unsafe policy")
			}
		})
	}
}

func TestCompileBoundsDuplicateDestinationWork(t *testing.T) {
	peers := make([]Peer, 17)
	for index := range peers {
		peers[index].Addresses = []string{fmt.Sprintf("10.200.0.%d/32", index+2)}
		peers[index].Destinations = make([]string, 4096)
		for destination := range peers[index].Destinations {
			peers[index].Destinations[destination] = "10.1.0.0/24"
		}
	}
	if _, err := compile(peers, nil); err == nil {
		t.Fatal("duplicate input must still consume bounded work budget")
	}
}

func BenchmarkCompileClientPolicy(b *testing.B) {
	peers := make([]Peer, 16)
	for index := range peers {
		peers[index] = Peer{Addresses: []string{fmt.Sprintf("10.200.0.%d/32", index+2)}, Destinations: []string{"10.1.0.0/24", "10.2.0.0/24"}}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := compile(peers, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCompileFamilyIdentityAndDenyPrecedence(t *testing.T) {
	r, err := compile([]Peer{{Addresses: []string{"10.200.0.2/32", "fd00:200::2/128"}, Destinations: []string{"10.1.0.0/24", "fd00:1::/64"}}}, []netip.Addr{netip.MustParseAddr("10.1.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.sources) != 2 || len(r.denied) != 3 || len(r.destinations) != 2 {
		t.Fatalf("unexpected policy: %+v", r)
	}
	v4, _ := addressKey(netip.MustParseAddr("10.200.0.2"))
	v6, _ := addressKey(netip.MustParseAddr("64:ff9b::10.200.0.2"))
	if v4.Address != v6.Address || v4.Family == v6.Family {
		t.Fatal("family must disambiguate shared RFC6052 bytes")
	}
	if _, ok := r.sources[v6]; ok {
		t.Fatal("IPv6 source inherited IPv4 identity")
	}
}
