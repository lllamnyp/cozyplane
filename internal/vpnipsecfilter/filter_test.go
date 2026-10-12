package vpnipsecfilter

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPolicyBoundsAndNativeFamilies(t *testing.T) {
	for _, prefixes := range [][]string{nil, {"0.0.0.0/0"}, {"::/0"}, {"::ffff:10.1.0.0/120"}, {"224.0.0.0/4"}, {strings.Repeat("a", 65)}, make([]string, 4097)} {
		if _, err := compile(prefixes, nil); err == nil {
			t.Fatalf("invalid prefixes accepted %d", len(prefixes))
		}
	}
	if _, err := compile([]string{"10.1.0.0/24"}, make([]netip.Addr, 1025)); err == nil {
		t.Fatal("local capacity exceeded")
	}
	r, err := compile([]string{"10.1.0.1/24", "10.1.0.0/24", "fd00:1::/64"}, []netip.Addr{netip.MustParseAddr("10.1.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.destinations) != 2 || len(r.denied) != 1 {
		t.Fatal("prefixes not canonicalized", r)
	}
	v4, err := addressKey(netip.MustParseAddr("10.1.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	v6, err := addressKey(netip.MustParseAddr("64:ff9b::10.1.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if v4.Address != v6.Address || v4.Family == v6.Family {
		t.Fatal("native family isolation lost")
	}
}
