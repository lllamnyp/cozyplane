package boundaryidentity

import "testing"

func TestPrimaryDigestBindsUIDIPAndOrder(t *testing.T) {
	a := PrimaryPort{"uid-a", "10.1.0.2"}
	b := PrimaryPort{"uid-b", "10.1.0.3"}
	if Digest(nil) == "" || Digest(nil) != Digest([]PrimaryPort{}) || Digest([]PrimaryPort{a, b}) != Digest([]PrimaryPort{b, a}) {
		t.Fatal("digest is empty or order-dependent")
	}
	if Digest([]PrimaryPort{a}) == Digest([]PrimaryPort{a, b}) || Digest([]PrimaryPort{a}) == Digest([]PrimaryPort{{"replacement", a.IP}}) || Digest([]PrimaryPort{a}) == Digest([]PrimaryPort{{a.UID, "10.1.0.9"}}) {
		t.Fatal("identity change retained acknowledgement")
	}
}
