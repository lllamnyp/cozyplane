package v1alpha1

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
)

func referenceCIDRsOverlap(a, b []string) bool {
	for _, as := range a {
		_, an, err := net.ParseCIDR(as)
		if err != nil {
			continue
		}
		for _, bs := range b {
			_, bn, err := net.ParseCIDR(bs)
			if err == nil && (an.Contains(bn.IP) || bn.Contains(an.IP)) {
				return true
			}
		}
	}
	return false
}

func TestCIDRsOverlapMatchesPairwiseDefinition(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	values := []string{"bad", "0.0.0.0/0", "::/0", "::ffff:10.0.0.1/120", "::ffff:10.0.0.1/80", "10.0.0.1/24", "2001:db8::1/64", "::ffff:0:0/96"}
	for range 200 {
		values = append(values, fmt.Sprintf("10.%d.%d.%d/%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(33)))
		values = append(values, fmt.Sprintf("2001:db8:%x::%x/%d", rng.Intn(65536), rng.Intn(65536), 32+rng.Intn(97)))
	}
	for _, a := range values[:8] {
		for _, b := range values[:8] {
			if got, want := CIDRsOverlap([]string{a}, []string{b}), referenceCIDRsOverlap([]string{a}, []string{b}); got != want {
				t.Fatalf("mapped/family parity %s %s: got=%v want=%v", a, b, got, want)
			}
		}
	}
	for range 2000 {
		a, b := []string{}, []string{}
		for range rng.Intn(16) {
			a = append(a, values[rng.Intn(len(values))])
		}
		for range rng.Intn(16) {
			b = append(b, values[rng.Intn(len(values))])
		}
		if got, want := CIDRsOverlap(a, b), referenceCIDRsOverlap(a, b); got != want {
			t.Fatalf("overlap parity: a=%v b=%v got=%v want=%v", a, b, got, want)
		}
	}
}

func BenchmarkCIDRsOverlapDisjoint(b *testing.B) {
	for _, size := range []int{128, 1024} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			a, other := make([]string, size), make([]string, size)
			for i := range size {
				a[i] = fmt.Sprintf("10.0.%d.%d/32", i/256, i%256)
				other[i] = fmt.Sprintf("172.16.%d.%d/32", i/256, i%256)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if CIDRsOverlap(a, other) {
					b.Fatal("disjoint lists overlap")
				}
			}
		})
	}
}
