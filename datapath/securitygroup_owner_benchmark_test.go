package datapath

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

var ownerBenchmarkResult [4]uint64

func BenchmarkSGEndpointOwner(b *testing.B) {
	uid := "00000000-0000-0000-0000-000000000001"
	container := strings.Repeat("a", 64)
	b.ReportAllocs()
	for b.Loop() {
		ownerBenchmarkResult = SGEndpointOwner(uid, container, "eth0")
	}
}

func TestSGEndpointOwnerBoundedDigest(t *testing.T) {
	for _, parts := range [][3]string{
		{"port", "sandbox", "eth0"},
		{"00000000-0000-0000-0000-000000000001", strings.Repeat("a", 64), "net1"},
		{strings.Repeat("a", 240), "b", strings.Repeat("c", 12)}, // exactly 255 bytes
	} {
		digest := sha256.Sum256([]byte(parts[0] + "\x00" + parts[1] + "\x00" + parts[2]))
		want := [4]uint64{binary.LittleEndian.Uint64(digest[:8]), binary.LittleEndian.Uint64(digest[8:16]), binary.LittleEndian.Uint64(digest[16:24]), binary.LittleEndian.Uint64(digest[24:])}
		if got := SGEndpointOwner(parts[0], parts[1], parts[2]); got != want {
			t.Fatal("valid witness digest changed", got, want)
		}
	}
	for _, parts := range [][3]string{{"", "sandbox", "eth0"}, {"port", "", "eth0"}, {"port", "sandbox", ""}, {strings.Repeat("a", 241), "b", strings.Repeat("c", 12)}, {"port", strings.Repeat("x", 256), "eth0"}} {
		if got := SGEndpointOwner(parts[0], parts[1], parts[2]); got != [4]uint64{} {
			t.Fatal("unrepresentable witness authorized an endpoint", got)
		}
	}
}
