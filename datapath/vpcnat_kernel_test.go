package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelVPCNATIdentityRotationAndReplacement(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	clear(spec.Programs)
	for name, mp := range spec.Maps {
		if name != "vpc_nat" && name != "nat_of" && name != "nat_owner" {
			delete(spec.Maps, name)
			continue
		}
		mp.Pinning = ebpf.PinNone
	}
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		VpcNat: c.Maps["vpc_nat"], NatOf: c.Maps["nat_of"], NatOwner: c.Maps["nat_owner"],
	}}}
	t.Run("rotation removes old reverse ownership", func(t *testing.T) {
		for _, address := range []string{"203.0.113.1", "203.0.113.2"} {
			if err := m.SetVPCNAT(101, address, "", NATPortBase, NATShardSpan); err != nil {
				t.Fatal(err)
			}
		}
		old, _ := addr128Str("203.0.113.1")
		var owner uint32
		if err := c.Maps["nat_of"].Lookup(old, &owner); !isNotExist(err) {
			t.Fatalf("withdrawn NAT address retains owner=%d err=%v", owner, err)
		}
		current, _ := addr128Str("203.0.113.2")
		if err := c.Maps["nat_of"].Lookup(current, &owner); err != nil || owner != 101 {
			t.Fatal("current reverse ownership missing", owner, err)
		}
	})
	t.Run("old VPC deletion preserves replacement reverse ownership", func(t *testing.T) {
		address := "203.0.113.3"
		if err := m.SetVPCNAT(101, address, "", NATPortBase, NATShardSpan); err != nil {
			t.Fatal(err)
		}
		if err := m.SetVPCNAT(102, address, "", NATPortBase, NATShardSpan); err != nil {
			t.Fatal(err)
		}
		if err := m.DelVPCNAT(101, address, ""); err != nil {
			t.Fatal(err)
		}
		key, _ := addr128Str(address)
		var owner uint32
		if err := c.Maps["nat_of"].Lookup(key, &owner); err != nil || owner != 102 {
			t.Fatal("old VPC erased replacement reverse ownership", owner, err)
		}
	})
	t.Run("complete reverse projection prunes orphan addresses and shards", func(t *testing.T) {
		identities := map[uint32]NATIdentity{102: {V4: "203.0.113.3", V6: "2001:db8::3"}}
		nodes := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
		if err := m.SyncNATReverse(identities, nodes); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncNATReverse(identities, nodes[:1]); err != nil {
			t.Fatal(err)
		}
		var key overlayAddr128
		var owner uint32
		it := c.Maps["nat_of"].Iterate()
		count := 0
		for it.Next(&key, &owner) {
			count++
			if owner != 102 {
				t.Fatal("orphan reverse address retained", owner)
			}
		}
		if err := it.Err(); err != nil || count != 2 {
			t.Fatal("incomplete reverse projection", count, err)
		}
		var shardKey overlayNatShardKey
		it = c.Maps["nat_owner"].Iterate()
		count = 0
		for it.Next(&shardKey, &owner) {
			count++
			if shardKey.Shard != 0 || owner != 0xc0000201 {
				t.Fatal("retired node shard retained", shardKey.Shard, owner)
			}
		}
		if err := it.Err(); err != nil || count != 2 {
			t.Fatal("incomplete shard projection", count, err)
		}
		// A node can lose its local SNAT shard while still receiving replies.
		if err := m.DelVPCNAT(102, "", ""); err != nil {
			t.Fatal(err)
		}
		current, _ := addr128Str("203.0.113.3")
		if err := c.Maps["nat_of"].Lookup(current, &owner); err != nil || owner != 102 {
			t.Fatal("local shard retirement removed global reverse ownership", owner, err)
		}
		// A known shard without a current node endpoint is not routable.
		if err := m.SyncNATReverse(identities, []net.IP{nil}); err != nil {
			t.Fatal(err)
		}
		it = c.Maps["nat_owner"].Iterate()
		if it.Next(&shardKey, &owner) || it.Err() != nil {
			t.Fatal("missing endpoint retained routing authority", it.Err())
		}
	})
	t.Run("ambiguous ownership and invalid addresses preserve projection", func(t *testing.T) {
		for _, invalid := range []map[uint32]NATIdentity{
			{101: {V4: "203.0.113.3"}, 102: {V4: "203.0.113.3"}},
			{101: {V4: "2001:db8::3"}},
			{101: {V6: "203.0.113.3"}},
		} {
			if err := m.SyncNATReverse(invalid, nil); err == nil {
				t.Fatal("invalid projection accepted")
			}
			key, _ := addr128Str("203.0.113.3")
			var owner uint32
			if err := c.Maps["nat_of"].Lookup(key, &owner); err != nil || owner != 102 {
				t.Fatal("invalid projection mutated existing ownership", owner, err)
			}
		}
	})
	t.Run("preflight both map capacities before any mutation", func(t *testing.T) {
		for _, name := range []string{"nat_of", "nat_owner"} {
			t.Run(name, func(t *testing.T) {
				smallSpec := *spec.Maps[name]
				smallSpec.MaxEntries = 1
				small, err := ebpf.NewMap(&smallSpec)
				if err != nil {
					t.Fatal(err)
				}
				defer small.Close()
				if name == "nat_of" {
					m.objs.NatOf = small
					defer func() { m.objs.NatOf = c.Maps["nat_of"] }()
				} else {
					m.objs.NatOwner = small
					defer func() { m.objs.NatOwner = c.Maps["nat_owner"] }()
				}
				old := map[uint32]NATIdentity{102: {V4: "203.0.113.3"}}
				nodes := []net.IP{net.ParseIP("192.0.2.1")}
				if err := m.SyncNATReverse(old, nodes); err != nil {
					t.Fatal(err)
				}
				tooLarge := map[uint32]NATIdentity{103: {V4: "203.0.113.4", V6: "2001:db8::4"}}
				if err := m.SyncNATReverse(tooLarge, nodes); err == nil {
					t.Fatal("oversized projection accepted")
				}
				key, _ := addr128Str("203.0.113.3")
				var owner uint32
				if err := m.objs.NatOf.Lookup(key, &owner); err != nil || owner != 102 {
					t.Fatal("failed preflight mutated network map", owner, err)
				}
				shard := overlayNatShardKey{Ip: key}
				if err := m.objs.NatOwner.Lookup(shard, &owner); err != nil || owner != 0xc0000201 {
					t.Fatal("failed preflight mutated shard map", owner, err)
				}
			})
		}
	})
}
