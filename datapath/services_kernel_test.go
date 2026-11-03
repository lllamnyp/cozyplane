package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelServiceVIPBudgetAndOwnership(t *testing.T) {
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
	spec.Maps["svc_vips"].Pinning = ebpf.PinNone
	spec.Maps["svc_vips"].MaxEntries = 2
	rows, err := ebpf.NewMap(spec.Maps["svc_vips"])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{SvcVips: rows}}}
	kpr := overlaySvcKey{Net: 0, Port: htons(80)}
	if err := rows.Put(kpr, overlaySvcVal{}); err != nil {
		t.Fatal(err)
	}
	entry := SvcEntry{Net: 100, VIP: net.ParseIP("10.0.0.254"), Proto: 6, Port: 80}
	if err := m.SyncServiceVIPs([]SvcEntry{entry}); err != nil {
		t.Fatal(err)
	}
	ip, _ := addr128(entry.VIP)
	key := overlaySvcKey{Net: 100, Vip: ip, Proto: 6, Port: htons(80)}
	var val overlaySvcVal
	tooMany := []SvcEntry{entry, entry, entry}
	tooMany[1].Port = 81
	tooMany[2].Port = 82
	if err := m.SyncServiceVIPs(tooMany); err == nil {
		t.Fatal("oversized desired map admitted")
	}
	if err := rows.Lookup(key, &val); err != nil {
		t.Fatal("rejected snapshot mutated current entry", err)
	}
	if err := m.SyncServiceVIPs(nil); err != nil {
		t.Fatal(err)
	}
	if err := rows.Lookup(key, &val); !isNotExist(err) {
		t.Fatal("tenant VIP retained after rejected view", err)
	}
	if err := rows.Lookup(kpr, &val); err != nil {
		t.Fatal("KPR entry pruned", err)
	}
	if err := m.SyncServiceVIPs([]SvcEntry{entry}); err != nil {
		t.Fatal("recovery", err)
	}
}
