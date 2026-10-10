package datapath

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Measures the actual kernel/per-CPU collector used by the HTTP metrics path.
func BenchmarkKernelVPCCounterScrape(b *testing.B) {
	b.Run("128_slots", func(b *testing.B) { benchmarkVPCCounterScrape(b, 128) })
	b.Run("4096_slots", func(b *testing.B) { benchmarkVPCCounterScrape(b, 4096) })
}

func benchmarkVPCCounterScrape(b *testing.B, count uint32) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		b.Skip("requires isolated privileged Linux container")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		b.Fatal(err)
	}
	ms := spec.Maps["vpc_counters"].Copy()
	ms.Pinning, ms.MaxEntries = ebpf.PinNone, count
	mp, err := ebpf.NewMap(ms)
	if err != nil {
		b.Fatal(err)
	}
	defer mp.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{VpcCounters: mp}}}
	for net := uint32(1); net <= count; net++ {
		if err := m.EnsureVPCCounter(net); err != nil {
			b.Fatal(err)
		}
		if net%32 == 0 {
			// Fixture setup is outside timing. Let the kernel populate its
			// dynamic per-CPU allocation pool between batches (NO_PREALLOC map).
			time.Sleep(time.Millisecond)
		}
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		counters, err := m.VPCCounters()
		if err != nil || len(counters) != int(count) {
			b.Fatal(len(counters), err)
		}
	}
	b.ReportMetric(float64(ncpu), "possibleCPUs")
}
