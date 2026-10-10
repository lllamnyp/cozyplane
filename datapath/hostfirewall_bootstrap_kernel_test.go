package datapath

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelHostFirewallModeSeeding(t *testing.T) {
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
	for _, ms := range spec.Maps {
		ms.Pinning = ebpf.PinNone
	}
	params, err := ebpf.NewMap(spec.Maps["params"])
	if err != nil {
		t.Fatal(err)
	}
	defer params.Close()
	for _, test := range []struct {
		name              string
		legacy, ambiguous bool
		mode, want        uint32
		reject            bool
	}{
		{"legacy active", true, false, 1, 1, false}, {"legacy transition", true, false, 2, 2, false}, {"fresh node", false, false, 0, 0, false}, {"lost legacy params", false, true, 0, 2, false}, {"invalid mode", true, false, 99, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			modes, err := ebpf.NewMap(spec.Maps["hf_modes"])
			if err != nil {
				t.Fatal(err)
			}
			defer modes.Close()
			var legacy *ebpf.Map
			if test.legacy {
				legacy = params
				if err := params.Put(cfgHFEnabled, test.mode); err != nil {
					t.Fatal(err)
				}
			}
			err = seedHFModeMap(modes, legacy, test.ambiguous)
			if test.reject {
				if err == nil {
					t.Fatal("invalid witness accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var mode uint32
			if err := modes.Lookup(uint32(0), &mode); err != nil || mode != test.want {
				t.Fatal(mode, err)
			}
			if err := params.Put(cfgHFEnabled, uint32(0)); err != nil {
				t.Fatal(err)
			}
			if err := seedHFModeMap(modes, params, false); err != nil {
				t.Fatal(err)
			}
			if err := modes.Lookup(uint32(0), &mode); err != nil || mode != test.want {
				t.Fatal("initialized state overwritten by reset params", mode, err)
			}
		})
	}
}
