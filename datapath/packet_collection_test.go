package datapath

import (
	"testing"

	"github.com/cilium/ebpf"
)

// Packet tests use the same entry/continuation chain as Manager.Load, without
// pins or host attachments. Production packet assertions stay unchanged.
func newKernelPacketCollection(t *testing.T, spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	t.Helper()
	original, err := loadOverlay()
	if err != nil {
		return nil, err
	}
	for entry, continuation := range map[string]string{
		"cozyplane_from_pod": "cozyplane_from_pod_continue",
		"cozyplane_to_pod":   "cozyplane_to_pod_continue",
	} {
		if spec.Programs[entry] != nil && spec.Programs[continuation] == nil {
			spec.Programs[continuation] = original.Programs[continuation]
		}
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	for slot, name := range map[uint32]string{
		0: "cozyplane_lb_ingress", 1: "cozyplane_lb_dsr",
		2: "cozyplane_hf_ingress", 3: "cozyplane_hf_egress",
		4: "cozyplane_from_pod_continue", 5: "cozyplane_to_pod_continue",
	} {
		if program := collection.Programs[name]; program != nil {
			if err := collection.Maps["lb_prog"].Put(slot, uint32(program.FD())); err != nil {
				collection.Close()
				return nil, err
			}
		}
	}
	return collection, nil
}
