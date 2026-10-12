package datapath

import (
	"net"
	"testing"
)

func TestBoundaryRejectsMalformedMaskBeforeTouchingMaps(t *testing.T) {
	policy := Boundary{Net: 1, Revision: 1, Identity: 1, CIDRs: []*net.IPNet{{
		IP: net.ParseIP("10.1.0.0"), Mask: net.IPMask{255, 0, 255, 0},
	}}}
	if err := New().SyncBoundaries([]Boundary{policy}, []uint32{1}, nil); err == nil {
		t.Fatal("non-contiguous mask accepted")
	}
}
