package main

import (
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
)

// Call only after the complete Port cache has synchronized. UID, not address,
// prevents a replacement Port from keeping the predecessor's veth alive.
func orphanPortVeths(ports []*sdnv1.Port, veths []datapath.LocalPortVeth) []datapath.LocalPortVeth {
	active := map[string]bool{}
	for _, port := range ports {
		if port.UID != "" {
			active[string(port.UID)] = true
		}
	}
	var orphans []datapath.LocalPortVeth
	for _, v := range veths {
		if v.PortUID != "" && !active[v.PortUID] && v.Net != 0 && v.RawNet != datapath.QuarantineNet && len(v.IPs) > 0 {
			orphans = append(orphans, v)
		}
	}
	return orphans
}
