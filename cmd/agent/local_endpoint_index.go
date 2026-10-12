package main

import (
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"net"
)

type endpointAddress struct {
	net uint32
	ip  string
}
type localEndpointIndex struct {
	ports  map[string][]datapath.LocalPortVeth
	legacy map[endpointAddress][]datapath.LocalPortVeth
}

func indexLocalPortVeths(veths []datapath.LocalPortVeth) localEndpointIndex {
	idx := localEndpointIndex{ports: map[string][]datapath.LocalPortVeth{}, legacy: map[endpointAddress][]datapath.LocalPortVeth{}}
	for _, v := range veths {
		if v.PortUID != "" {
			idx.ports[v.PortUID] = append(idx.ports[v.PortUID], v)
			continue
		}
		for _, ip := range v.IPs {
			key := endpointAddress{net: v.Net, ip: ip.String()}
			idx.legacy[key] = append(idx.legacy[key], v)
		}
	}
	return idx
}

func (idx localEndpointIndex) forPort(port *sdnv1.Port) []datapath.LocalPortVeth {
	vni, ok := vniFromPortName(port.Name)
	if !ok {
		return nil
	}
	known := idx.ports[string(port.UID)]
	legacy := idx.legacy[endpointAddress{net: vni, ip: net.ParseIP(port.Spec.IP).String()}]
	if len(known) == 0 {
		return legacy
	}
	if len(legacy) == 0 {
		return known
	}
	return append(append([]datapath.LocalPortVeth(nil), known...), legacy...)
}
