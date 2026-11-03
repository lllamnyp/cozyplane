package main

import (
	"net"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnlisters "github.com/lllamnyp/cozyplane/pkg/generated/sdn/listers/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func guestPortCandidates(ports sdnlisters.PortLister, inventory []datapath.LocalPortVeth) ([]*sdnv1.Port, error) {
	seen := map[string]bool{}
	var candidates []*sdnv1.Port
	for _, v := range inventory {
		if v.Net == 0 || v.RawNet == datapath.QuarantineNet || v.RawNet&datapath.PortGatewayFlag != 0 {
			continue
		}
		for _, ip := range v.IPs {
			if ip == nil {
				continue
			}
			name := sdn.PortName(int32(v.Net), ip.String())
			if seen[name] {
				continue
			}
			port, err := ports.Get(name)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if port == nil || (v.PortUID != "" && string(port.UID) != v.PortUID) {
				continue
			}
			vni, ok := vniFromPortName(port.Name)
			if !ok || vni != v.Net || !ip.Equal(net.ParseIP(port.Spec.IP)) {
				continue
			}
			// A stale UID must not hide a matching replacement later in inventory.
			seen[name] = true
			candidates = append(candidates, port)
		}
	}
	return candidates, nil
}
