package main

import (
	"context"
	"fmt"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
)

const maxOwnNetworkInputs = 65536

func compileOwnNetworks(ctx context.Context, vpcs []*sdn.VPC) ([]datapath.PeerNet, error) {
	if len(vpcs) > maxOwnNetworkInputs {
		return nil, fmt.Errorf("own network snapshot exceeds object budget")
	}
	var desired []datapath.PeerNet
	work := len(vpcs)
	for _, vpc := range vpcs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if vpc == nil || !vpc.DeletionTimestamp.IsZero() || vpc.Status.VNI <= 0 || vpc.Status.VNI >= 1<<22 {
			continue
		}
		if len(vpc.Spec.CIDRs) > sdn.MaxVPCCIDRs {
			continue // oversized legacy data cannot poison healthy VPC replay
		}
		if len(vpc.Spec.CIDRs) > maxOwnNetworkInputs-work {
			return nil, fmt.Errorf("own network snapshot exceeds input work budget")
		}
		work += len(vpc.Spec.CIDRs)
		if err := sdn.ValidateVPCCIDRs(vpc.Spec.CIDRs); err != nil {
			continue // charge bounded malformed input too, before parsing its CIDRs
		}
		for _, cidr := range vpc.Spec.CIDRs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			net := uint32(vpc.Status.VNI)
			desired = append(desired, datapath.PeerNet{Scope: net, Net: net, CIDR: cidr})
		}
	}
	return desired, nil
}
