package main

import (
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/sdnref"
)

func validGroupPeerReference(peer sdn.SecurityGroupPeer) bool {
	if peer.CIDR != "" {
		return false
	}
	if peer.VPC == nil {
		return sdnref.ObjectName(peer.Group)
	}
	return sdnref.NamespaceName(peer.VPC.Namespace) && sdnref.ObjectName(peer.VPC.Name) && sdnref.ObjectName(peer.Group)
}
