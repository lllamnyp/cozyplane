package main

import (
	"net"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/sgidentity"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
)

func securityGroupPeerReference(peer sdn.SecurityGroupPeer) bool {
	if peer.VPC == nil {
		return vpnlimits.GroupReference(peer.Group, "", "")
	}
	return vpnlimits.NamespaceName(peer.VPC.Namespace) && vpnlimits.GroupReference(peer.Group, peer.VPC.Namespace, peer.VPC.Name)
}

func securityGroupMembers(ports []*sdn.Port, groups []*sdn.SecurityGroup) []datapath.SGMember {
	index := sgidentity.NewIndex(groups)
	var members []datapath.SGMember
	for _, p := range ports {
		if p.Spec.IP == "" {
			continue
		}
		net_, ok := vniFromPortName(p.Name)
		if !ok {
			continue
		}
		bitmap := index.Bitmap(p)
		members = append(members, datapath.SGMember{Net: net_, IP: net.ParseIP(p.Spec.IP), Groups: bitmap,
			Owner: datapath.SGEndpointOwner(string(p.UID), p.Annotations[sdn.AnnotationContainerID], p.Annotations[sdn.AnnotationCNIIfName])})
	}
	return members
}
