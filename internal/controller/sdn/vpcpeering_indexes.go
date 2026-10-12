package sdn

import (
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	peeringPairIndex = "cozyplane.peering-pair"
	peeringVPCIndex  = "cozyplane.peering-vpc"
)

func peeringRefKey(ref sdn.VPCRef) string {
	return ref.Namespace + "/" + ref.Name
}

func peeringPairKey(local, remote sdn.VPCRef) string {
	return peeringRefKey(local) + "/" + peeringRefKey(remote)
}

func peeringPairKeys(obj client.Object) []string {
	p := obj.(*sdn.VPCPeering)
	if !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
		return nil
	}
	return []string{peeringPairKey(p.LocalRef(), p.Spec.PeerRef)}
}

func peeringVPCKeys(obj client.Object) []string {
	p := obj.(*sdn.VPCPeering)
	if !vpnlimits.PeeringReferences(p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerRef.Namespace, p.Spec.PeerRef.Name) {
		return nil
	}
	local, remote := peeringRefKey(p.LocalRef()), peeringRefKey(p.Spec.PeerRef)
	if local == remote {
		return []string{local}
	}
	return []string{local, remote}
}
