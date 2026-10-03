package vpc

import (
	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func validateBoundary(v *sdn.VPC) field.ErrorList {
	b := v.Spec.Boundary
	if b == nil {
		return nil
	}
	p := field.NewPath("spec", "boundary")
	var errs field.ErrorList
	if b.Revision < 1 {
		errs = append(errs, field.Invalid(p.Child("revision"), b.Revision, "must be positive"))
	}
	if len(b.Peers) > 256 {
		errs = append(errs, field.TooMany(p.Child("peers"), len(b.Peers), 256))
	}
	entries := 0
	for i, r := range b.Peers {
		q := p.Child("peers").Index(i)
		if r.PeerRef.Name == "" || r.PeerRef.Namespace == "" || (r.PeerRef.Name == v.Name && r.PeerRef.Namespace == v.Namespace) {
			errs = append(errs, field.Invalid(q.Child("peerRef"), r.PeerRef, "must identify another VPC"))
		}
		if r.Direction != "ingress" && r.Direction != "egress" {
			errs = append(errs, field.NotSupported(q.Child("direction"), r.Direction, []string{"ingress", "egress"}))
		}
		switch r.Protocol {
		case "TCP", "UDP":
			if len(r.Ports) < 1 || len(r.Ports) > 32 || r.ICMPType != nil || r.ICMPCode != nil {
				errs = append(errs, field.Invalid(q, r, "TCP/UDP requires 1..32 ports and no ICMP fields"))
			}
			seen := map[int32]bool{}
			for j, n := range r.Ports {
				if n < 1 || n > 65535 || seen[n] {
					errs = append(errs, field.Invalid(q.Child("ports").Index(j), n, "must be a distinct port in 1..65535"))
				}
				seen[n] = true
			}
			entries += len(r.Ports)
		case "ICMP":
			if len(r.Ports) != 0 || r.ICMPType == nil || r.ICMPCode == nil || *r.ICMPType < 0 || *r.ICMPType > 255 || *r.ICMPCode < 0 || *r.ICMPCode > 255 {
				errs = append(errs, field.Invalid(q, r, "ICMP requires type/code in 0..255 and no ports"))
			}
			entries += 2
		default:
			errs = append(errs, field.NotSupported(q.Child("protocol"), r.Protocol, []string{"TCP", "UDP", "ICMP"}))
		}
	}
	if entries > 4096 {
		errs = append(errs, field.TooMany(p.Child("peers"), entries, 4096))
	}
	return errs
}
