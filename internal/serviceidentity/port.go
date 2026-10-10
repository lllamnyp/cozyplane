package serviceidentity

import (
	"net"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
)

// A durably reserved VNI is the network generation carried by a Port claim.
func MatchesPortVPC(port *sdnv1alpha1.Port, vpc *sdnv1alpha1.VPC) bool {
	if port == nil || vpc == nil || vpc.UID == "" || !port.DeletionTimestamp.IsZero() || !vpc.DeletionTimestamp.IsZero() || vpc.Status.VNI <= 0 || vpc.Status.VNI >= 1<<22 || port.Spec.VPCRef.Namespace != vpc.Namespace || port.Spec.VPCRef.Name != vpc.Name {
		return false
	}
	ip := net.ParseIP(port.Spec.IP)
	return ip != nil && !ipam.IsReserved(ip) && ip.String() == port.Spec.IP && port.Name == sdn.PortName(vpc.Status.VNI, port.Spec.IP)
}
