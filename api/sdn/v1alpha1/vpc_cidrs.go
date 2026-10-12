package v1alpha1

import (
	"fmt"
	"net"
)

// MaxVPCCIDRs matches the entire networks map ceiling. It bounds raw input,
// including duplicates, and does not reserve capacity for a VPC.
const MaxVPCCIDRs = 1024

const MaxVPCCIDRBytes = 64

func ValidateVPCCIDRs(cidrs []string) error {
	if len(cidrs) > MaxVPCCIDRs {
		return fmt.Errorf("VPC exceeds %d input CIDRs", MaxVPCCIDRs)
	}
	for i, cidr := range cidrs {
		if len(cidr) > MaxVPCCIDRBytes {
			return fmt.Errorf("VPC CIDR at index %d exceeds %d bytes", i, MaxVPCCIDRBytes)
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("VPC CIDR at index %d is not a valid IP CIDR", i)
		}
	}
	return nil
}
