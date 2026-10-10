package vpngateway

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestIPsecClientPoolsRejectIndependentActiveActiveLeaseAllocators(t *testing.T) {
	for _, mode := range []sdn.VPNGatewayHAMode{"", sdn.VPNGatewayHAModeWarmStandby, sdn.VPNGatewayHAModeLiveMigration, sdn.VPNGatewayHAModeActiveActive} {
		for _, pooled := range []bool{false, true} {
			gw := ipsecGenerationGateway()
			if pooled {
				gw.Spec.IPsec.CredentialSecretRef = "tls"
				gw.Spec.IPsec.AddressPools = []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "198.18.0.0/24"}}
			}
			if mode != "" {
				gw.Spec.HA = &sdn.VPNGatewayHA{Mode: mode}
			}
			switch mode {
			case sdn.VPNGatewayHAModeActiveActive:
				gw.Spec.HA.ActiveActive = &sdn.VPNGatewayActiveActive{LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"192.0.2.1"}}
			case sdn.VPNGatewayHAModeLiveMigration:
				gw.Spec.HA.VirtualMachine = &sdn.VPNGatewayVirtualMachine{Image: "example.invalid/appliance:test", StateClaimName: "state"}
			}
			errs := NewStrategy(nil).Validate(t.Context(), gw)
			wantRejected := pooled && mode == sdn.VPNGatewayHAModeActiveActive
			if (len(errs) != 0) != wantRejected {
				t.Fatalf("mode=%q pooled=%v admission errors=%v", mode, pooled, errs)
			}
			if wantRejected && (len(errs) != 1 || errs[0].Field != "spec.ipsec.addressPools") {
				t.Fatalf("unsafe pool mode has no precise admission error: %v", errs)
			}
		}
	}
}
