package vpngateway

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateVPNGatewayAddressPools(t *testing.T) {
	tests := []struct {
		name    string
		gateway *sdn.VPNGateway
		wantErr bool
	}{
		{
			name: "valid roadwarrior pool",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				IPsec: &sdn.VPNGatewayIPsec{
					CredentialSecretRef: "gateway-ike-tls",
					AddressPools:        []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24", DNS: []string{"10.0.0.53"}}},
				},
			}},
		},
		{
			name: "overlapping pools",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				IPsec: &sdn.VPNGatewayIPsec{
					CredentialSecretRef: "gateway-ike-tls",
					AddressPools: []sdn.VPNIPsecAddressPool{
						{Name: "clients-a", CIDR: "10.250.0.0/24"},
						{Name: "clients-b", CIDR: "10.250.0.128/25"},
					},
				},
			}},
			wantErr: true,
		},
		{
			name: "pool requires TLS credential",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				IPsec:  &sdn.VPNGatewayIPsec{AddressPools: []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24"}}},
			}},
			wantErr: true,
		},
		{
			name: "valid active active",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"}, WireGuard: &sdn.VPNGatewayWireGuard{},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{
					LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"}, BFD: true,
				}},
				ExternalAddress: sdn.VPNExternalAddress{AddressClaimNames: []string{"endpoint-a", "endpoint-b"}},
			}},
		},
		{
			name: "active active needs two distinct claims",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"}, WireGuard: &sdn.VPNGatewayWireGuard{},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{
					LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"},
				}},
				ExternalAddress: sdn.VPNExternalAddress{AddressClaimNames: []string{"endpoint-a"}},
			}},
			wantErr: true,
		},
		{
			name: "valid live migration",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"}, IPsec: &sdn.VPNGatewayIPsec{},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeLiveMigration, VirtualMachine: &sdn.VPNGatewayVirtualMachine{
					Image: "registry.invalid/vpn-appliance:test", StateClaimName: "vpn-state",
				}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(validateVPNGateway(tt.gateway)) > 0; got != tt.wantErr {
				t.Fatalf("errors = %v, wantErr %v", validateVPNGateway(tt.gateway), tt.wantErr)
			}
		})
	}
}

func TestValidateVPNGatewayAdditionalVPCRefs(t *testing.T) {
	tests := []struct {
		name    string
		gateway *sdn.VPNGateway
		wantErr bool
	}{
		{
			name: "valid additional VPCs",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef:            sdn.LocalVPCRef{Name: "vpc"},
				WireGuard:         &sdn.VPNGatewayWireGuard{},
				AdditionalVPCRefs: []sdn.LocalVPCRef{{Name: "vpc-b"}, {Name: "vpc-c"}},
			}},
		},
		{
			name: "duplicate additional VPC name",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef:            sdn.LocalVPCRef{Name: "vpc"},
				WireGuard:         &sdn.VPNGatewayWireGuard{},
				AdditionalVPCRefs: []sdn.LocalVPCRef{{Name: "vpc-b"}, {Name: "vpc-b"}},
			}},
			wantErr: true,
		},
		{
			name: "additional VPC equal to vpcRef",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef:            sdn.LocalVPCRef{Name: "vpc"},
				WireGuard:         &sdn.VPNGatewayWireGuard{},
				AdditionalVPCRefs: []sdn.LocalVPCRef{{Name: "vpc"}},
			}},
			wantErr: true,
		},
		{
			name: "too many additional VPCs",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef:    sdn.LocalVPCRef{Name: "vpc"},
				WireGuard: &sdn.VPNGatewayWireGuard{},
				AdditionalVPCRefs: []sdn.LocalVPCRef{
					{Name: "vpc-1"}, {Name: "vpc-2"}, {Name: "vpc-3"}, {Name: "vpc-4"}, {Name: "vpc-5"},
					{Name: "vpc-6"}, {Name: "vpc-7"}, {Name: "vpc-8"}, {Name: "vpc-9"}, {Name: "vpc-10"},
				},
			}},
			wantErr: true,
		},
		{
			name: "empty additional VPC name",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef:            sdn.LocalVPCRef{Name: "vpc"},
				WireGuard:         &sdn.VPNGatewayWireGuard{},
				AdditionalVPCRefs: []sdn.LocalVPCRef{{Name: ""}},
			}},
			wantErr: true,
		},
		{
			name: "live migration forbids additional VPCs",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeLiveMigration, VirtualMachine: &sdn.VPNGatewayVirtualMachine{
					Image: "example.invalid/appliance:test", StateClaimName: "state",
				}},
				AdditionalVPCRefs: []sdn.LocalVPCRef{{Name: "vpc-b"}},
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateVPNGateway(tt.gateway)
			if got := len(errs) > 0; got != tt.wantErr {
				t.Fatalf("errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if tt.name == "live migration forbids additional VPCs" {
				found := false
				for _, e := range errs {
					if e.Type == field.ErrorTypeForbidden && e.Field == "spec.additionalVPCRefs" {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected a Forbidden error on spec.additionalVPCRefs, got %v", errs)
				}
			}
		})
	}
}
