package vpnconnection

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestValidateVPNConnection(t *testing.T) {
	tests := []struct {
		name    string
		conn    *sdn.VPNConnection
		wantErr bool
	}{
		{
			name: "wireguard",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef:  sdn.LocalVPNGatewayRef{Name: "gateway"},
				RemoteCIDRs: []string{"10.20.0.0/16"},
				WireGuard:   &sdn.VPNConnectionWireGuard{PeerPublicKey: "public-key"},
			}},
		},
		{
			name: "wireguard active-active pair",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				WireGuard: &sdn.VPNConnectionWireGuard{
					PeerPublicKeys: []string{"key-0", "key-1"},
					PeerEndpoints:  []string{"192.0.2.10:51820", "192.0.2.11:51820"},
				},
			}},
		},
		{
			name: "wireguard active-active mismatched endpoints",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				WireGuard: &sdn.VPNConnectionWireGuard{
					PeerPublicKeys: []string{"key-0", "key-1"},
					PeerEndpoints:  []string{"192.0.2.10:51820"},
				},
			}},
			wantErr: true,
		},
		{
			name: "responder with known address",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef:  sdn.LocalVPNGatewayRef{Name: "gateway"},
				RemoteCIDRs: []string{"10.30.0.0/16"},
				IPsec: &sdn.VPNConnectionIPsec{
					PeerAddress: "192.0.2.10",
					StartAction: sdn.VPNIPsecStartActionNone,
				},
			}},
		},
		{
			name: "start requires address",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				IPsec:      &sdn.VPNConnectionIPsec{StartAction: sdn.VPNIPsecStartActionStart},
			}},
			wantErr: true,
		},
		{
			name: "backends are mutually exclusive",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				WireGuard:  &sdn.VPNConnectionWireGuard{},
				IPsec:      &sdn.VPNConnectionIPsec{},
			}},
			wantErr: true,
		},
		{
			name: "invalid CIDR",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef:  sdn.LocalVPNGatewayRef{Name: "gateway"},
				RemoteCIDRs: []string{"not-a-cidr"},
				WireGuard:   &sdn.VPNConnectionWireGuard{},
			}},
			wantErr: true,
		},
		{
			name: "EAP roadwarrior",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				IPsec: &sdn.VPNConnectionIPsec{
					AddressPool: "clients",
					Auth: sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{
						Identity: "device-001", SecretRef: "device-001-eap",
					}},
				},
			}},
		},
		{
			name: "EAP requires pool",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				IPsec: &sdn.VPNConnectionIPsec{Auth: sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{
					Identity: "device-001", SecretRef: "device-001-eap",
				}}},
			}},
			wantErr: true,
		},
		{
			name: "authentication methods are exclusive",
			conn: &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
				GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"},
				IPsec: &sdn.VPNConnectionIPsec{Auth: sdn.VPNConnectionIPsecAuth{
					PSKSecretRef: "psk",
					Certificate:  &sdn.VPNIPsecCertificateAuth{RemoteIdentity: "device-001"},
				}},
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errList := validateVPNConnection(tt.conn)
			if gotErr := len(errList) > 0; gotErr != tt.wantErr {
				t.Fatalf("errors = %v, wantErr %v", errList, tt.wantErr)
			}
		})
	}
}
