package main

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSelectPrivateKey(t *testing.T) {
	tests := []struct {
		name, podName string
		cfg           config
		want          string
		wantErr       bool
	}{
		{name: "legacy", cfg: config{PrivateKey: "legacy"}, want: "legacy"},
		{name: "first ordinal", podName: "gateway-vpn-0", cfg: config{PrivateKeys: []string{"first", "second"}}, want: "first"},
		{name: "second ordinal", podName: "gateway-vpn-1", cfg: config{PrivateKeys: []string{"first", "second"}}, want: "second"},
		{name: "missing pod name", cfg: config{PrivateKeys: []string{"first", "second"}}, wantErr: true},
		{name: "out of range", podName: "gateway-vpn-2", cfg: config{PrivateKeys: []string{"first", "second"}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectPrivateKey(tt.cfg, tt.podName)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("selectPrivateKey() = %q, %v; want %q, error=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestSelectInstancePeers(t *testing.T) {
	sets := [][]peer{{{Name: "first"}}, {{Name: "second"}}}
	got, err := selectInstancePeers(config{PeerInstances: sets}, "gateway-vpn-1")
	if err != nil || len(got) != 1 || got[0].Name != "second" {
		t.Fatalf("selectInstancePeers() = %+v, %v", got, err)
	}
}

func TestWireGuardSnapshotUsesFreshHandshake(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := wgtypes.Key{1}
	device := &wgtypes.Device{Peers: []wgtypes.Peer{{
		PublicKey:         key,
		LastHandshakeTime: now.Add(-time.Minute),
		ReceiveBytes:      10,
		TransmitBytes:     20,
	}}}
	snapshot := wireGuardSnapshot(device, map[wgtypes.Key]string{key: "connection"}, now)
	connection := snapshot.Connections["connection"]
	if !connection.Up || connection.LastHandshakeUnix != now.Add(-time.Minute).Unix() {
		t.Fatalf("unexpected live connection snapshot: %+v", connection)
	}
	if connection.RXBytes != 10 || connection.TXBytes != 20 {
		t.Fatalf("unexpected counters: %+v", connection)
	}

	device.Peers[0].LastHandshakeTime = now.Add(-wireGuardHandshakeTimeout - time.Second)
	if stale := wireGuardSnapshot(device, nil, now).Connections[key.String()]; stale.Up {
		t.Fatalf("stale handshake reported up: %+v", stale)
	}
}
