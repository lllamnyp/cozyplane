package main

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardHTTPScrapeConfiguredMissingAndUnknownPeers(t *testing.T) {
	now := time.Now()
	live, missing, unknown := wgtypes.Key{1}, wgtypes.Key{2}, wgtypes.Key{3}
	dev := &wgtypes.Device{Peers: []wgtypes.Peer{
		{PublicKey: live, LastHandshakeTime: now.Add(-time.Minute), ReceiveBytes: 101, TransmitBytes: 202},
		{PublicKey: unknown, LastHandshakeTime: now, ReceiveBytes: 999, TransmitBytes: 999},
	}}
	handler := wireGuardMetricsHandler(func() (*wgtypes.Device, error) { return dev, nil }, map[wgtypes.Key]string{live: "connection-a", missing: "connection-b"}, "configured", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(handler)
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(body)))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("invalid scrape: status=%d error=%v", response.StatusCode, err)
	}
	if got := families["cozyplane_vpn_gateway_connections"].GetMetric()[0].GetGauge().GetValue(); got != 2 {
		t.Fatalf("configured peer count=%v", got)
	}
	for name, expected := range map[string][]float64{
		"cozyplane_vpn_connection_rx_bytes_total":                   {101, 0},
		"cozyplane_vpn_connection_tx_bytes_total":                   {202, 0},
		"cozyplane_vpn_connection_up":                               {1, 0},
		"cozyplane_vpn_connection_last_handshake_timestamp_seconds": {float64(now.Add(-time.Minute).Unix()), 0},
	} {
		family := families[name]
		if family == nil || len(family.Metric) != 2 {
			t.Fatalf("%s omitted a configured peer or included an unknown peer", name)
		}
		for i, metric := range family.Metric {
			value := metric.GetGauge().GetValue() + metric.GetCounter().GetValue()
			if value != expected[i] {
				t.Fatalf("%s peer %d=%v want %v", name, i, value, expected[i])
			}
		}
	}
	if families["cozyplane_vpn_connection_rx_packets_total"] != nil {
		t.Fatal("WireGuard invented unavailable packet counters")
	}
	if dir := os.Getenv("VPN_MONITORING_ARTIFACT_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "wireguard-http.prom"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWireGuardHTTPCollectionFailuresAndFutureHandshake(t *testing.T) {
	key := wgtypes.Key{1}
	for _, broken := range []string{"read error", "negative rx", "negative tx", "future handshake"} {
		t.Run(broken, func(t *testing.T) {
			p := wgtypes.Peer{PublicKey: key}
			var readErr error
			switch broken {
			case "read error":
				readErr = errors.New("private diagnostic")
			case "negative rx":
				p.ReceiveBytes = -1
			case "negative tx":
				p.TransmitBytes = -1
			case "future handshake":
				p.LastHandshakeTime = time.Now().Add(time.Hour)
			}
			handler := wireGuardMetricsHandler(func() (*wgtypes.Device, error) { return &wgtypes.Device{Peers: []wgtypes.Peer{p}}, readErr }, map[wgtypes.Key]string{key: "connection-a"}, "", slog.Default())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			if broken != "future handshake" {
				if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private diagnostic") {
					t.Fatal("collection failure hidden or diagnostic leaked", response)
				}
				return
			}
			parser := expfmt.NewTextParser(model.LegacyValidation)
			families, err := parser.TextToMetricFamilies(response.Body)
			if err != nil || families["cozyplane_vpn_connection_up"].Metric[0].Gauge.GetValue() != 0 || families["cozyplane_vpn_connection_last_handshake_timestamp_seconds"].Metric[0].Gauge.GetValue() != 0 {
				t.Fatal("future handshake reported healthy", err)
			}
		})
	}
}
