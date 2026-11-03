package main

import (
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/strongswan/govici/vici"
)

type httpMetricStream struct{ event *vici.Message }

func (*httpMetricStream) Close() error { return nil }
func (s *httpMetricStream) CallStreaming(context.Context, string, string, *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(yield func(*vici.Message, error) bool) { yield(s.event, nil) }
}

func TestIPsecHTTPScrapeAndKernelTelemetryFailure(t *testing.T) {
	for _, kernelError := range []bool{false, true} {
		t.Run(map[bool]string{false: "kernel available", true: "kernel unavailable"}[kernelError], func(t *testing.T) {
			collector := &ipsecCollector{slot: make(chan struct{}, 1), open: func(context.Context) (ipsecStream, error) {
				return &httpMetricStream{event: ipsecSAEvent(t, "connection-a", "INSTALLED", 101, 202, 3, 4, 900)}, nil
			}}
			handler := ipsecMetricsHandler(collector, []peer{{Name: "connection-a"}, {Name: "connection-b"}}, slog.Default(), "configured", func() (map[string]uint64, error) {
				if kernelError {
					return nil, errors.New("private diagnostic")
				}
				return map[string]uint64{"XfrmInStateSeqError": 37, "XfrmInError": 0}, nil
			})
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
				t.Fatalf("invalid scrape: %d %v", response.StatusCode, err)
			}
			for name, expected := range map[string][]float64{
				"cozyplane_vpn_connection_rx_bytes_total": {101, 0}, "cozyplane_vpn_connection_tx_bytes_total": {202, 0},
				"cozyplane_vpn_connection_rx_packets_total": {3, 0}, "cozyplane_vpn_connection_tx_packets_total": {4, 0}, "cozyplane_vpn_connection_up": {1, 0},
			} {
				family := families[name]
				if family == nil || len(family.Metric) != 2 {
					t.Fatalf("%s missing configured peer", name)
				}
				for i, metric := range family.Metric {
					if metric.GetCounter().GetValue()+metric.GetGauge().GetValue() != expected[i] {
						t.Fatalf("%s incorrect value", name)
					}
				}
			}
			if families["cozyplane_vpn_gateway_connections"].Metric[0].Gauge.GetValue() != 2 {
				t.Fatal("configured count missing")
			}
			if kernelError {
				if families["cozyplane_vpn_ipsec_xfrm_collection_success"].Metric[0].Gauge.GetValue() != 0 || families["cozyplane_vpn_ipsec_xfrm_errors_total"] != nil || strings.Contains(string(body), "private diagnostic") {
					t.Fatal("kernel telemetry failure hidden or diagnostic leaked")
				}
			} else {
				if families["cozyplane_vpn_ipsec_xfrm_collection_success"].Metric[0].Gauge.GetValue() != 1 || len(families["cozyplane_vpn_ipsec_xfrm_errors_total"].Metric) != 2 {
					t.Fatal("kernel counters missing")
				}
				if dir := os.Getenv("VPN_MONITORING_ARTIFACT_DIR"); dir != "" {
					if err := os.WriteFile(filepath.Join(dir, "ipsec-http.prom"), body, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestIPsecHTTPScrapeFailsWhenVICIUnavailable(t *testing.T) {
	collector := &ipsecCollector{slot: make(chan struct{}, 1), open: func(context.Context) (ipsecStream, error) { return nil, errors.New("private diagnostic") }}
	handler := ipsecMetricsHandler(collector, nil, slog.Default(), "", func() (map[string]uint64, error) { t.Fatal("kernel reader invoked after failed VICI"); return nil, nil })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private diagnostic") {
		t.Fatal("failed VICI collection published stale/zero metrics or leaked diagnostics")
	}
}

func TestXfrmErrorParsingIsBoundedAndStrict(t *testing.T) {
	for _, bad := range []string{"", "XfrmInStateSeqError -1\n", "XfrmInStateSeqError 1\nXfrmInStateSeqError 2\n", "XfrmInStateSeqError 18446744073709551616\n", "XfrmInStateSeqError 1\n" + strings.Repeat("FutureCounter 0\n", 2000)} {
		if _, err := parseXfrmErrors(strings.NewReader(bad)); err == nil {
			t.Fatal("invalid statistics accepted")
		}
	}
	counters, err := parseXfrmErrors(strings.NewReader("XfrmInStateSeqError 37\nXfrmInError 0\nFutureCounter 1\n"))
	if err != nil || len(counters) != 2 || counters["XfrmInStateSeqError"] != 37 {
		t.Fatal("valid counters rejected or unknown labels admitted", counters, err)
	}
}

func TestNamespaceKernelXfrmStatistics(t *testing.T) {
	if _, err := os.Stat("/proc/self/net/xfrm_stat"); err != nil {
		t.Skip("kernel does not expose namespace-local XFRM statistics")
	}
	counters, err := readXfrmErrors()
	if err != nil {
		t.Fatal(err)
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	body := formatXfrmErrors(counters, nil)
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil || len(families["cozyplane_vpn_ipsec_xfrm_errors_total"].Metric) != len(counters) {
		t.Fatal("actual namespace statistics did not reach exposition", err)
	}
	if dir := os.Getenv("VPN_MONITORING_ARTIFACT_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "xfrm-kernel.prom"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
