package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/lllamnyp/cozyplane/internal/vpnmetrics"
	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func wireGuardMetricsSnapshot(dev *wgtypes.Device, names map[wgtypes.Key]string, now time.Time) (vpnstatus.Snapshot, error) {
	for _, p := range dev.Peers {
		if _, configured := names[p.PublicKey]; configured && (p.ReceiveBytes < 0 || p.TransmitBytes < 0) {
			return vpnstatus.Snapshot{}, fmt.Errorf("invalid WireGuard counters")
		}
	}
	live := wireGuardSnapshot(dev, names, now)
	configured := make(map[string]vpnstatus.Connection, len(names))
	for key := range names {
		name := connLabel(names, key)
		c := live.Connections[name]
		if c.LastHandshakeUnix > now.Unix() {
			c.LastHandshakeUnix = 0
		}
		configured[name] = c
	}
	live.Connections = configured
	return live, nil
}

func wireGuardMetricsHandler(readDevice func() (*wgtypes.Device, error), names map[wgtypes.Key]string, checksum string, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		dev, err := readDevice()
		if err != nil {
			http.Error(w, "WireGuard status unavailable", http.StatusServiceUnavailable)
			return
		}
		snapshot, err := wireGuardMetricsSnapshot(dev, names, time.Now())
		if err != nil {
			http.Error(w, "WireGuard counters unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(vpnmetrics.Format("wireguard", snapshot.Connections, false)))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		dev, err := readDevice()
		if err != nil {
			http.Error(w, "WireGuard status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		snapshot := wireGuardSnapshot(dev, names, time.Now())
		snapshot.ConfigChecksum = checksum
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			log.Warn("encode status", "err", err)
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := readDevice(); err != nil {
			http.Error(w, "WireGuard device unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
