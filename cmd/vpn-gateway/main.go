/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// cozyplane-vpn-gateway terminates a WireGuard site-to-site tunnel inside a
// managed appliance pod's own netns (issue #6, docs/vpn.md §3.2). It creates a
// kernel WireGuard device, configures it from a mounted config (the gateway's
// private key + the peers a VPNGateway's VPNConnections describe), routes each
// peer's remote CIDRs into the tunnel, and enables forwarding — so a VPC pod's
// traffic (steered here by the per-VPC route table) crosses encrypted, and
// decrypted return traffic leaves on the VPC leg with the remote source (which
// the appliance's scoped forwarding grant admits). cozyplane adds no crypto to
// its datapath; the kernel does it here, in this netns only.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/lllamnyp/cozyplane/internal/vpnnet"
	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
)

const wgDev = "wg0"

// config is the mounted tunnel description. It carries the private key and PSKs,
// so it is delivered as a Secret, never a ConfigMap.
type config struct {
	PrivateKey    string   `json:"privateKey"`
	PrivateKeys   []string `json:"privateKeys,omitempty"`
	ListenPort    int      `json:"listenPort,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	Peers         []peer   `json:"peers"`
	PeerInstances [][]peer `json:"peerInstances,omitempty"`
}

type peer struct {
	Name         string   `json:"name,omitempty"` // the VPNConnection name, for metric labels
	PublicKey    string   `json:"publicKey"`
	Endpoint     string   `json:"endpoint,omitempty"` // host:port; empty for a responder-only peer
	AllowedIPs   []string `json:"allowedIPs"`         // the remote CIDRs
	PresharedKey string   `json:"presharedKey,omitempty"`
	Keepalive    int      `json:"keepalive,omitempty"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	path := os.Getenv("VPN_CONFIG")
	if path == "" {
		path = "/etc/cozyplane-vpn/config.json"
	}
	if err := run(path, log); err != nil {
		log.Error("vpn-gateway failed", "err", err)
		os.Exit(1)
	}
}

func run(path string, log *slog.Logger) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	privateKey, err := selectPrivateKey(cfg, os.Getenv("POD_NAME"))
	if err != nil {
		return err
	}
	priv, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	instancePeers, err := selectInstancePeers(cfg, os.Getenv("POD_NAME"))
	if err != nil {
		return err
	}
	cfg.Peers = instancePeers

	// The appliance forwards between its WireGuard leg and its VPC leg.
	if err := vpnnet.EnsureForwarding(); err != nil {
		return err
	}

	// Create the kernel WireGuard device (idempotent — a restart re-adopts it).
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: wgDev}}
	if err := netlink.LinkAdd(link); err != nil && !os.IsExist(err) {
		if _, e := netlink.LinkByName(wgDev); e != nil {
			return fmt.Errorf("create %s: %w", wgDev, err)
		}
	}
	dev, err := netlink.LinkByName(wgDev)
	if err != nil {
		return fmt.Errorf("find %s: %w", wgDev, err)
	}
	if cfg.MTU > 0 {
		if err := netlink.LinkSetMTU(dev, cfg.MTU); err != nil {
			return fmt.Errorf("set %s MTU to %d: %w", wgDev, cfg.MTU, err)
		}
	}

	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer wg.Close()

	peers, routes, err := buildPeers(cfg.Peers)
	if err != nil {
		return err
	}
	wgCfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        peers,
	}
	if cfg.ListenPort > 0 {
		wgCfg.ListenPort = &cfg.ListenPort
	}
	if err := wg.ConfigureDevice(wgDev, wgCfg); err != nil {
		return fmt.Errorf("configure %s: %w", wgDev, err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		return fmt.Errorf("set %s up: %w", wgDev, err)
	}
	// Route each remote CIDR into the tunnel; the VPC CIDR stays on the VPC leg
	// (the CNI's on-link route), so decrypted return traffic leaves there.
	for _, r := range routes {
		route := &netlink.Route{LinkIndex: dev.Attrs().Index, Dst: r}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("route %s dev %s: %w", r, wgDev, err)
		}
	}
	log.Info("wireguard tunnel up", "device", wgDev, "peers", len(peers), "routes", len(routes),
		"listenPort", cfg.ListenPort)

	// Per-connection metrics, read from kernel WireGuard state and served for
	// Prometheus/VictoriaMetrics to scrape (docs/vpn.md §6). The datapath never
	// learns what a "connection" is; this shim does, from the config it mounted.
	names := map[wgtypes.Key]string{}
	for _, p := range cfg.Peers {
		if k, err := wgtypes.ParseKey(p.PublicKey); err == nil {
			names[k] = p.Name
		}
	}
	go serveMetrics(wg, names, log)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	return nil
}

func selectPrivateKey(cfg config, podName string) (string, error) {
	if len(cfg.PrivateKeys) == 0 {
		if cfg.PrivateKey == "" {
			return "", fmt.Errorf("wireguard private key is empty")
		}
		return cfg.PrivateKey, nil
	}
	if len(cfg.PrivateKeys) == 1 {
		return cfg.PrivateKeys[0], nil
	}
	ordinal, err := podOrdinal(podName)
	if err != nil {
		return "", err
	}
	if ordinal >= len(cfg.PrivateKeys) {
		return "", fmt.Errorf("POD_NAME ordinal %d has no configured WireGuard identity", ordinal)
	}
	return cfg.PrivateKeys[ordinal], nil
}

func selectInstancePeers(cfg config, podName string) ([]peer, error) {
	if len(cfg.PeerInstances) == 0 {
		return cfg.Peers, nil
	}
	if len(cfg.PeerInstances) == 1 {
		return cfg.PeerInstances[0], nil
	}
	ordinal, err := podOrdinal(podName)
	if err != nil {
		return nil, err
	}
	if ordinal >= len(cfg.PeerInstances) {
		return nil, fmt.Errorf("POD_NAME ordinal %d has no configured WireGuard peer set", ordinal)
	}
	return cfg.PeerInstances[ordinal], nil
}

func podOrdinal(podName string) (int, error) {
	separator := strings.LastIndexByte(podName, '-')
	if separator < 0 || separator == len(podName)-1 {
		return 0, fmt.Errorf("POD_NAME %q has no StatefulSet ordinal", podName)
	}
	ordinal := 0
	for _, digit := range podName[separator+1:] {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("POD_NAME %q has an invalid StatefulSet ordinal", podName)
		}
		ordinal = ordinal*10 + int(digit-'0')
	}
	return ordinal, nil
}

const metricsAddr = ":9410"

const wireGuardHandshakeTimeout = 180 * time.Second

// serveMetrics exposes per-connection WireGuard counters in Prometheus text
// format on metricsAddr. Each scrape reads live kernel state via wgctrl.
func serveMetrics(wg *wgctrl.Client, names map[wgtypes.Key]string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		dev, err := wg.Device(wgDev)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var b strings.Builder
		b.WriteString("# HELP cozyplane_vpn_connection_rx_bytes_total Bytes received from the peer over the tunnel.\n")
		b.WriteString("# TYPE cozyplane_vpn_connection_rx_bytes_total counter\n")
		for i := range dev.Peers {
			b.WriteString(fmt.Sprintf("cozyplane_vpn_connection_rx_bytes_total{connection=%q,backend=\"wireguard\"} %d\n",
				connLabel(names, dev.Peers[i].PublicKey), dev.Peers[i].ReceiveBytes))
		}
		b.WriteString("# HELP cozyplane_vpn_connection_tx_bytes_total Bytes sent to the peer over the tunnel.\n")
		b.WriteString("# TYPE cozyplane_vpn_connection_tx_bytes_total counter\n")
		for i := range dev.Peers {
			b.WriteString(fmt.Sprintf("cozyplane_vpn_connection_tx_bytes_total{connection=%q,backend=\"wireguard\"} %d\n",
				connLabel(names, dev.Peers[i].PublicKey), dev.Peers[i].TransmitBytes))
		}
		b.WriteString("# HELP cozyplane_vpn_connection_up Whether the WireGuard peer has handshaked within the last 180 seconds.\n")
		b.WriteString("# TYPE cozyplane_vpn_connection_up gauge\n")
		now := time.Now()
		for i := range dev.Peers {
			up := 0
			if !dev.Peers[i].LastHandshakeTime.IsZero() && now.Sub(dev.Peers[i].LastHandshakeTime) <= wireGuardHandshakeTimeout {
				up = 1
			}
			b.WriteString(fmt.Sprintf("cozyplane_vpn_connection_up{connection=%q,backend=\"wireguard\"} %d\n",
				connLabel(names, dev.Peers[i].PublicKey), up))
		}
		b.WriteString("# HELP cozyplane_vpn_connection_last_handshake_timestamp_seconds Unix time of the peer's last handshake (0 if none).\n")
		b.WriteString("# TYPE cozyplane_vpn_connection_last_handshake_timestamp_seconds gauge\n")
		for i := range dev.Peers {
			var ts int64
			if !dev.Peers[i].LastHandshakeTime.IsZero() {
				ts = dev.Peers[i].LastHandshakeTime.Unix()
			}
			b.WriteString(fmt.Sprintf("cozyplane_vpn_connection_last_handshake_timestamp_seconds{connection=%q,backend=\"wireguard\"} %d\n",
				connLabel(names, dev.Peers[i].PublicKey), ts))
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		dev, err := wg.Device(wgDev)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(wireGuardSnapshot(dev, names, time.Now())); err != nil {
			log.Warn("encode status", "err", err)
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := wg.Device(wgDev); err != nil {
			http.Error(w, "WireGuard device unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{
		Addr:              metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second, // reap idle keep-alives; a misbehaving scraper can't pile up connections
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("metrics server stopped", "err", err)
	}
}

func wireGuardSnapshot(dev *wgtypes.Device, names map[wgtypes.Key]string, now time.Time) vpnstatus.Snapshot {
	s := vpnstatus.Snapshot{
		Backend:     "wireguard",
		ObservedAt:  now.UTC(),
		Connections: make(map[string]vpnstatus.Connection, len(dev.Peers)),
	}
	for i := range dev.Peers {
		p := &dev.Peers[i]
		last := int64(0)
		up := false
		if !p.LastHandshakeTime.IsZero() {
			last = p.LastHandshakeTime.Unix()
			up = now.Sub(p.LastHandshakeTime) <= wireGuardHandshakeTimeout
		}
		s.Connections[connLabel(names, p.PublicKey)] = vpnstatus.Connection{
			Up:                up,
			LastHandshakeUnix: last,
			RXBytes:           uint64(p.ReceiveBytes),
			TXBytes:           uint64(p.TransmitBytes),
		}
	}
	return s
}

// connLabel maps a peer's public key to its connection name, falling back to the
// key when unknown (a peer configured out of band).
func connLabel(names map[wgtypes.Key]string, key wgtypes.Key) string {
	if n := names[key]; n != "" {
		return n
	}
	return key.String()
}

// buildPeers turns the config peers into wgtypes peers and the set of remote
// routes to install on the WireGuard device.
func buildPeers(in []peer) ([]wgtypes.PeerConfig, []*net.IPNet, error) {
	var out []wgtypes.PeerConfig
	var routes []*net.IPNet
	for i, p := range in {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("peer %d public key: %w", i, err)
		}
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
		for _, cidr := range p.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, nil, fmt.Errorf("peer %d allowedIP %q: %w", i, cidr, err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
			routes = append(routes, ipnet)
		}
		if p.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return nil, nil, fmt.Errorf("peer %d endpoint %q: %w", i, p.Endpoint, err)
			}
			pc.Endpoint = addr
		}
		if p.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(p.PresharedKey)
			if err != nil {
				return nil, nil, fmt.Errorf("peer %d preshared key: %w", i, err)
			}
			pc.PresharedKey = &psk
		}
		if p.Keepalive > 0 {
			d := time.Duration(p.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		out = append(out, pc)
	}
	return out, routes, nil
}
