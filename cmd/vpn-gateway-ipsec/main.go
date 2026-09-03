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

// cozyplane-vpn-gateway-ipsec terminates IKEv2/IPsec site-to-site tunnels inside
// a managed appliance pod's own netns (issue #6, docs/vpn.md §3.2), the
// enterprise-interop backend. It runs charon (strongSwan's IKE daemon),
// configures it over VICI from a mounted config (the peers a VPNGateway's
// VPNConnections describe), and terminates each tunnel route-based on an
// xfrm-interface — so decrypted traffic lands on ipsecN and leaves on the VPC
// leg with the remote source (which the appliance's scoped forwarding grant
// admits), exactly as the WireGuard backend does. cozyplane adds no crypto to
// its datapath; charon and the kernel's xfrm stack do it here, in this netns.
//
// Route-based (charon.install_routes=no + per-child if_id) keeps the datapath
// clean: no policy-based IPsec, no netfilter — the SA is selected by the
// xfrm-interface the remote CIDRs route to, not by a kernel SPD match.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/strongswan/govici/vici"
	"github.com/vishvananda/netlink"

	"github.com/lllamnyp/cozyplane/internal/vpnnet"
	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
)

const (
	viciSocket   = "/var/run/charon.vici"
	charonBinary = "/usr/lib/ipsec/charon"
)

// config is the mounted tunnel description. It carries PSKs, so it is delivered
// as a Secret, never a ConfigMap.
type config struct {
	MTU         int             `json:"mtu,omitempty"`
	Credentials *ikeCredentials `json:"credentials,omitempty"`
	Pools       []addressPool   `json:"pools,omitempty"`
	Peers       []peer          `json:"peers"`
}

type ikeCredentials struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	CA          string `json:"ca,omitempty"`
	LocalID     string `json:"localIdentity,omitempty"`
}

type addressPool struct {
	Name string   `json:"name"`
	CIDR string   `json:"cidr"`
	DNS  []string `json:"dns,omitempty"`
}

type peer struct {
	Name        string   `json:"name"`
	PeerAddress string   `json:"peerAddress,omitempty"` // remote IKE endpoint; empty = responder-only
	StartAction string   `json:"startAction,omitempty"` // "start" initiates; "none" is responder-only
	PSK         string   `json:"psk,omitempty"`
	RemoteCIDRs []string `json:"remoteCIDRs"`
	Proposals   []string `json:"proposals,omitempty"`
	DPDDelay    int      `json:"dpdDelay,omitempty"`
	IfID        uint32   `json:"ifId"` // the xfrm if_id binding SA ⇄ ipsec<ifId> interface
	AuthMode    string   `json:"authMode,omitempty"`
	RemoteID    string   `json:"remoteIdentity,omitempty"`
	EAPIdentity string   `json:"eapIdentity,omitempty"`
	EAPPassword string   `json:"eapPassword,omitempty"`
	AddressPool string   `json:"addressPool,omitempty"`
	LocalID     string   `json:"localIdentity,omitempty"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	path := os.Getenv("VPN_CONFIG")
	if path == "" {
		path = "/etc/cozyplane-vpn/config.json"
	}
	if err := run(path, log); err != nil {
		log.Error("vpn-gateway-ipsec failed", "err", err)
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

	if err := vpnnet.EnsureForwarding(); err != nil {
		return err
	}

	// Preflight the one hard kernel prerequisite before doing anything else, and
	// fail loud rather than bringing IKE up over a tunnel that can carry no
	// traffic. Route-based IPsec needs xfrm-interface support — mainline since
	// Linux 4.19, and the portable choice on any kernel that enables it. This
	// checks the effective runtime capability instead of guessing from a distro
	// or kernel version.
	if err := probeXfrmSupport(); err != nil {
		return fmt.Errorf("route-based IPsec cannot create an xfrm interface: %w — verify CONFIG_XFRM_INTERFACE and CAP_NET_ADMIN (docs/vpn.md §5)", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// charon runs as our child; if it dies, so must we, so the Deployment
	// restarts the pair. exec.CommandContext only binds the child's lifetime to
	// the context, never the reverse — so charon.Wait() is watched explicitly: a
	// charon that crashes/OOMs on its own resolves the run with an error (a
	// non-zero exit the kubelet restarts), instead of leaving a live pod with a
	// dead tunnel silently black-holing traffic.
	charon := exec.CommandContext(ctx, charonBinary)
	charon.Stdout, charon.Stderr = os.Stderr, os.Stderr
	if err := charon.Start(); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	log.Info("charon started", "pid", charon.Process.Pid)
	charonDied := make(chan error, 1)
	go func() { charonDied <- charon.Wait() }()

	sess, err := waitForVICI(ctx, log)
	if err != nil {
		return err
	}
	defer sess.Close()
	if cfg.Credentials != nil {
		if err := loadIKECredentials(sess, *cfg.Credentials); err != nil {
			return fmt.Errorf("load IKE credentials: %w", err)
		}
	}
	for _, pool := range cfg.Pools {
		if err := loadAddressPool(sess, pool); err != nil {
			return fmt.Errorf("load address pool %q: %w", pool.Name, err)
		}
	}

	for _, p := range cfg.Peers {
		if cfg.Credentials != nil {
			p.LocalID = cfg.Credentials.LocalID
		}
		// The xfrm-interface the decrypted traffic lands on. Fatal on failure:
		// support was preflighted above, so a per-peer failure here is a real
		// error (a bad if_id/CIDR), not the kernel-capability gate.
		if err := ensureXfrm(p.IfID, p.RemoteCIDRs, cfg.MTU); err != nil {
			return fmt.Errorf("peer %q xfrm interface: %w", p.Name, err)
		}
		if err := loadPeer(sess, p); err != nil {
			return fmt.Errorf("load peer %q: %w", p.Name, err)
		}
		log.Info("ipsec connection loaded", "peer", p.Name, "ifId", p.IfID,
			"remoteCIDRs", p.RemoteCIDRs, "peerAddress", p.PeerAddress)
	}
	log.Info("ipsec tunnels configured", "peers", len(cfg.Peers))
	go serveIPsecMetrics(sess, cfg.Peers, log)

	select {
	case <-ctx.Done():
		return nil // a signal: shut down gracefully
	case err := <-charonDied:
		// charon exited on its own (crash/OOM/CVE) — fail the process so the
		// kubelet restarts the pair rather than leaving a dead tunnel up.
		return fmt.Errorf("charon exited unexpectedly: %w", err)
	}
}

const metricsAddr = ":9410"

type ipsecConnectionMetrics struct {
	RXBytes           uint64
	TXBytes           uint64
	RXPackets         uint64
	TXPackets         uint64
	Up                uint64
	LastHandshakeSec  int64
	AssignedAddresses []string
}

// serveIPsecMetrics exposes one series per configured VPNConnection. Each
// scrape reads live IKE/CHILD SA state over VICI, so rekeys and failures are
// reflected without a separate cache or polling loop.
func serveIPsecMetrics(sess *vici.Session, peers []peer, log *slog.Logger) {
	var mu sync.Mutex // VICI streaming subscriptions are session-scoped.
	collect := func() (map[string]ipsecConnectionMetrics, time.Time, error) {
		mu.Lock()
		events, err := sess.StreamedCommandRequest("list-sas", "list-sa", vici.NewMessage())
		mu.Unlock()
		now := time.Now().UTC()
		if err != nil {
			return nil, now, err
		}
		return collectIPsecMetrics(events, peers, now), now, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		metrics, _, err := collect()
		if err != nil {
			http.Error(w, "IPsec status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(formatIPsecMetrics(metrics)))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		metrics, observedAt, err := collect()
		if err != nil {
			http.Error(w, "IPsec status unavailable", http.StatusServiceUnavailable)
			return
		}
		snapshot := vpnstatus.Snapshot{
			Backend:     "ipsec",
			ObservedAt:  observedAt,
			Connections: make(map[string]vpnstatus.Connection, len(metrics)),
		}
		for name, m := range metrics {
			snapshot.Connections[name] = vpnstatus.Connection{
				Up:                m.Up == 1,
				LastHandshakeUnix: m.LastHandshakeSec,
				RXBytes:           m.RXBytes,
				TXBytes:           m.TXBytes,
				RXPackets:         m.RXPackets,
				TXPackets:         m.TXPackets,
				AssignedAddresses: append([]string(nil), m.AssignedAddresses...),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			log.Warn("encode IPsec status", "err", err)
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if _, _, err := collect(); err != nil {
			http.Error(w, "IPsec status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{
		Addr:              metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("metrics server stopped", "err", err)
	}
}

func collectIPsecMetrics(events []*vici.Message, peers []peer, now time.Time) map[string]ipsecConnectionMetrics {
	metrics := make(map[string]ipsecConnectionMetrics, len(peers))
	for _, p := range peers {
		metrics[p.Name] = ipsecConnectionMetrics{}
	}
	for _, event := range events {
		for _, ikeName := range event.Keys() {
			ike, ok := event.Get(ikeName).(*vici.Message)
			if !ok {
				continue
			}
			established := messageUint(ike, "established")
			remoteVIPs := messageStrings(ike, "remote-vips")
			children, ok := ike.Get("child-sas").(*vici.Message)
			if !ok {
				continue
			}
			for _, childKey := range children.Keys() {
				child, ok := children.Get(childKey).(*vici.Message)
				if !ok {
					continue
				}
				name := messageString(child, "name")
				if name == "" {
					name = ikeName
				}
				m, configured := metrics[name]
				if !configured {
					continue
				}
				m.RXBytes += messageUint(child, "bytes-in")
				m.TXBytes += messageUint(child, "bytes-out")
				m.RXPackets += messageUint(child, "packets-in")
				m.TXPackets += messageUint(child, "packets-out")
				if messageString(child, "state") == "INSTALLED" {
					m.Up = 1
					if established > 0 {
						ts := now.Add(-time.Duration(established) * time.Second).Unix()
						if ts > m.LastHandshakeSec {
							m.LastHandshakeSec = ts
						}
					}
				}
				m.AssignedAddresses = appendUniqueStrings(m.AssignedAddresses, remoteVIPs...)
				metrics[name] = m
			}
		}
	}
	return metrics
}

func messageString(m *vici.Message, key string) string {
	v, _ := m.Get(key).(string)
	return v
}

func messageUint(m *vici.Message, key string) uint64 {
	v, err := strconv.ParseUint(messageString(m, key), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func messageStrings(m *vici.Message, key string) []string {
	v, _ := m.Get(key).([]string)
	return append([]string(nil), v...)
}

func appendUniqueStrings(dst []string, values ...string) []string {
	seen := make(map[string]bool, len(dst)+len(values))
	for _, value := range dst {
		seen[value] = true
	}
	for _, value := range values {
		if value != "" && !seen[value] {
			dst = append(dst, value)
			seen[value] = true
		}
	}
	sort.Strings(dst)
	return dst
}

func formatIPsecMetrics(metrics map[string]ipsecConnectionMetrics) string {
	names := make([]string, 0, len(metrics))
	for name := range metrics {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# HELP cozyplane_vpn_connection_rx_bytes_total Bytes received from the peer over the tunnel.\n")
	b.WriteString("# TYPE cozyplane_vpn_connection_rx_bytes_total counter\n")
	for _, name := range names {
		fmt.Fprintf(&b, "cozyplane_vpn_connection_rx_bytes_total{connection=%q,backend=\"ipsec\"} %d\n", name, metrics[name].RXBytes)
	}
	b.WriteString("# HELP cozyplane_vpn_connection_tx_bytes_total Bytes sent to the peer over the tunnel.\n")
	b.WriteString("# TYPE cozyplane_vpn_connection_tx_bytes_total counter\n")
	for _, name := range names {
		fmt.Fprintf(&b, "cozyplane_vpn_connection_tx_bytes_total{connection=%q,backend=\"ipsec\"} %d\n", name, metrics[name].TXBytes)
	}
	b.WriteString("# HELP cozyplane_vpn_connection_rx_packets_total Packets received from the peer over the tunnel.\n")
	b.WriteString("# TYPE cozyplane_vpn_connection_rx_packets_total counter\n")
	for _, name := range names {
		fmt.Fprintf(&b, "cozyplane_vpn_connection_rx_packets_total{connection=%q,backend=\"ipsec\"} %d\n", name, metrics[name].RXPackets)
	}
	b.WriteString("# HELP cozyplane_vpn_connection_tx_packets_total Packets sent to the peer over the tunnel.\n")
	b.WriteString("# TYPE cozyplane_vpn_connection_tx_packets_total counter\n")
	for _, name := range names {
		fmt.Fprintf(&b, "cozyplane_vpn_connection_tx_packets_total{connection=%q,backend=\"ipsec\"} %d\n", name, metrics[name].TXPackets)
	}
	b.WriteString("# HELP cozyplane_vpn_connection_up Whether at least one CHILD_SA is installed for the connection.\n")
	b.WriteString("# TYPE cozyplane_vpn_connection_up gauge\n")
	for _, name := range names {
		fmt.Fprintf(&b, "cozyplane_vpn_connection_up{connection=%q,backend=\"ipsec\"} %d\n", name, metrics[name].Up)
	}
	b.WriteString("# HELP cozyplane_vpn_connection_last_handshake_timestamp_seconds Unix time of the latest established IKE SA (0 if none).\n")
	b.WriteString("# TYPE cozyplane_vpn_connection_last_handshake_timestamp_seconds gauge\n")
	for _, name := range names {
		fmt.Fprintf(&b, "cozyplane_vpn_connection_last_handshake_timestamp_seconds{connection=%q,backend=\"ipsec\"} %d\n", name, metrics[name].LastHandshakeSec)
	}
	return b.String()
}

// probeXfrmSupport reports whether the kernel supports xfrm-interfaces, by
// creating and deleting a throwaway one. A kernel without CONFIG_XFRM_INTERFACE
// rejects LinkAdd with "operation not supported" / "unknown device type".
func probeXfrmSupport() error {
	const probe = "cpxfrmprobe"
	link := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: probe}, Ifid: 0x0cb1}
	if err := netlink.LinkAdd(link); err != nil {
		return err
	}
	if l, e := netlink.LinkByName(probe); e == nil {
		_ = netlink.LinkDel(l)
	}
	return nil
}

// ensureXfrm creates (idempotently) the xfrm-interface ipsec<ifId> bound to
// if_id, brings it up, and routes each remote CIDR to it. charon installs no
// routes (install_routes=no); these are what steer traffic into the SA.
func ensureXfrm(ifID uint32, remoteCIDRs []string, mtu int) error {
	name := fmt.Sprintf("ipsec%d", ifID)
	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Ifid:      ifID,
	}
	if err := netlink.LinkAdd(link); err != nil && !os.IsExist(err) {
		if _, e := netlink.LinkByName(name); e != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	dev, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find %s: %w", name, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(dev, mtu); err != nil {
			return fmt.Errorf("set %s MTU to %d: %w", name, mtu, err)
		}
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	for _, cidr := range remoteCIDRs {
		dst, err := netlink.ParseIPNet(cidr)
		if err != nil {
			return fmt.Errorf("remote CIDR %q: %w", cidr, err)
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: dev.Attrs().Index, Dst: dst}); err != nil {
			return fmt.Errorf("route %s dev %s: %w", cidr, name, err)
		}
	}
	return nil
}

// waitForVICI blocks until charon's VICI socket accepts a session (charon takes
// a moment to open it after start), or the context is cancelled.
func waitForVICI(ctx context.Context, log *slog.Logger) (*vici.Session, error) {
	for {
		if _, err := os.Stat(viciSocket); err == nil {
			sess, err := vici.NewSession(vici.WithSocketPath(viciSocket))
			if err == nil {
				return sess, nil
			}
			if sess != nil {
				_ = sess.Close() // never leak a half-open session across retries
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("charon VICI socket never became ready: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// viciChild is one CHILD_SA (the tunnel proper), route-based via if_id.
type viciChild struct {
	LocalTS      []string `vici:"local_ts"`
	RemoteTS     []string `vici:"remote_ts"`
	IfIDIn       string   `vici:"if_id_in"`
	IfIDOut      string   `vici:"if_id_out"`
	Mode         string   `vici:"mode"`
	StartAction  string   `vici:"start_action"`
	DPDAction    string   `vici:"dpd_action,omitempty"`
	ESPProposals []string `vici:"esp_proposals,omitempty"`
}

// viciEnd is one end of the IKE_SA's authentication.
type viciEnd struct {
	Auth  string `vici:"auth"`
	ID    string `vici:"id,omitempty"`
	EAPID string `vici:"eap_id,omitempty"`
}

// viciConn is a strongSwan connection (swanctl connections.<name>).
type viciConn struct {
	Version     int                  `vici:"version"`
	LocalAddrs  []string             `vici:"local_addrs,omitempty"`
	RemoteAddrs []string             `vici:"remote_addrs,omitempty"`
	Local       viciEnd              `vici:"local"`
	Remote      viciEnd              `vici:"remote"`
	Children    map[string]viciChild `vici:"children"`
	Proposals   []string             `vici:"proposals,omitempty"`
	DPDDelay    string               `vici:"dpd_delay,omitempty"`
	Pools       []string             `vici:"pools,omitempty"`
}

func loadIKECredentials(sess *vici.Session, creds ikeCredentials) error {
	for _, item := range []struct {
		command string
		values  map[string]any
	}{
		{command: "load-cert", values: map[string]any{"type": "X509", "flag": "NONE", "data": creds.Certificate}},
		{command: "load-key", values: map[string]any{"type": "any", "data": creds.PrivateKey}},
	} {
		if err := sendVICI(sess, item.command, item.values); err != nil {
			return err
		}
	}
	if creds.CA != "" {
		if err := sendVICI(sess, "load-cert", map[string]any{"type": "X509", "flag": "CA", "data": creds.CA}); err != nil {
			return err
		}
	}
	return nil
}

func loadAddressPool(sess *vici.Session, pool addressPool) error {
	entry := vici.NewMessage()
	if err := entry.Set("addrs", pool.CIDR); err != nil {
		return err
	}
	if len(pool.DNS) > 0 {
		if err := entry.Set("dns", pool.DNS); err != nil {
			return err
		}
	}
	req := vici.NewMessage()
	if err := req.Set(pool.Name, entry); err != nil {
		return err
	}
	return sendVICIMessage(sess, "load-pool", req)
}

func sendVICI(sess *vici.Session, command string, values map[string]any) error {
	req := vici.NewMessage()
	for key, value := range values {
		if err := req.Set(key, value); err != nil {
			return err
		}
	}
	return sendVICIMessage(sess, command, req)
}

func sendVICIMessage(sess *vici.Session, command string, req *vici.Message) error {
	resp, err := sess.CommandRequest(command, req)
	if err != nil {
		return err
	}
	if success := messageString(resp, "success"); success != "" && success != "yes" {
		return fmt.Errorf("%s failed: %s", command, messageString(resp, "errmsg"))
	}
	return nil
}

// loadPeer loads the peer's PSK (load-shared) and connection (load-conn). The
// tunnel is route-based: TS 0.0.0.0/0 on both ends, selection by if_id.
func loadPeer(sess *vici.Session, p peer) error {
	if p.PSK != "" {
		// Deliberately omit owners. The VICI credential backend then assigns
		// %any, matching both local and remote IKE identities. Restricting the
		// secret to PeerAddress breaks local PSK authentication when the local
		// identity is the appliance's VPC address. Explicit local/remote IKE IDs
		// can narrow this once the API exposes them.
		if err := sendVICI(sess, "load-shared", map[string]any{"type": "IKE", "data": p.PSK}); err != nil {
			return fmt.Errorf("load-shared: %w", err)
		}
	}
	if p.EAPPassword != "" {
		if err := sendVICI(sess, "load-shared", map[string]any{
			"id": p.Name, "type": "EAP", "data": p.EAPPassword, "owners": []string{p.EAPIdentity},
		}); err != nil {
			return fmt.Errorf("load EAP secret: %w", err)
		}
	}

	ifID := strconv.FormatUint(uint64(p.IfID), 10)
	startAction := ipsecStartAction(p)
	child := viciChild{
		LocalTS:      []string{"0.0.0.0/0", "::/0"},
		RemoteTS:     []string{"0.0.0.0/0", "::/0"},
		IfIDIn:       ifID,
		IfIDOut:      ifID,
		Mode:         "tunnel",
		StartAction:  startAction,
		ESPProposals: p.Proposals,
	}
	if p.AddressPool != "" {
		child.RemoteTS = []string{"dynamic"}
	}
	if p.DPDDelay > 0 {
		child.DPDAction = "restart"
	}
	localAuth := "psk"
	remoteAuth := "psk"
	localEnd := viciEnd{Auth: localAuth}
	remoteEnd := viciEnd{Auth: remoteAuth}
	switch p.AuthMode {
	case "certificate":
		localEnd = viciEnd{Auth: "pubkey", ID: p.LocalID}
		remoteEnd = viciEnd{Auth: "pubkey", ID: p.RemoteID}
	case "eap":
		localEnd = viciEnd{Auth: "pubkey", ID: p.LocalID}
		remoteEnd = viciEnd{Auth: "eap-dynamic", EAPID: p.EAPIdentity}
	}
	conn := viciConn{
		Version:   2, // IKEv2
		Local:     localEnd,
		Remote:    remoteEnd,
		Children:  map[string]viciChild{p.Name: child},
		Proposals: p.Proposals,
	}
	if p.AddressPool != "" {
		conn.Pools = []string{p.AddressPool}
	}
	if p.PeerAddress != "" {
		conn.RemoteAddrs = []string{p.PeerAddress}
	}
	if p.DPDDelay > 0 {
		conn.DPDDelay = strconv.Itoa(p.DPDDelay) + "s"
	}

	connMsg, err := vici.MarshalMessage(conn)
	if err != nil {
		return fmt.Errorf("marshal connection: %w", err)
	}
	req := vici.NewMessage()
	if err := req.Set(p.Name, connMsg); err != nil {
		return err
	}
	if err := sendVICIMessage(sess, "load-conn", req); err != nil {
		return fmt.Errorf("load-conn: %w", err)
	}
	return nil
}

// ipsecStartAction keeps old API objects compatible while allowing a managed
// peer to explicitly remain responder-only even when its address is known.
func ipsecStartAction(p peer) string {
	switch strings.ToLower(p.StartAction) {
	case "start":
		return "start"
	case "none":
		return "none"
	default:
		if p.PeerAddress != "" {
			return "start"
		}
		return "none"
	}
}
