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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/lllamnyp/cozyplane/internal/httpserver"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/strongswan/govici/vici"
	"github.com/vishvananda/netlink"

	"github.com/lllamnyp/cozyplane/internal/vpnidentity"
	"github.com/lllamnyp/cozyplane/internal/vpnipsecfilter"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"github.com/lllamnyp/cozyplane/internal/vpnmetrics"
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
	LocalID     string          `json:"localIdentity,omitempty"`
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
	LocalCIDRs  []string `json:"localCIDRs"`
	Proposals   []string `json:"proposals,omitempty"`
	DPDDelay    int      `json:"dpdDelay,omitempty"`
	IfID        uint32   `json:"ifId"` // the xfrm if_id binding SA ⇄ ipsec<ifId> interface
	AuthMode    string   `json:"authMode,omitempty"`
	RemoteID    string   `json:"remoteIdentity,omitempty"`
	EAPIdentity string   `json:"eapIdentity,omitempty"`
	EAPPassword string   `json:"eapPassword,omitempty"`
	AddressPool string   `json:"addressPool,omitempty"`
	LocalID     string   `json:"localIdentity,omitempty"`
	poolCIDR    string
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
	// A container restart keeps its pod network namespace. Revoke the previous
	// process' dataplane before even reading its replacement Secret.
	if err := closePreviousXfrm(); err != nil {
		return fmt.Errorf("close previous IPsec dataplane: %w", err)
	}
	defer func() {
		if err := closePreviousXfrm(); err != nil {
			log.Error("close IPsec dataplane", "err", err)
		}
	}()
	// #nosec G304 G703 -- VPN_CONFIG is an operator-set environment path to the controller-mounted Secret; tenant requests cannot select this path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	if err := checkExpectedConfig(raw, os.Getenv("VPN_CONFIG_CHECKSUM")); err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if err := validatePeerIdentities(cfg.Peers); err != nil {
		return err
	}
	if cfg.Credentials != nil {
		if err := validateIKECredentialBudget(*cfg.Credentials); err != nil {
			return err
		}
	}
	if len(cfg.Pools) > vpnlimits.AddressPools {
		return fmt.Errorf("IPsec address pools exceed 128")
	}
	for _, pool := range cfg.Pools {
		if problem := vpnlimits.IPsecPoolNameProblem(pool.Name, true); problem != "" {
			return fmt.Errorf("%s", problem)
		}
	}
	if problem := vpnlimits.IPsecScalarProblem("", cfg.LocalID); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	configured, err := configuredPeers(cfg)
	if err != nil {
		return err
	}
	cfg.Peers = configured
	for _, p := range cfg.Peers {
		if err := validatePeerSelectors(p); err != nil {
			return err
		}
	}
	xfrmPeers, err := groupXfrmPeers(cfg.Peers)
	if err != nil {
		return err
	}
	// Forwarding remains enabled across container restarts. Protect accepted
	// destinations before waiting for IKE/VICI, including a fresh namespace.
	if err := protectRemotePrefixes(xfrmPeers); err != nil {
		return err
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
	return superviseCharon(ctx, []string{charonBinary}, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		sess, err := waitForVICI(ctx, log)
		if err != nil {
			return err
		}
		defer sess.Close()
		closeOnCancel := context.AfterFunc(ctx, func() { _ = sess.Close() })
		defer closeOnCancel()
		requester := startupVICI{context: ctx, session: sess}
		if cfg.Credentials != nil {
			if err := loadIKECredentials(requester, *cfg.Credentials); err != nil {
				return fmt.Errorf("load IKE credentials: %w", err)
			}
		}
		for _, pool := range cfg.Pools {
			if err := loadAddressPool(requester, pool); err != nil {
				return fmt.Errorf("load address pool %q: %w", pool.Name, err)
			}
		}

		for _, p := range xfrmPeers {
			// The xfrm-interface the decrypted traffic lands on. Fatal on failure:
			// support was preflighted above, so a per-peer failure here is a real
			// error (a bad if_id/CIDR), not the kernel-capability gate.
			if err := ensureXfrm(p.IfID, p.RemoteCIDRs, p.LocalCIDRs, cfg.MTU); err != nil {
				return fmt.Errorf("peer %q xfrm interface: %w", p.Name, err)
			}
		}
		for _, p := range cfg.Peers {
			if err := loadPeer(requester, p); err != nil {
				return fmt.Errorf("load peer %q: %w", p.Name, err)
			}
			log.Info("ipsec connection loaded", "peer", p.Name, "ifId", p.IfID,
				"remoteCIDRs", p.RemoteCIDRs, "peerAddress", p.PeerAddress)
		}
		log.Info("ipsec tunnels configured", "peers", len(cfg.Peers))
		return nil
	}, func(ctx context.Context) { serveIPsecMetrics(ctx, cfg.Peers, log, configChecksum(raw)) })
}

func configChecksum(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func checkExpectedConfig(raw []byte, expected string) error {
	if expected != "" && expected != configChecksum(raw) {
		return fmt.Errorf("mounted VPN config does not match expected checksum")
	}
	return nil
}

func validatePeerIdentities(peers []peer) error {
	for _, p := range peers {
		if err := validatePeerBudget(p); err != nil {
			return err
		}
	}
	identities := make(map[string]string, len(peers))
	for _, p := range peers {
		identity := p.RemoteID
		if p.AuthMode == "eap" {
			identity = p.EAPIdentity
		}
		if !vpnidentity.Exact(identity) {
			return fmt.Errorf("peer %q requires an exact identity", p.Name)
		}
		key := vpnidentity.Key(identity)
		if previous, exists := identities[key]; exists {
			return fmt.Errorf("IPsec identity reused by %q and %q", previous, p.Name)
		}
		identities[key] = p.Name
	}
	return nil
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
func serveIPsecMetrics(ctx context.Context, peers []peer, log *slog.Logger, checksum string) {
	collector := &ipsecCollector{slot: make(chan struct{}, 1), open: func(ctx context.Context) (ipsecStream, error) { return openMetricsVICI(ctx, viciSocket) }}
	srv := httpserver.New(metricsAddr, ipsecMetricsHandler(collector, peers, log, checksum, readXfrmErrors))
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.ListenAndServe(); err != nil {
		log.Error("metrics server stopped", "err", err)
	}
}

func ipsecMetricsHandler(collector *ipsecCollector, peers []peer, log *slog.Logger, checksum string, readErrors func() (map[string]uint64, error)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics, _, err := collector.collect(r.Context(), peers)
		if err != nil {
			http.Error(w, "IPsec status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		counters, counterErr := readErrors()
		_, _ = w.Write([]byte(formatIPsecMetrics(metrics) + formatXfrmErrors(counters, counterErr)))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		metrics, observedAt, err := collector.collect(r.Context(), peers)
		if err != nil {
			http.Error(w, "IPsec status unavailable", http.StatusServiceUnavailable)
			return
		}
		snapshot := vpnstatus.Snapshot{
			ConfigChecksum: checksum,
			Backend:        "ipsec",
			ObservedAt:     observedAt,
			Connections:    make(map[string]vpnstatus.Connection, len(metrics)),
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
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := collector.collect(r.Context(), peers); err != nil {
			http.Error(w, "IPsec status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
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
					if established > 0 && established <= math.MaxInt64 {
						age := int64(established)
						ts := now.Unix() - age
						if now.Unix() >= age && ts > m.LastHandshakeSec {
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
	if m == nil {
		return ""
	}
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
	connections := make(map[string]vpnstatus.Connection, len(metrics))
	for name, m := range metrics {
		connections[name] = vpnstatus.Connection{
			Up: m.Up == 1, LastHandshakeUnix: m.LastHandshakeSec,
			RXBytes: m.RXBytes, TXBytes: m.TXBytes,
			RXPackets: m.RXPackets, TXPackets: m.TXPackets,
		}
	}
	return vpnmetrics.Format("ipsec", connections, true)
}

// probeXfrmSupport reports whether the kernel supports xfrm-interfaces, by
// creating and deleting a throwaway one. A kernel without CONFIG_XFRM_INTERFACE
// rejects LinkAdd with "operation not supported" / "unknown device type".
func probeXfrmSupport() (result error) {
	if err := closeXfrmProbe(); err != nil {
		return err
	}
	link := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: xfrmProbeName}, Ifid: xfrmProbeID}
	if err := netlink.LinkAdd(link); err != nil {
		return err
	}
	dev, err := netlink.LinkByName(xfrmProbeName)
	if err != nil {
		return err
	}
	defer func() {
		if err := netlink.LinkDel(dev); err != nil {
			result = fmt.Errorf("remove XFRM probe: %w", err)
		}
	}()
	return netlink.LinkSetAlias(dev, xfrmProbeAlias)
}

// ensureXfrm creates (idempotently) the xfrm-interface ipsec<ifId> bound to
// if_id, brings it up, and routes each remote CIDR to it. charon installs no
// routes (install_routes=no); these are what steer traffic into the SA.
func ensureXfrm(ifID uint32, remoteCIDRs, localCIDRs []string, mtu int) error {
	if ifID == 0 {
		return fmt.Errorf("IPsec if_id must be nonzero")
	}
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
	if err := validateXfrmDevice(dev, ifID); err != nil {
		return err
	}
	if err := netlink.LinkSetAlias(dev, xfrmDeviceAlias); err != nil {
		return fmt.Errorf("mark XFRM interface: %w", err)
	}
	if err := netlink.LinkSetDown(dev); err != nil {
		return err
	}
	dev, err = netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(dev, mtu); err != nil {
			return fmt.Errorf("set %s MTU to %d: %w", name, mtu, err)
		}
	}
	if err := vpnipsecfilter.Install(dev, localCIDRs); err != nil {
		return err
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
			sess, err := dialVICI(ctx, viciSocket)
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

func loadIKECredentials(sess viciRequester, creds ikeCredentials) error {
	if err := validateIKECredentialBudget(creds); err != nil {
		return err
	}
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

func loadAddressPool(sess viciRequester, pool addressPool) error {
	if problem := vpnlimits.IPsecPoolNameProblem(pool.Name, true); problem != "" {
		return fmt.Errorf("%s", problem)
	}
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

type viciRequester interface {
	CommandRequest(string, *vici.Message) (*vici.Message, error)
}

func sendVICI(sess viciRequester, command string, values map[string]any) error {
	req := vici.NewMessage()
	for key, value := range values {
		if err := req.Set(key, value); err != nil {
			return err
		}
	}
	return sendVICIMessage(sess, command, req)
}

func sendVICIMessage(sess viciRequester, command string, req *vici.Message) error {
	resp, err := sess.CommandRequest(command, req)
	if err != nil {
		return err
	}
	if messageString(resp, "success") != "yes" {
		// VICI diagnostics may contain credential material supplied by the
		// request. Do not echo them into the pod logs.
		return fmt.Errorf("%s was not acknowledged by charon", command)
	}
	return nil
}

// loadPeer loads the peer's PSK (load-shared) and connection (load-conn). The
// Route selection uses if_id; inbound selectors also bind the authenticated
// peer to its authorized prefixes (or its individually assigned pool address).
func loadPeer(sess viciRequester, p peer) error {
	if err := validatePeerBudget(p); err != nil {
		return err
	}
	if err := validatePeerSelectors(p); err != nil {
		return err
	}
	identity := p.RemoteID
	if p.AuthMode == "eap" {
		identity = p.EAPIdentity
	}
	if !vpnidentity.Exact(identity) {
		return fmt.Errorf("IPsec peer %s requires an exact authentication identity", p.Name)
	}
	if p.EAPPassword != "" && !vpnidentity.Exact(p.EAPIdentity) {
		return fmt.Errorf("IPsec peer %s requires an exact EAP identity", p.Name)
	}
	if p.PSK != "" {
		if !vpnidentity.Exact(p.RemoteID) {
			return fmt.Errorf("PSK peer %s requires an exact remote identity", p.Name)
		}
		// Restrict to the remote identity alone: the shared-key lookup accepts
		// an exact match on either end. A common local owner or wildcard would
		// make this credential available to unrelated peers again.
		if err := sendVICI(sess, "load-shared", map[string]any{"id": "ike-" + p.Name, "type": "IKE", "data": p.PSK, "owners": []string{p.RemoteID}}); err != nil {
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
		LocalTS:      append([]string(nil), p.LocalCIDRs...),
		RemoteTS:     append([]string(nil), p.RemoteCIDRs...),
		IfIDIn:       ifID,
		IfIDOut:      ifID,
		Mode:         "tunnel",
		StartAction:  startAction,
		ESPProposals: p.Proposals,
	}
	if p.AddressPool != "" {
		child.RemoteTS = []string{"dynamic"}
		for _, cidr := range p.RemoteCIDRs {
			prefix, _ := netip.ParsePrefix(cidr)
			if prefix.Masked().String() != p.poolCIDR {
				child.RemoteTS = append(child.RemoteTS, cidr)
			}
		}
	}
	if len(child.RemoteTS) == 0 {
		return fmt.Errorf("IPsec peer %s has no authorized remote traffic selectors", p.Name)
	}
	if len(child.LocalTS) == 0 {
		return fmt.Errorf("IPsec peer %s has no authorized local traffic selectors", p.Name)
	}
	if p.DPDDelay > 0 {
		child.DPDAction = "restart"
	}
	localAuth := "psk"
	remoteAuth := "psk"
	localEnd := viciEnd{Auth: localAuth, ID: p.LocalID}
	remoteEnd := viciEnd{Auth: remoteAuth, ID: p.RemoteID}
	switch p.AuthMode {
	case "certificate":
		localEnd = viciEnd{Auth: "pubkey", ID: p.LocalID}
		remoteEnd = viciEnd{Auth: "pubkey", ID: p.RemoteID}
	case "eap":
		localEnd = viciEnd{Auth: "pubkey", ID: p.LocalID}
		// Debian ships MSCHAPv2, not the optional eap-dynamic plugin. Charon
		// 6.0.1 does not select profiles by eap_id, so bind the IKE identity too.
		remoteEnd = viciEnd{Auth: "eap-mschapv2", ID: p.EAPIdentity, EAPID: p.EAPIdentity}
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

func validatePeerBudget(p peer) error {
	if problem := vpnlimits.IPsecPoolNameProblem(p.AddressPool, false); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	if len(p.PSK) > vpnlimits.IPsecAuthBytes || len(p.EAPPassword) > vpnlimits.IPsecAuthBytes {
		return fmt.Errorf("IPsec PSK/EAP credential exceeds byte limit")
	}
	if problem := vpnlimits.IPsecScalarProblem(p.PeerAddress, p.RemoteID, p.EAPIdentity, p.LocalID); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	if problem := vpnlimits.IPsecProposalProblem(p.Proposals); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	return nil
}

func validatePeerSelectors(p peer) error {
	if p.AddressPool != "" && p.AuthMode != "certificate" && p.AuthMode != "eap" {
		return fmt.Errorf("IPsec address pools require certificate or EAP authentication")
	}
	if p.AuthMode == "eap" && p.AddressPool == "" {
		return fmt.Errorf("IPsec EAP authentication requires an address pool")
	}
	if p.AddressPool != "" && p.poolCIDR == "" {
		return fmt.Errorf("IPsec pool selector was not resolved")
	}
	if len(p.LocalCIDRs) == 0 || len(p.LocalCIDRs) > vpnlimits.RoutePrefixes || len(p.RemoteCIDRs) > vpnlimits.RoutePrefixes {
		return fmt.Errorf("IPsec traffic selector capacity exceeded")
	}
	if p.AddressPool == "" && len(p.RemoteCIDRs) == 0 {
		return fmt.Errorf("IPsec peer has no authorized remote traffic selectors")
	}
	for _, cidrs := range [][]string{p.LocalCIDRs, p.RemoteCIDRs} {
		for _, raw := range cidrs {
			if len(raw) > vpnlimits.RoutePrefixBytes {
				return fmt.Errorf("IPsec traffic selector exceeds size budget")
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() || prefix.Bits() == 0 {
				return fmt.Errorf("IPsec traffic selector must be a unicast prefix")
			}
		}
	}
	if p.AuthMode != "" && p.AuthMode != "psk" && p.AuthMode != "certificate" && p.AuthMode != "eap" {
		return fmt.Errorf("unsupported IPsec authentication mode")
	}
	return nil
}

func validateIKECredentialBudget(creds ikeCredentials) error {
	if problem := vpnlimits.IPsecScalarProblem("", creds.LocalID); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	if len(creds.Certificate) > vpnlimits.IPsecTLSBytes || len(creds.PrivateKey) > vpnlimits.IPsecTLSBytes || len(creds.CA) > vpnlimits.IPsecTLSBytes {
		return fmt.Errorf("TLS credential exceeds VICI byte limit")
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
