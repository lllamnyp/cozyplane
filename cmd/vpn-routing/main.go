package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	defaultConfigPath = "/etc/cozyplane-vpn/config.json"
	frrConfigPath     = "/etc/frr/cozyplane-vpn.conf"
	frrRunDir         = "/run/frr"
)

type config struct {
	Routing *routingConfig `json:"routing"`
}

type routingConfig struct {
	LocalASN       int64    `json:"localASN"`
	PeerASN        int64    `json:"peerASN"`
	PeerAddresses  []string `json:"peerAddresses"`
	AdvertiseCIDRs []string `json:"advertiseCIDRs"`
	BFD            bool     `json:"bfd"`
}

func main() {
	path := os.Getenv("VPN_CONFIG")
	if path == "" {
		path = defaultConfigPath
	}
	if err := run(path, os.Getenv("POD_IP")); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, podIP string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read routing config: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse routing config: %w", err)
	}
	if cfg.Routing == nil {
		return errors.New("routing config is absent")
	}
	rendered, err := renderFRR(*cfg.Routing, podIP)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(frrConfigPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(frrRunDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(frrConfigPath, []byte(rendered), 0o600); err != nil {
		return fmt.Errorf("write FRR config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	commands := [][]string{
		{"/usr/lib/frr/zebra", "-f", frrConfigPath, "-z", filepath.Join(frrRunDir, "zserv.api"), "-i", filepath.Join(frrRunDir, "zebra.pid")},
	}
	if cfg.Routing.BFD {
		commands = append(commands, []string{"/usr/lib/frr/bfdd", "-f", frrConfigPath, "-z", filepath.Join(frrRunDir, "zserv.api"), "-i", filepath.Join(frrRunDir, "bfdd.pid")})
	}
	commands = append(commands, []string{"/usr/lib/frr/bgpd", "-f", frrConfigPath, "-z", filepath.Join(frrRunDir, "zserv.api"), "-i", filepath.Join(frrRunDir, "bgpd.pid")})

	exited := make(chan error, len(commands))
	for i, argv := range commands {
		if i > 0 {
			if err := waitForPath(ctx, filepath.Join(frrRunDir, "zserv.api")); err != nil {
				return err
			}
		}
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start %s: %w", filepath.Base(argv[0]), err)
		}
		go func(name string) { exited <- fmt.Errorf("%s exited: %w", name, cmd.Wait()) }(filepath.Base(argv[0]))
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-exited:
		return err
	}
}

func waitForPath(ctx context.Context, path string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func renderFRR(cfg routingConfig, podIP string) (string, error) {
	const maxASN = int64(4294967295)
	if cfg.LocalASN < 1 || cfg.LocalASN > maxASN || cfg.PeerASN < 1 || cfg.PeerASN > maxASN {
		return "", errors.New("BGP ASNs must be between 1 and 4294967295")
	}
	if len(cfg.PeerAddresses) == 0 {
		return "", errors.New("at least one BGP peer is required")
	}
	routerID := routerIDFor(podIP)
	peers4, peers6 := splitIPs(cfg.PeerAddresses)
	prefixes4, prefixes6, err := splitCIDRs(cfg.AdvertiseCIDRs)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "frr defaults traditional\nhostname cozyplane-vpn-routing\nlog stdout\nservice integrated-vtysh-config\n")
	if cfg.BFD {
		b.WriteString("bfd\n")
		for _, peer := range append(append([]string(nil), peers4...), peers6...) {
			fmt.Fprintf(&b, " peer %s\n  no shutdown\n exit\n", peer)
		}
		b.WriteString("exit\n")
	}
	fmt.Fprintf(&b, "router bgp %d\n bgp router-id %s\n no bgp ebgp-requires-policy\n", cfg.LocalASN, routerID)
	for _, peer := range append(append([]string(nil), peers4...), peers6...) {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", peer, cfg.PeerASN)
		if cfg.BFD {
			fmt.Fprintf(&b, " neighbor %s bfd\n", peer)
		}
	}
	renderFamily(&b, "ipv4", peers4, prefixes4)
	renderFamily(&b, "ipv6", peers6, prefixes6)
	b.WriteString("exit\n")
	return b.String(), nil
}

func renderFamily(b *strings.Builder, family string, peers, prefixes []string) {
	if len(peers) == 0 && len(prefixes) == 0 {
		return
	}
	fmt.Fprintf(b, " address-family %s unicast\n", family)
	for _, peer := range peers {
		fmt.Fprintf(b, "  neighbor %s activate\n", peer)
	}
	for _, prefix := range prefixes {
		fmt.Fprintf(b, "  network %s\n", prefix)
	}
	b.WriteString(" exit-address-family\n")
}

func routerIDFor(podIP string) string {
	if ip := net.ParseIP(podIP); ip != nil && ip.To4() != nil {
		return ip.To4().String()
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(podIP))
	v := h.Sum32()
	return fmt.Sprintf("10.%d.%d.%d", byte(v>>16), byte(v>>8), byte(v))
}

func splitIPs(values []string) (v4, v6 []string) {
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

func splitCIDRs(values []string) (v4, v6 []string, err error) {
	for _, value := range values {
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("advertise CIDR %q: %w", value, parseErr)
		}
		if network.IP.To4() != nil {
			v4 = append(v4, network.String())
		} else {
			v6 = append(v6, network.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}
