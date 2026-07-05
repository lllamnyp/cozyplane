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

// Command cozyplane-gateway runs inside a VPC's egress gateway pod (a
// default-network pod with a second, gateway-attached leg into the VPC). The
// datapath delivers the VPC's off-net traffic to that leg; this binary makes
// the pod forward it out the fabric leg, masqueraded to the pod's own fabric
// address, under a default-deny filter:
//
//   - queries to cluster DNS on :53 are REDIRECTed to a local proxy that
//     forwards them upstream over its own sockets. Forwarding the packets
//     would not work: with kube-proxy-replacement, ClusterIP translation
//     happens at the socket level (cgroup connect hooks), never for packets
//     merely forwarded through a pod — only a real local socket gets
//     translated. Tenant pods keep their stock resolv.conf;
//   - everything else destined to cluster-internal CIDRs is dropped — the
//     tenant->system trust boundary holds through the gateway;
//   - the rest (the internet) is forwarded and masqueraded.
//
// It is deliberately dumb: netfilter rules, conntrack, and a ~screenful DNS
// proxy. Per-tenant DNS views, metadata, and floating IPs plug in here later.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"

	"github.com/lllamnyp/cozyplane/datapath"
)

func main() {
	var (
		vpcIface      string
		fabricIface   string
		clusterDNS    string
		internalCIDRs string
	)
	flag.StringVar(&vpcIface, "vpc-iface", "eth1", "the gateway's VPC leg (gateway-attach interface)")
	flag.StringVar(&fabricIface, "fabric-iface", "eth0", "the gateway's default-network leg")
	flag.StringVar(&clusterDNS, "cluster-dns", "", "cluster DNS ClusterIP to allow on :53 (empty disables DNS forwarding)")
	flag.StringVar(&internalCIDRs, "internal-cidrs", "", "comma-separated cluster-internal CIDRs the VPC must not reach (pod, service, node networks)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if err := run(vpcIface, fabricIface, clusterDNS, splitCIDRs(internalCIDRs), log); err != nil {
		log.Error("gateway failed", "err", err)
		os.Exit(1)
	}
}

func run(vpcIface, fabricIface, clusterDNS string, internalCIDRs []string, log *slog.Logger) error {
	// The CNI sets these up at gateway-attach; re-assert in case the netns was
	// recycled (privileged container, own netns only).
	if err := datapath.WriteProcSys("net/ipv4/ip_forward", "1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	if err := datapath.WriteProcSys("net/ipv6/conf/all/forwarding", "1"); err != nil {
		return fmt.Errorf("enable ipv6 forwarding: %w", err)
	}

	// The same policy in both families, each table seeing only its own
	// internal CIDRs (a v6 VPC's gateway forwards v6 out the dual-stack fabric
	// leg; the internal-deny must hold per family). This runs in the gateway's
	// OWN netns — it is not part of the node's netfilter footprint.
	for _, fam := range []struct {
		proto iptables.Protocol
		v6    bool
	}{{iptables.ProtocolIPv4, false}, {iptables.ProtocolIPv6, true}} {
		ipt, err := iptables.NewWithProtocol(fam.proto)
		if err != nil {
			return fmt.Errorf("init iptables (v6=%v): %w", fam.v6, err)
		}
		famCIDRs := cidrsOfFamily(internalCIDRs, fam.v6)
		famDNS := clusterDNS
		if dnsIP := net.ParseIP(clusterDNS); dnsIP != nil && (dnsIP.To4() == nil) != fam.v6 {
			famDNS = "" // the cluster DNS ClusterIP is the other family
		}
		for _, spec := range masqueradeRules(fabricIface) {
			if err := ipt.AppendUnique("nat", "POSTROUTING", spec...); err != nil {
				return fmt.Errorf("nat rule %v (v6=%v): %w", spec, fam.v6, err)
			}
		}
		for _, spec := range dnsRedirectRules(vpcIface, famDNS, famCIDRs, fam.v6) {
			if err := ipt.AppendUnique("nat", "PREROUTING", spec...); err != nil {
				return fmt.Errorf("dns redirect rule %v (v6=%v): %w", spec, fam.v6, err)
			}
		}
		for _, spec := range inputRules(vpcIface, fam.v6) {
			if err := ipt.AppendUnique("filter", "INPUT", spec...); err != nil {
				return fmt.Errorf("input rule %v (v6=%v): %w", spec, fam.v6, err)
			}
		}
		for _, spec := range forwardRules(vpcIface, famCIDRs) {
			if err := ipt.AppendUnique("filter", "FORWARD", spec...); err != nil {
				return fmt.Errorf("forward rule %v (v6=%v): %w", spec, fam.v6, err)
			}
		}
		// Default-deny anything the explicit rules didn't admit.
		if err := ipt.ChangePolicy("filter", "FORWARD", "DROP"); err != nil {
			return fmt.Errorf("set FORWARD policy (v6=%v): %w", fam.v6, err)
		}
	}

	if clusterDNS != "" {
		if err := runDNSProxy(net.JoinHostPort(clusterDNS, "53"), log); err != nil {
			return fmt.Errorf("start dns proxy: %w", err)
		}
	}

	log.Info("gateway ready", "vpcIface", vpcIface, "fabricIface", fabricIface,
		"clusterDNS", clusterDNS, "internalCIDRs", internalCIDRs)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	return nil
}

// masqueradeRules masquerades everything the gateway forwards out its fabric
// leg to the pod's own (fabric) address, so replies have a return path.
func masqueradeRules(fabricIface string) [][]string {
	return [][]string{
		{"-o", fabricIface, "-j", "MASQUERADE"},
	}
}

// dnsRedirectRules intercept tenant DNS queries headed for ANY
// cluster-internal destination and hand them to the local DNS proxy. Two
// reasons the destination varies: without socket-LB the query targets the
// cluster DNS ClusterIP; with Cilium's socket-LB the ClusterIP was already
// rewritten to a CoreDNS *pod IP* inside the client's connect() — so matching
// only the ClusterIP misses. Queries to external resolvers are not redirected;
// they forward like any internet traffic.
func dnsRedirectRules(vpcIface, clusterDNS string, internalCIDRs []string, v6 bool) [][]string {
	var dsts []string
	if clusterDNS != "" {
		mask := "/32"
		if v6 {
			mask = "/128"
		}
		dsts = append(dsts, clusterDNS+mask)
	}
	dsts = append(dsts, internalCIDRs...)
	if len(dsts) == 0 {
		return nil
	}
	var rules [][]string
	for _, dst := range dsts {
		for _, proto := range []string{"udp", "tcp"} {
			rules = append(rules, []string{
				"-i", vpcIface, "-d", dst, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "53",
			})
		}
	}
	return rules
}

// cidrsOfFamily filters a CIDR list to one address family.
func cidrsOfFamily(cidrs []string, v6 bool) []string {
	var out []string
	for _, c := range cidrs {
		if ip, _, err := net.ParseCIDR(c); err == nil && (ip.To4() == nil) == v6 {
			out = append(out, c)
		}
	}
	return out
}

// inputRules restrict what the VPC side may address to the gateway itself:
// the DNS proxy and reply traffic, nothing else.
func inputRules(vpcIface string, v6 bool) [][]string {
	var rules [][]string
	if v6 {
		// NDP is ICMPv6 — unlike ARP, ip6tables sees it, and dropping the
		// neighbor solicitation/advertisement leaves the VPC leg's fe80::1
		// next hop unresolvable (the same v4/v6 asymmetry the datapath's
		// v6_link_scoped bypass exists for).
		rules = append(rules,
			[]string{"-i", vpcIface, "-p", "icmpv6", "--icmpv6-type", "135", "-j", "ACCEPT"},
			[]string{"-i", vpcIface, "-p", "icmpv6", "--icmpv6-type", "136", "-j", "ACCEPT"},
		)
	}
	return append(rules,
		[]string{"-i", vpcIface, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		[]string{"-i", vpcIface, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		[]string{"-i", vpcIface, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		[]string{"-i", vpcIface, "-j", "DROP"},
	)
}

// forwardRules is the gateway's forwarding policy, in order: replies pass,
// internal CIDRs are dropped, and what remains — the outside world — is
// forwarded. The chain policy is DROP.
func forwardRules(vpcIface string, internalCIDRs []string) [][]string {
	rules := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, cidr := range internalCIDRs {
		rules = append(rules, []string{"-i", vpcIface, "-d", cidr, "-j", "DROP"})
	}
	rules = append(rules, []string{"-i", vpcIface, "-j", "ACCEPT"})
	return rules
}

// runDNSProxy serves :53 (UDP and TCP) and forwards each query to upstream
// over its own sockets, which the node's Service machinery translates
// (socket-LB or kube-proxy alike). Fire-and-forget goroutines per query.
func runDNSProxy(upstream string, log *slog.Logger) error {
	const timeout = 5 * time.Second

	uconn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		return fmt.Errorf("listen udp :53: %w", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, client, err := uconn.ReadFromUDP(buf)
			if err != nil {
				log.Error("dns udp read", "err", err)
				return
			}
			query := make([]byte, n)
			copy(query, buf[:n])
			go func(query []byte, client *net.UDPAddr) {
				up, err := net.DialTimeout("udp", upstream, timeout)
				if err != nil {
					return
				}
				defer up.Close()
				_ = up.SetDeadline(time.Now().Add(timeout))
				if _, err := up.Write(query); err != nil {
					return
				}
				resp := make([]byte, 65535)
				n, err := up.Read(resp)
				if err != nil {
					return
				}
				_, _ = uconn.WriteToUDP(resp[:n], client)
			}(query, client)
		}
	}()

	tln, err := net.Listen("tcp", ":53")
	if err != nil {
		return fmt.Errorf("listen tcp :53: %w", err)
	}
	go func() {
		for {
			conn, err := tln.Accept()
			if err != nil {
				log.Error("dns tcp accept", "err", err)
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				up, err := net.DialTimeout("tcp", upstream, timeout)
				if err != nil {
					return
				}
				defer up.Close()
				_ = conn.SetDeadline(time.Now().Add(timeout))
				_ = up.SetDeadline(time.Now().Add(timeout))
				go func() { _, _ = io.Copy(up, conn) }()
				_, _ = io.Copy(conn, up)
			}(conn)
		}
	}()

	return nil
}

func splitCIDRs(s string) []string {
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}
