package vpnnet

import (
	"fmt"
	"net/netip"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

const orgGatewayChain = "COZYPLANE-ORG-GATEWAY"

// MasqueradeOrgGateway lets tunnel traffic reach the organisation Gateway
// (docs/vpn.md § "Organisation gateway"): TCP 80/443 to each destination /32,
// and DNS to the cluster resolver when dns is set, leave the primary VPC leg —
// the link carrying the default route — masqueraded to the appliance's own VPC
// address, the only source the datapath re-sources toward the Gateway. It runs
// in the appliance's own netns, on every start.
func MasqueradeOrgGateway(destinations []string, dns string) error {
	var rules [][]string
	if len(destinations) > 0 || dns != "" {
		dev, err := defaultRouteLink()
		if err != nil {
			return err
		}
		if rules, err = orgGatewayRules(dev, destinations, dns); err != nil {
			return err
		}
	}
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		if len(rules) == 0 {
			return nil // no iptables in this netns: nothing can have been installed
		}
		return fmt.Errorf("init iptables: %w", err)
	}
	return syncOrgGatewayChain(ipt, rules)
}

type natTable interface {
	ChainExists(table, chain string) (bool, error)
	ClearChain(table, chain string) error
	ClearAndDeleteChain(table, chain string) error
	Append(table, chain string, rulespec ...string) error
	AppendUnique(table, chain string, rulespec ...string) error
	DeleteIfExists(table, chain string, rulespec ...string) error
}

// syncOrgGatewayChain rebuilds the private chain from scratch, so a restart in
// the same netns (a VM guest, a container restart) never keeps a stale
// destination; with no rules the chain and its jump are removed.
func syncOrgGatewayChain(ipt natTable, rules [][]string) error {
	if len(rules) == 0 {
		exists, err := ipt.ChainExists("nat", orgGatewayChain)
		if err != nil || !exists {
			return err
		}
		if err := ipt.DeleteIfExists("nat", "POSTROUTING", "-j", orgGatewayChain); err != nil {
			return fmt.Errorf("remove jump to %s: %w", orgGatewayChain, err)
		}
		return ipt.ClearAndDeleteChain("nat", orgGatewayChain)
	}
	if err := ipt.ClearChain("nat", orgGatewayChain); err != nil {
		return fmt.Errorf("prepare %s: %w", orgGatewayChain, err)
	}
	for _, rule := range rules {
		if err := ipt.Append("nat", orgGatewayChain, rule...); err != nil {
			return fmt.Errorf("organisation gateway rule %v: %w", rule, err)
		}
	}
	if err := ipt.AppendUnique("nat", "POSTROUTING", "-j", orgGatewayChain); err != nil {
		return fmt.Errorf("jump to %s: %w", orgGatewayChain, err)
	}
	return nil
}

func orgGatewayRules(dev string, destinations []string, dns string) ([][]string, error) {
	var rules [][]string
	for _, d := range destinations {
		if p, err := netip.ParsePrefix(d); err != nil || !p.Addr().Is4() || p.Bits() != 32 {
			return nil, fmt.Errorf("organisation gateway destination %q is not an IPv4 /32", d)
		}
		rules = append(rules, []string{"-o", dev, "-d", d, "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "MASQUERADE"})
	}
	if dns != "" {
		ip, err := netip.ParseAddr(dns)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("cluster DNS destination %q is not an IPv4 address", dns)
		}
		for _, proto := range []string{"udp", "tcp"} {
			rules = append(rules, []string{"-o", dev, "-d", ip.String() + "/32", "-p", proto, "--dport", "53", "-j", "MASQUERADE"})
		}
	}
	return rules, nil
}

func defaultRouteLink() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			return "", fmt.Errorf("default route link: %w", err)
		}
		return link.Attrs().Name, nil
	}
	return "", fmt.Errorf("no IPv4 default route: the primary VPC leg is unknown")
}
