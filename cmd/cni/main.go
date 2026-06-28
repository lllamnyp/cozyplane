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

// Command cozyplane is the CNI plugin. It sets up a pod's interface on the
// default network and attaches the eBPF overlay classifier to the host veth.
// IPAM is delegated to the standard host-local plugin, with the range injected
// from the node pod CIDR the agent publishes.
package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/lllamnyp/cozyplane/datapath"
)

const (
	contVethName = "eth0"
	ipamPlugin   = "host-local"
)

// linkLocalGW is the on-link next hop installed in every pod, answered by the
// host-side veth via proxy_arp (Calico-style point-to-point veth).
var linkLocalGW = net.IPv4(169, 254, 1, 1)

// NetConf is the plugin configuration.
type NetConf struct {
	types.NetConf
	// MTU overrides the agent-published MTU when non-zero.
	MTU int `json:"mtu,omitempty"`
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, "cozyplane CNI")
}

func loadConf(stdin []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, fmt.Errorf("parse network config: %w", err)
	}
	return conf, nil
}

// ipamStdin rewrites the plugin config so the ipam section drives host-local
// over the node pod CIDR published by the agent.
func ipamStdin(stdin []byte, podCIDR string) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(stdin, &raw); err != nil {
		return nil, err
	}
	raw["ipam"] = map[string]interface{}{
		"type":   ipamPlugin,
		"ranges": [][]map[string]string{{{"subnet": podCIDR}}},
	}
	return json.Marshal(raw)
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	state, err := datapath.LoadAgentState()
	if err != nil {
		return err
	}

	mtu := conf.MTU
	if mtu == 0 {
		mtu = state.MTU
	}

	// Delegate IP allocation to host-local over the node pod CIDR.
	ipamData, err := ipamStdin(args.StdinData, state.PodCIDR)
	if err != nil {
		return err
	}
	r, err := ipam.ExecAdd(ipamPlugin, ipamData)
	if err != nil {
		return fmt.Errorf("ipam add: %w", err)
	}
	defer func() {
		if err != nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}()

	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}
	if len(ipamResult.IPs) == 0 {
		return fmt.Errorf("ipam returned no addresses")
	}
	podIP := ipamResult.IPs[0].Address.IP

	hostNS, err := ns.GetCurrentNS()
	if err != nil {
		return fmt.Errorf("get host netns: %w", err)
	}
	defer hostNS.Close()

	var hostVethName string
	if err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		hostVeth, _, e := ip.SetupVethWithName(contVethName, hostVethNameFor(args.ContainerID), mtu, "", hostNS)
		if e != nil {
			return e
		}
		hostVethName = hostVeth.Name
		return configurePodIface(podIP)
	}); err != nil {
		return err
	}

	// netID 0 = default/system network. VPC attachment sets this in Inc3.
	if err = configureHostVeth(hostVethName, podIP, 0); err != nil {
		return err
	}

	result := &current.Result{
		CNIVersion: conf.CNIVersion,
		IPs:        ipamResult.IPs,
		Interfaces: []*current.Interface{{
			Name:    contVethName,
			Sandbox: args.Netns,
		}},
	}
	result.IPs[0].Interface = current.Int(0)

	return types.PrintResult(result, conf.CNIVersion)
}

// configurePodIface sets the pod's eth0 address, brings it up, and installs the
// link-local default route. Runs inside the pod netns.
func configurePodIface(podIP net.IP) error {
	link, err := netlink.LinkByName(contVethName)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)}}); err != nil {
		return fmt.Errorf("add pod address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	// On-link route to the gateway, then default via the gateway.
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: linkLocalGW, Mask: net.CIDRMask(32, 32)},
	}); err != nil {
		return fmt.Errorf("add gateway route: %w", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        linkLocalGW,
	}); err != nil {
		return fmt.Errorf("add default route: %w", err)
	}
	return nil
}

// configureHostVeth brings up the host-side veth, enables proxy_arp and
// forwarding, installs the /32 route to the pod, attaches the classifier, and
// records the pod's network id.
func configureHostVeth(name string, podIP net.IP, netID uint32) error {
	hv, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(hv); err != nil {
		return err
	}
	for key, val := range map[string]string{
		fmt.Sprintf("net/ipv4/conf/%s/proxy_arp", name):  "1",
		fmt.Sprintf("net/ipv4/conf/%s/forwarding", name): "1",
		fmt.Sprintf("net/ipv4/conf/%s/rp_filter", name):  "0",
	} {
		if err := writeProcSys(key, val); err != nil {
			return err
		}
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: hv.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: podIP, Mask: net.CIDRMask(32, 32)},
	}); err != nil {
		return fmt.Errorf("add pod /32 route: %w", err)
	}

	prog, err := datapath.OpenPinnedProgram()
	if err != nil {
		return err
	}
	defer prog.Close()
	if err := datapath.AttachIngress(hv.Attrs().Index, prog); err != nil {
		return err
	}

	return datapath.SetPortNet(hv.Attrs().Index, netID)
}

func cmdDel(args *skel.CmdArgs) error {
	// Clear the ports map entry; the host veth (and its tc filter) is removed
	// when the pod veth below is deleted.
	if hv, e := netlink.LinkByName(hostVethNameFor(args.ContainerID)); e == nil {
		_ = datapath.DelPortNet(hv.Attrs().Index)
	}

	state, err := datapath.LoadAgentState()
	if err == nil {
		if ipamData, e := ipamStdin(args.StdinData, state.PodCIDR); e == nil {
			_ = ipam.ExecDel(ipamPlugin, ipamData)
		}
	}

	if args.Netns == "" {
		return nil
	}
	// Deleting the pod veth removes its peer and the attached tc filter.
	err = ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		_, e := ip.DelLinkByNameAddr(contVethName)
		if e != nil && e == ip.ErrLinkNotFound {
			return nil
		}
		return e
	})
	if err != nil {
		return err
	}
	return nil
}

func cmdCheck(args *skel.CmdArgs) error { return nil }

func hostVethNameFor(containerID string) string {
	id := containerID
	if len(id) > 11 {
		id = id[:11]
	}
	return "cph" + id
}

func writeProcSys(path, value string) error {
	return datapath.WriteProcSys(path, value)
}
