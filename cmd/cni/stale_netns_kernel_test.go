package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/vishvananda/netlink"
)

func TestKernelStaleDELReusedNetnsKeepsCurrentInterfaces(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	host, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for _, samePrefix := range []bool{false, true} {
		for _, gateway := range []bool{false, true} {
			t.Run(map[bool]string{false: "different host names", true: "same truncated prefix"}[samePrefix]+map[bool]string{false: "/secondary", true: "/gateway"}[gateway], func(t *testing.T) {
				pod, err := testutils.NewNS()
				if err != nil {
					t.Fatal(err)
				}
				defer pod.Close()
				defer testutils.UnmountNS(pod)
				current, old := strings.Repeat("e", 64), strings.Repeat("d", 64)
				if samePrefix {
					old = strings.Repeat("e", 11) + strings.Repeat("d", 53)
				}
				links := map[string]string{contVethName: hostVethNameFor(current), defaultIfName(1): hostVethNameForIndex(current, 1)}
				if gateway {
					delete(links, defaultIfName(1))
					links[gwVethName] = gwHostVethNameFor(current)
				}
				for podName, hostName := range links {
					if err = pod.Do(func(ns.NetNS) error { return setupSandboxVeth(current, "eth0", podName, hostName, 1400, host) }); err != nil {
						t.Fatal(err)
					}
					link, e := netlink.LinkByName(hostName)
					if e != nil {
						t.Fatal(e)
					}
					defer netlink.LinkDel(link)
					mac, _ := net.ParseMAC("02:00:00:00:00:01")
					if err = datapath.SetVethAlias(link, 101, []net.IP{net.ParseIP("10.0.0.2")}, mac); err != nil {
						t.Fatal(err)
					}
					if err = datapath.SetVethSandbox(link, current, "eth0"); err != nil {
						t.Fatal(err)
					}
				}
				args := &skel.CmdArgs{ContainerID: old, IfName: "eth0", Netns: pod.Path(), StdinData: []byte(`{"cniVersion":"1.0.0","name":"cozyplane","type":"cozyplane"}`)}
				if err = cmdDel(args); err != nil {
					t.Fatal("stale DEL failed", err)
				}
				if !samePrefix && !gateway {
					before, e := os.ReadDir("/proc/self/fd")
					if e != nil {
						t.Fatal(e)
					}
					workers := runtime.NumGoroutine()
					for range 64 {
						if e = cmdDel(args); e != nil {
							t.Fatal(e)
						}
					}
					after, e := os.ReadDir("/proc/self/fd")
					if e != nil {
						t.Fatal(e)
					}
					if len(after) != len(before) {
						t.Error("DEL descriptor growth", len(before), len(after))
					}
					if runtime.NumGoroutine() > workers+2 {
						t.Error("DEL worker growth", workers, runtime.NumGoroutine())
					}
				}
				if err = pod.Do(func(ns.NetNS) error {
					for name := range links {
						if _, e := netlink.LinkByName(name); e != nil {
							t.Errorf("stale DEL removed current pod interface %s: %v", name, e)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for _, name := range links {
					if _, e := netlink.LinkByName(name); e != nil {
						t.Errorf("stale DEL removed current host peer %s: %v", name, e)
					}
				}
			})
		}
	}
}

func TestKernelDELRejectsPeerIndexInDifferentNamespace(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	host, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	oldPod, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	defer oldPod.Close()
	defer testutils.UnmountNS(oldPod)
	currentPod, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	defer currentPod.Close()
	defer testutils.UnmountNS(currentPod)
	id := strings.Repeat("b", 64)
	name := hostVethNameFor(id)
	if err = oldPod.Do(func(ns.NetNS) error { return setupSandboxVeth(id, "eth0", "eth0", name, 1400, host) }); err != nil {
		t.Fatal(err)
	}
	oldHost, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(oldHost)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if err = datapath.SetVethAlias(oldHost, 101, []net.IP{net.ParseIP("10.0.0.2")}, mac); err != nil {
		t.Fatal(err)
	}
	if err = datapath.SetVethSandbox(oldHost, id, "eth0"); err != nil {
		t.Fatal(err)
	}
	// Force the foreign local peer's namespace-local index to equal a real
	// owned host peer index. A host LinkByIndex check alone would accept it.
	if err = currentPod.Do(func(ns.NetNS) error {
		return netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "inside", Index: oldHost.Attrs().Index}, PeerName: "eth0"})
	}); err != nil {
		t.Fatal(err)
	}
	if err = netlink.SetNetNsIdByFd(int(currentPod.Fd()), -1); err != nil {
		t.Fatal(err)
	}
	if err = currentPod.Do(func(ns.NetNS) error {
		link, e := netlink.LinkByName("eth0")
		if e != nil {
			return e
		}
		peer, e := netlink.VethPeerIndex(link.(*netlink.Veth))
		if e != nil {
			return e
		}
		if peer != oldHost.Attrs().Index {
			return fmt.Errorf("fixture peer index %d does not collide with owned host index %d", peer, oldHost.Attrs().Index)
		}
		addresses, e := deleteSandboxPodVeth(id, "eth0", "eth0", host, currentPod)
		if e != nil || len(addresses) != 0 {
			return fmt.Errorf("foreign namespace deletion result: addresses=%v error=%v", addresses, e)
		}
		_, e = netlink.LinkByName("eth0")
		return e
	}); err != nil {
		t.Fatal("foreign local peer was deleted", err)
	}
	if _, err = netlink.LinkByName(name); err != nil {
		t.Fatal("owned peer in other namespace changed", err)
	}
}

func TestKernelDELPreservesUnknownAndNonVethInterfaces(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	host, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	pod, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	defer pod.Close()
	defer testutils.UnmountNS(pod)
	id := strings.Repeat("c", 64)
	name := hostVethNameFor(id)
	if err = pod.Do(func(ns.NetNS) error { return setupSandboxVeth(id, "eth0", "eth0", name, 1400, host) }); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	if err = pod.Do(func(ns.NetNS) error {
		if e := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}}); e != nil {
			return e
		}
		for _, name := range []string{"eth0", "eth1"} {
			if _, e := deleteSandboxPodVeth(id, "eth0", name, host, pod); e != nil {
				return e
			}
			if _, e := netlink.LinkByName(name); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		t.Fatal("unproven interface deleted", err)
	}
}

func TestKernelCurrentDELOwnedNetnsRemovesInterfaces(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	host, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	pod, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	defer pod.Close()
	defer testutils.UnmountNS(pod)
	id := strings.Repeat("f", 64)
	names := map[string]string{contVethName: hostVethNameFor(id), defaultIfName(1): hostVethNameForIndex(id, 1)}
	for podName, hostName := range names {
		if err = pod.Do(func(ns.NetNS) error { return setupSandboxVeth(id, "eth0", podName, hostName, 1400, host) }); err != nil {
			t.Fatal(err)
		}
		link, e := netlink.LinkByName(hostName)
		if e != nil {
			t.Fatal(e)
		}
		defer netlink.LinkDel(link)
		mac, _ := net.ParseMAC("02:00:00:00:00:01")
		if err = datapath.SetVethAlias(link, 101, []net.IP{net.ParseIP("10.0.0.2")}, mac); err != nil {
			t.Fatal(err)
		}
		if err = datapath.SetVethSandbox(link, id, "eth0"); err != nil {
			t.Fatal(err)
		}
		if err = pod.Do(func(ns.NetNS) error {
			p, e := netlink.LinkByName(podName)
			if e != nil {
				return e
			}
			return netlink.AddrAdd(p, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	args := &skel.CmdArgs{ContainerID: id, IfName: "eth0", Netns: pod.Path(), StdinData: []byte(`{"cniVersion":"1.0.0","name":"cozyplane","type":"cozyplane"}`)}
	if err = cmdDel(args); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, e := netlink.LinkByName(name); e == nil {
			t.Error("owned peer retained", name)
		}
	}
	if err = cmdDel(args); err != nil {
		t.Fatal("repeat DEL failed", err)
	}
}
