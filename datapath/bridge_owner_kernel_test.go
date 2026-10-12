package datapath

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKernelBridgeAddressReuseKeepsNewSandbox(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("isolated privileged Linux container required")
	}
	if entries, err := os.ReadDir(PinRoot); err == nil && len(entries) > 0 {
		t.Fatal("refusing to touch existing pinned state")
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/sys/fs/bpf", 0)
	if err := os.MkdirAll(PinRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	maps := map[string]*ebpf.Map{}
	for _, name := range []string{"bridges", "bridge_owners", "fabric_of", "locals", "ports", "fwd_cidrs"} {
		mapSpec := spec.Maps[name].Copy()
		mapSpec.Pinning = ebpf.PinNone
		m, err := ebpf.NewMap(mapSpec)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if err := m.Pin(filepath.Join(PinRoot, name)); err != nil {
			t.Fatal(err)
		}
		defer m.Unpin()
		maps[name] = m
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	create := func(name, id, ip string) netlink.Link {
		t.Helper()
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1400}, PeerName: name + "p"}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		if err := SetVethAlias(link, 101, []net.IP{net.ParseIP(ip)}, mac); err != nil {
			t.Fatal(err)
		}
		if err := SetVethSandbox(link, id, "eth0"); err != nil {
			t.Fatal(err)
		}
		return link
	}
	old := create("cphold", "old", "10.70.0.2")
	current := create("cphnew", "current", "10.70.0.3")
	t.Run("rebuild and revoke bridge whose fabric equals VPC address", func(t *testing.T) {
		for i, address := range []string{"203.0.113.187", "fd00:187::10"} {
			t.Run(address, func(t *testing.T) {
				name := []string{"cph187v4", "cph187v6"}[i]
				ip := net.ParseIP(address)
				link := create(name, "sandbox-187", address)
				peer, err := netlink.LinkByName(name + "p")
				if err != nil {
					t.Fatal(err)
				}
				if err := netlink.LinkSetUp(peer); err != nil {
					t.Fatal(err)
				}
				if err := ConfigureEndpoint(link, 101, []net.IP{ip}, mac, "sandbox-187", "eth0", PortVethIdentity{UID: "port-187"}, nil); err != nil {
					t.Fatal(err)
				}
				if err := AddBridge(address, address, name, 101, mac); err != nil {
					t.Fatal(err)
				}
				key, _ := addr128Str(address)
				inverseKey, _ := localKey(101, ip)
				// Model lost bridge pins while the authoritative live veth route
				// and sandbox alias survive an agent/map restart.
				for _, name := range []string{"bridges", "bridge_owners"} {
					if err := maps[name].Delete(key); err != nil {
						t.Fatal(err)
					}
				}
				if err := maps["fabric_of"].Delete(inverseKey); err != nil {
					t.Fatal(err)
				}
				fresh, err := netlink.LinkByIndex(link.Attrs().Index)
				if err != nil {
					t.Fatal(err)
				}
				if err := rebuildVeth(fresh, fresh.Attrs().Index, 101, []net.IP{ip}, mac); err != nil {
					t.Fatal(err)
				}
				var bridge overlayBridgeEp
				var owner overlayBridgeOwner
				var inverse overlayAddr128
				if err := maps["bridges"].Lookup(key, &bridge); err != nil || bridge.Net != 101 || bridge.VpcIp != key {
					t.Fatal("equal-address bridge was not reconstructed", bridge, err)
				}
				if err := maps["bridge_owners"].Lookup(key, &owner); err != nil || owner.Ifindex != uint32(link.Attrs().Index) {
					t.Fatal("reconstructed bridge lost its sandbox owner", owner, err)
				}
				if err := maps["fabric_of"].Lookup(inverseKey, &inverse); err != nil || inverse != key {
					t.Fatal("reconstructed bridge lost its inverse", inverse, err)
				}
				if severed, err := SeverVethIfOwned(101, ip, fresh.Attrs().Index, fresh.Attrs().Alias, ""); err != nil || !severed {
					t.Fatal("equal-address bridge revocation failed", severed, err)
				}
				if err := maps["bridges"].Lookup(key, &bridge); !isNotExist(err) {
					t.Fatal("equal-address bridge survived revocation", err)
				}
			})
		}
	})
	t.Run("oversized legacy grant withdraws forwarding flags and prefixes", func(t *testing.T) {
		ip := net.ParseIP("10.70.0.68")
		endpoint := create("cphgrantbudget", "budget-sandbox", ip.String())
		raw := uint32(101) | PortForwardFlag | PortForwardScopedFlag
		if err := ConfigureEndpoint(endpoint, raw, []net.IP{ip}, mac, "budget-sandbox", "eth0", PortVethIdentity{UID: "budget-port"}, []string{"192.0.2.0/24"}); err != nil {
			t.Fatal(err)
		}
		fresh, err := netlink.LinkByIndex(endpoint.Attrs().Index)
		if err != nil {
			t.Fatal(err)
		}
		binding := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer"}, Spec: sdnv1alpha1.VPCBindingSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: "owner", Name: "net"}, AllowForwarding: true, ForwardingCIDRs: make([]string, sdnv1alpha1.MaxForwardingPrefixes+1),
		}}
		attached, allow, cidrs := sdnv1alpha1.BindingGrants([]*sdnv1alpha1.VPCBinding{binding}, "consumer", "owner", "net")
		if !attached || allow || cidrs != nil {
			t.Fatal("oversized snapshot did not disable forwarding")
		}
		if err := SyncEndpointForwarding([]ForwardingEndpoint{{Net: 101, Ifindex: endpoint.Attrs().Index, Alias: fresh.Attrs().Alias, Allow: allow, CIDRs: cidrs}}); err != nil {
			t.Fatal(err)
		}
		if state, _, err := GetPortState(endpoint.Attrs().Index); err != nil || state != 101 {
			t.Fatal("oversized union retained forwarding flags", state, err)
		}
		key, _ := fwdCIDRKey(uint32(endpoint.Attrs().Index), "192.0.2.0/24")
		var value uint8
		if err := maps["fwd_cidrs"].Lookup(key, &value); !isNotExist(err) {
			t.Fatal("oversized union retained previous allowed prefix", value, err)
		}
	})
	t.Run("batch forwarding diffs preserve unrelated scopes and unchanged links", func(t *testing.T) {
		ip := net.ParseIP("10.70.0.67")
		link := create("cphbatch67", "batch-sandbox", ip.String())
		raw := uint32(101) | PortForwardFlag | PortForwardScopedFlag
		if err := ConfigureEndpoint(link, raw, []net.IP{ip}, mac, "batch-sandbox", "eth0", PortVethIdentity{UID: "batch-port"}, []string{"192.0.2.0/24"}); err != nil {
			t.Fatal(err)
		}
		foreign, _ := fwdCIDRKey(9999, "203.0.113.0/24")
		if err := maps["fwd_cidrs"].Put(foreign, uint8(1)); err != nil {
			t.Fatal(err)
		}
		fresh, err := netlink.LinkByIndex(link.Attrs().Index)
		if err != nil {
			t.Fatal(err)
		}
		entries := []ForwardingEndpoint{{Net: 101, Ifindex: link.Attrs().Index, Alias: fresh.Attrs().Alias, Allow: true, CIDRs: []string{"192.0.2.0/24"}}}
		updates := make(chan netlink.LinkUpdate, 16)
		stop := make(chan struct{})
		if err := netlink.LinkSubscribe(updates, stop); err != nil {
			t.Fatal(err)
		}
		defer close(stop)
		if err := SyncEndpointForwarding(entries); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-updates:
			t.Fatal("unchanged grant generated link event", event)
		case <-time.After(30 * time.Millisecond):
		}
		entries[0].Allow = false
		if err := SyncEndpointForwarding(entries); err != nil {
			t.Fatal(err)
		}
		if state, _, err := GetPortState(link.Attrs().Index); err != nil || state != 101 {
			t.Fatal("batch failed to revoke forwarding", state, err)
		}
		var value uint8
		if err := maps["fwd_cidrs"].Lookup(foreign, &value); err != nil || value != 1 {
			t.Fatal("batch removed unrelated scope", value, err)
		}
	})
	t.Run("retired Port UID drains only predecessor veth", func(t *testing.T) {
		ip := net.ParseIP("10.70.0.65")
		retired := create("cphretired65", "retired-sandbox", ip.String())
		live := create("cphlive65", "live-sandbox", ip.String())
		for _, s := range []struct {
			link             netlink.Link
			cid, uid, fabric string
		}{{retired, "retired-sandbox", "retired-port", "10.244.0.65"}, {live, "live-sandbox", "live-port", "10.244.0.66"}} {
			if err := ConfigureEndpoint(s.link, 101, []net.IP{ip}, mac, s.cid, "eth0", PortVethIdentity{UID: s.uid}, nil); err != nil {
				t.Fatal(err)
			}
			if err := AddBridge(s.fabric, ip.String(), s.link.Attrs().Name, 101, mac); err != nil {
				t.Fatal(err)
			}
		}
		fresh, err := netlink.LinkByIndex(retired.Attrs().Index)
		if err != nil {
			t.Fatal(err)
		}
		if cut, err := SeverVethIfOwned(101, ip, fresh.Attrs().Index, fresh.Attrs().Alias, ""); err != nil || !cut {
			t.Fatal(cut, err)
		}
		if idx, _, found, err := GetLocal(101, ip); err != nil || !found || idx != live.Attrs().Index {
			t.Fatal("old UID sever removed replacement local", idx, found, err)
		}
		fkey, _ := localKey(101, ip)
		var fabric overlayAddr128
		want, _ := addr128Str("10.244.0.66")
		if err := maps["fabric_of"].Lookup(fkey, &fabric); err != nil || fabric != want {
			t.Fatal("old UID sever removed replacement bridge inverse", fabric, err)
		}
	})
	t.Run("forwarding publication failure never arms partial grant", func(t *testing.T) {
		ip := net.ParseIP("10.70.0.61")
		link := create("cphgrant61", "grant-sandbox", ip.String())
		id := PortVethIdentity{UID: "grant-port"}
		raw := uint32(101) | PortForwardFlag | PortForwardScopedFlag
		if err := ConfigureEndpoint(link, raw, []net.IP{ip}, mac, "grant-sandbox", "eth0", id, []string{"192.0.2.0/24"}); err != nil {
			t.Fatal(err)
		}
		if err := ConfigureEndpoint(link, raw, []net.IP{ip}, mac, "grant-sandbox", "eth0", id, []string{"198.51.100.0/24", "invalid"}); err == nil {
			t.Fatal("invalid grant accepted")
		}
		if state, found, err := GetPortState(link.Attrs().Index); err != nil || !found || state != QuarantineNet {
			t.Fatal("partial grant still armed", state, err)
		}
		key, _ := fwdCIDRKey(uint32(link.Attrs().Index), "192.0.2.0/24")
		var value uint8
		if err := maps["fwd_cidrs"].Lookup(key, &value); !isNotExist(err) {
			t.Fatal("obsolete forwarding CIDR retained", err)
		}
		other := PortVethIdentity{UID: "other-port"}
		if err := PrepareEndpointHooks(link, "grant-sandbox", "eth0", other); err == nil {
			t.Fatal("stale ADD fenced another Port generation")
		}
		if state, _, err := GetPortState(link.Attrs().Index); err != nil || state != QuarantineNet {
			t.Fatal("foreign initialization changed live state", state, err)
		}
	})
	t.Run("staged target stays staged after rebuild and is revoked without locals", func(t *testing.T) {
		ip := net.ParseIP("fd00:70::58")
		staged := create("cphstaged58", "target-sandbox", ip.String())
		id := PortVethIdentity{UID: "11111111-1111-1111-1111-111111111111", Staged: true}
		if err := SetEndpointVethAlias(staged, 101, []net.IP{ip}, mac, "target-sandbox", "eth0", id); err != nil {
			t.Fatal(err)
		}
		if err := rebuildVeth(staged, staged.Attrs().Index, 101, []net.IP{ip}, mac); err != nil {
			t.Fatal(err)
		}
		if _, _, found, err := GetLocal(101, ip); err != nil || found {
			t.Fatal("staged endpoint activated by rebuild", found, err)
		}
		if ok, err := EnsureLocalFromVeth(101, ip, "target-sandbox", "eth0", id.UID); err != nil || !ok {
			t.Fatal("cutover failed", ok, err)
		}
		if err := SetLocalStaging(101, ip, id.UID, true); err != nil {
			t.Fatal(err)
		}
		fresh, err := netlink.LinkByIndex(staged.Attrs().Index)
		if err != nil {
			t.Fatal(err)
		}
		if !VethPortIdentity(fresh.Attrs().Alias).Staged {
			t.Fatal("move-away did not persist staging")
		}
		if err := rebuildVeth(fresh, fresh.Attrs().Index, 101, []net.IP{ip}, mac); err != nil {
			t.Fatal(err)
		}
		if _, _, found, err := GetLocal(101, ip); err != nil || found {
			t.Fatal("move-away revived after restart", found, err)
		}
		if err := SyncVethForwarding(101, fresh.Attrs().Index, fresh.Attrs().Alias, true, []string{"2001:db8::/32"}); err != nil {
			t.Fatal(err)
		}
		fresh, err = netlink.LinkByIndex(staged.Attrs().Index)
		if err != nil {
			t.Fatal(err)
		}
		if got := VethPortIdentity(fresh.Attrs().Alias); got != id {
			t.Fatal("grant lost endpoint identity", got)
		}
		const fabric = "10.244.0.58"
		if err := AddBridge(fabric, ip.String(), staged.Attrs().Name, 101, mac); err != nil {
			t.Fatal(err)
		}
		if severed, err := SeverVethIfOwned(101, ip, fresh.Attrs().Index, fresh.Attrs().Alias, fabric); err != nil || !severed {
			t.Fatal("staged revocation failed", severed, err)
		}
		if raw, found, err := GetPortState(fresh.Attrs().Index); err != nil || !found || raw != QuarantineNet {
			t.Fatal("staged endpoint not quarantined", raw, found, err)
		}
		key, _ := addr128Str(fabric)
		var ep overlayBridgeEp
		if err := maps["bridges"].Lookup(key, &ep); !isNotExist(err) {
			t.Fatal("staged bridge survived revocation", err)
		}
		if err := SetEndpointVethAlias(staged, 101, []net.IP{ip}, mac, "target-sandbox", "eth0", id); err == nil {
			t.Fatal("ADD retry reactivated revoked sandbox")
		}
		if err := AddBridge(fabric, ip.String(), staged.Attrs().Name, 101, mac); err == nil {
			t.Fatal("stale ADD recreated revoked bridge")
		}
		replacement := create("cphreplace58", "new-sandbox", ip.String())
		oldAlias := replacement.Attrs().Alias
		if err := SetEndpointVethAlias(replacement, 101, []net.IP{ip}, mac, "new-sandbox", "eth0", PortVethIdentity{UID: "replacement-port"}); err != nil {
			t.Fatal(err)
		}
		if severed, err := SeverVethIfOwned(101, ip, replacement.Attrs().Index, oldAlias, ""); err != nil || severed {
			t.Fatal("stale snapshot revoked replacement", severed, err)
		}
	})
	t.Run("grant sync cannot turn platform gateway into tenant router", func(t *testing.T) {
		gw := create("cphsysgw", "gateway", "10.70.0.1")
		ip := net.ParseIP("10.70.0.1")
		if err := SetVethAlias(gw, 101|PortGatewayFlag, []net.IP{ip}, mac); err != nil {
			t.Fatal(err)
		}
		if err := SetPortNet(gw.Attrs().Index, 101|PortGatewayFlag); err != nil {
			t.Fatal(err)
		}
		if err := SetLocal(101, ip, gw.Attrs().Index, mac); err != nil {
			t.Fatal(err)
		}
		if err := SyncLocalForwarding(101, ip, true, nil); err != nil {
			t.Fatal(err)
		}
		var raw uint32
		if err := maps["ports"].Lookup(uint32(gw.Attrs().Index), &raw); err != nil {
			t.Fatal(err)
		}
		if raw != 101|PortGatewayFlag {
			t.Fatalf("gateway flags replaced by tenant grant: %#x", raw)
		}
	})
	t.Run("default rebuild does not revive stale address owner", func(t *testing.T) {
		shared := net.ParseIP("10.244.0.42")
		stale := create("cphflatold", "old-flat", shared.String())
		live := create("cphflatnew", "live-flat", shared.String())
		for _, link := range []netlink.Link{stale, live} {
			if err := SetVethAlias(link, 0, []net.IP{shared}, mac); err != nil {
				t.Fatal(err)
			}
		}
		if err := EnsureFabricHostRoute(stale.Attrs().Index, shared); err != nil {
			t.Fatal(err)
		}
		if err := EnsureFabricHostRoute(live.Attrs().Index, shared); err != nil {
			t.Fatal(err)
		}
		routes, err := netlink.RouteGet(shared)
		if err != nil || len(routes) != 1 || routes[0].LinkIndex != live.Attrs().Index {
			t.Fatal("authorized ADD did not replace stale fabric route", routes, err)
		}
		for _, link := range []netlink.Link{live, stale} {
			if err := rebuildVeth(link, link.Attrs().Index, 0, []net.IP{shared}, mac); err != nil {
				t.Fatal(err)
			}
		}
		index, _, found, err := GetLocal(0, shared)
		if err != nil || !found || index != live.Attrs().Index {
			t.Fatalf("rebuild resurrected stale fabric owner: index=%d live=%d found=%v err=%v", index, live.Attrs().Index, found, err)
		}
		if err := SetLocal(0, shared, stale.Attrs().Index, mac); err != nil {
			t.Fatal(err)
		}
		if _, err := pruneStaleLocalState(); err != nil {
			t.Fatal(err)
		}
		if _, _, found, err := GetLocal(0, shared); err != nil || found {
			t.Fatal("prune kept stale default-network address owner", found, err)
		}
		v6 := net.ParseIP("fd00:244::42")
		if err := EnsureFabricHostRoute(stale.Attrs().Index, v6); err != nil {
			t.Fatal(err)
		}
		if err := EnsureFabricHostRoute(live.Attrs().Index, v6); err != nil {
			t.Fatal(err)
		}
		for _, link := range []netlink.Link{live, stale} {
			if err := rebuildVeth(link, link.Attrs().Index, 0, []net.IP{v6}, mac); err != nil {
				t.Fatal(err)
			}
		}
		index, _, found, err = GetLocal(0, v6)
		if err != nil || !found || index != live.Attrs().Index {
			t.Fatal("IPv6 rebuild chose stale sandbox", index, found, err)
		}
	})
	t.Run("locals cutover versus stale DEL", func(t *testing.T) {
		shared := net.ParseIP("10.70.0.42")
		if err := SetLocal(101, shared, current.Attrs().Index, mac); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 2)
		var writers sync.WaitGroup
		writers.Go(func() {
			for range 20 {
				if err := DelLocalIfOwned(101, shared, map[int]bool{old.Attrs().Index: true}); err != nil {
					errs <- err
					return
				}
			}
		})
		writers.Go(func() {
			for range 20 {
				if err := SetLocal(101, shared, current.Attrs().Index, mac); err != nil {
					errs <- err
					return
				}
			}
		})
		writers.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		index, _, found, err := GetLocal(101, shared)
		if err != nil || !found || index != current.Attrs().Index {
			t.Fatal("stale DEL removed current local endpoint", index, found, err)
		}
		if err := DelLocalIfOwned(101, shared, map[int]bool{current.Attrs().Index: true}); err != nil {
			t.Fatal(err)
		}
		if _, _, found, err := GetLocal(101, shared); err != nil || found {
			t.Fatal("current DEL did not remove its endpoint", found, err)
		}
	})
	const address = "10.244.0.2"
	if err := AddBridge(address, "10.70.0.2", old.Attrs().Name, 101, mac); err != nil {
		t.Fatal(err)
	}
	if err := AddBridge(address, "10.70.0.3", current.Attrs().Name, 101, mac); err != nil {
		t.Fatal(err)
	}
	errors := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			if err := DelSandboxBridge(address, old.Attrs().Name, "old", "eth0"); err != nil {
				errors <- err
				return
			}
		}
	})
	wg.Go(func() {
		for range 20 {
			if err := AddBridge(address, "10.70.0.3", current.Attrs().Name, 101, mac); err != nil {
				errors <- err
				return
			}
		}
	})
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(old); err != nil {
		t.Fatal(err)
	}
	if err := DelSandboxBridge(address, old.Attrs().Name, "old", "eth0"); err != nil {
		t.Fatal(err)
	}
	key, _ := addr128Str(address)
	var endpoint overlayBridgeEp
	if err := maps["bridges"].Lookup(key, &endpoint); err != nil {
		t.Fatal("new bridge removed", err)
	}
	vpc, _ := addr128Str("10.70.0.3")
	if endpoint.Net != 101 || endpoint.VpcIp != vpc {
		t.Fatal("bridge points to old sandbox")
	}
	routes, err := netlink.RouteGet(net.ParseIP(address))
	if err != nil || len(routes) == 0 || routes[0].LinkIndex != current.Attrs().Index {
		t.Fatal("new route removed", routes, err)
	}
	var owner overlayBridgeOwner
	if err := maps["bridge_owners"].Lookup(key, &owner); err != nil || owner.Ifindex != uint32(current.Attrs().Index) || owner.Sandbox != sandboxWitness("current", "eth0") {
		t.Fatal("new owner lost", owner, err)
	}
	if err := DelSandboxBridge(address, current.Attrs().Name, "current", "eth0"); err != nil {
		t.Fatal(err)
	}
	if err := maps["bridges"].Lookup(key, &endpoint); !isNotExist(err) {
		t.Fatal("owned bridge not removed", err)
	}
}
func TestKernelCutoverSelectsSandboxVeth(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("isolated privileged Linux container required")
	}
	address := net.ParseIP("10.70.0.9")
	mac, _ := net.ParseMAC("02:00:00:00:00:09")
	create := func(name, id string) netlink.Link {
		t.Helper()
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			t.Fatal(err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		if err := SetVethAlias(link, 109, []net.IP{address}, mac); err != nil {
			t.Fatal(err)
		}
		if err := SetVethSandbox(link, id, "eth0"); err != nil {
			t.Fatal(err)
		}
		return link
	}
	old, current := create("cphstageold", "old-sandbox"), create("cphstagenew", "new-sandbox")
	for _, expected := range []struct {
		id   string
		link netlink.Link
	}{{"old-sandbox", old}, {"new-sandbox", current}} {
		index, _, found, err := vethForAddr(109, address, expected.id, "eth0")
		if err != nil || !found || index != expected.link.Attrs().Index {
			t.Fatal("wrong sandbox selected", index, found, err)
		}
	}
	if _, _, found, err := vethForAddr(109, address, "", ""); err == nil || found {
		t.Fatal("ambiguous legacy endpoint accepted")
	}
	if _, _, found, err := vethForAddr(109, address, "new-sandbox", "net1"); err != nil || found {
		t.Fatal("different CNI interface accepted", err)
	}
}
