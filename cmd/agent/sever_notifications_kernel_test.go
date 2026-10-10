package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// Uses the real Port handler, generated SDK informer and isolated kernel maps.
func testKernelSeverAcknowledgementBurst(t *testing.T, mgr *datapath.Manager, prog *ebpf.Program, localFactory localinformers.SharedInformerFactory) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprintf("replacement-%v", replacement), func(t *testing.T) { testKernelSeverBurstRecovery(t, mgr, prog, localFactory, replacement) })
	}
}

func testKernelSeverBurstRecovery(t *testing.T, mgr *datapath.Manager, prog *ebpf.Program, localFactory localinformers.SharedInformerFactory, replacement bool) {
	port := severTestPort()
	client := sdnfake.NewSimpleClientset(port)
	api, recovery := recoverableSeverAPI(t, client, port)
	mac, _ := net.ParseMAC("02:00:00:00:00:06")
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphqueue180"}, PeerName: "queue180peer"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	if err := datapath.ConfigureEndpoint(link, 100, []net.IP{net.ParseIP(port.Spec.IP)}, mac, "queue-sandbox", "eth0", datapath.PortVethIdentity{UID: string(port.UID)}, nil); err != nil {
		t.Fatal(err)
	}
	if got := revocationControlVerdict(t, prog, link.Attrs().Index, mac, net.ParseIP(port.Spec.IP)); got != 0 {
		t.Fatal("fixture endpoint initially blocked", got)
	}
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); factory.Shutdown() }()
	skipped := make(chan struct{}, 1)
	log := slog.New(testLogObserver{Handler: slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}), message: "skip obsolete sever acknowledgement", seen: skipped})
	if err := watchPorts(ctx, factory, localFactory, api, corefake.NewSimpleClientset(), mgr, "local", "192.0.2.200", log); err != nil {
		t.Fatal(err)
	}
	inf := factory.Sdn().V1alpha1().Ports().Informer()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		t.Fatal("Port cache did not sync")
	}
	select {
	case <-recovery.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real acknowledgement request did not start")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range 512 {
		update := port.DeepCopy()
		update.ResourceVersion = fmt.Sprint(i + 2)
		update.Annotations = map[string]string{"audit-load": strings.Repeat(fmt.Sprintf("%08d", i), 4096)}
		if _, err := client.SdnV1alpha1().Ports().Update(ctx, update, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		// The fake tracker panics when its 100-event transport buffer fills.
		// Wait for cache delivery (not callback/acknowledgement completion), so
		// all 512 events still pressure the real handler while the API stalls.
		if (i+1)%64 == 0 {
			deadline := time.Now().Add(2 * time.Second)
			for {
				obj, found, err := inf.GetStore().GetByKey(port.Name)
				if err != nil {
					t.Fatal(err)
				}
				if found && obj.(*sdnv1.Port).ResourceVersion == update.ResourceVersion {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("upstream cache failed to receive burst batch")
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	probe := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v104.192-0-2-44", UID: "remote-owner"}, Spec: sdnv1.PortSpec{Node: "remote", IP: "192.0.2.44", NodeIP: "192.0.2.201"}}
	if err := mgr.DelRemote(104, hostCIDR(probe.Spec.IP)); err != nil {
		t.Fatal(err)
	}
	defer mgr.DelRemote(104, hostCIDR(probe.Spec.IP))
	if _, err := client.SdnV1alpha1().Ports().Create(ctx, probe, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Fake.Actions itself retains request objects; exclude that fixture history.
	client.ClearActions()
	deadline := time.Now().Add(2 * time.Second)
	for {
		obj, found, err := inf.GetStore().GetByKey(port.Name)
		if err != nil {
			t.Fatal(err)
		}
		if found && obj.(*sdnv1.Port).ResourceVersion == "513" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream cache failed to receive burst")
		}
		time.Sleep(time.Millisecond)
	}
	remotes, err := ebpf.LoadPinnedMap(filepath.Join(datapath.PinRoot, "remotes"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remotes.Close()
	key := struct {
		Prefixlen, ScopeNet uint32
		Addr                [16]byte
	}{Prefixlen: 160, ScopeNet: 104}
	key.Addr[1], key.Addr[2], key.Addr[3] = 0x64, 0xff, 0x9b
	copy(key.Addr[12:], net.ParseIP(probe.Spec.IP).To4())
	var route uint32
	deadline = time.Now().Add(2 * time.Second)
	for {
		err = remotes.Lookup(key, &route)
		if err == nil && route == binary.BigEndian.Uint32(net.ParseIP(probe.Spec.NodeIP).To4()) {
			break
		}
		if time.Now().After(deadline) {
			t.Error("acknowledgement stalled unrelated remote route", route, err)
			break
		}
		time.Sleep(time.Millisecond)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Log("retained heap delta after 512 current-Port updates", delta)
	if delta > 4<<20 {
		t.Error("acknowledgement retained old notification payloads", delta)
	}
	if got := revocationControlVerdict(t, prog, link.Attrs().Index, mac, net.ParseIP(port.Spec.IP)); got != 2 {
		t.Error("proven endpoint waited for stalled acknowledgement before quarantine", got)
	}
	if ctx.Err() != nil || len(port.Finalizers) != 1 {
		t.Error("burst canceled parent or removed unconfirmed barrier")
	}
	// Reusing the address does not authorize cleanup of a different alias UID.
	newLink := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphq180new"}, PeerName: "q180newpeer"}
	if err := netlink.LinkAdd(newLink); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(newLink)
	newMAC, _ := net.ParseMAC("02:00:00:00:00:07")
	if err := datapath.ConfigureEndpoint(newLink, 100, []net.IP{net.ParseIP(port.Spec.IP)}, newMAC, "replacement-sandbox", "eth0", datapath.PortVethIdentity{UID: "replacement-owner"}, nil); err != nil {
		t.Fatal(err)
	}
	if replacement {
		current := port.DeepCopy()
		current.UID, current.ResourceVersion, current.DeletionTimestamp = "replacement-owner", "514", nil
		if _, err := client.SdnV1alpha1().Ports().Update(ctx, current, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	close(recovery.resume)
	if replacement {
		select {
		case <-skipped:
		case <-time.After(2 * time.Second):
			t.Fatal("old acknowledgement did not observe replacement ownership")
		}
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		current, err := client.SdnV1alpha1().Ports().Get(ctx, port.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !replacement && len(current.Finalizers) == 0 {
			break
		}
		if replacement {
			if current.UID != "replacement-owner" || len(current.Finalizers) != 1 || recovery.puts.Load() != 0 {
				t.Fatal("old acknowledgement changed replacement claim", current, recovery.puts.Load())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("current sever acknowledgement did not recover")
		}
		time.Sleep(time.Millisecond)
	}
	if !replacement && recovery.puts.Load() != 1 {
		t.Fatal("notification burst amplified acknowledgement writes", recovery.puts.Load())
	}
	if got := revocationControlVerdict(t, prog, newLink.Attrs().Index, newMAC, net.ParseIP(port.Spec.IP)); got != 0 {
		t.Fatal("old sever damaged replacement endpoint", got)
	}
}

type testLogObserver struct {
	slog.Handler
	message string
	seen    chan<- struct{}
	count   *atomic.Int32
}

func (h testLogObserver) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == h.message {
		if h.count != nil {
			h.count.Add(1)
		}
		select {
		case h.seen <- struct{}{}:
		default:
		}
	}
	return h.Handler.Handle(ctx, record)
}
