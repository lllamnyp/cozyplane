package main

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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

func testKernelForwardingRetryAfterMapFailure(t *testing.T, mgr *datapath.Manager, prog *ebpf.Program, localFactory localinformers.SharedInformerFactory) {
	port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v105.192-0-2-50", UID: "retry-forward-owner"}, Spec: sdnv1.PortSpec{Node: "local", PodNamespace: "tenant", PodName: "workload", IP: "192.0.2.50", VPCRef: sdnv1.VPCRef{Namespace: "owner", Name: "net"}}}
	mac, _ := net.ParseMAC("02:00:00:00:00:08")
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphretry181"}, PeerName: "retry181peer"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	if err := datapath.ConfigureEndpoint(link, 105|datapath.PortForwardFlag, []net.IP{net.ParseIP(port.Spec.IP)}, mac, "retry-sandbox", "eth0", datapath.PortVethIdentity{UID: string(port.UID)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetNetwork(105, "192.0.2.0/24", 105); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("retry181peer")
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.SetLocal(105, net.ParseIP("192.0.2.51"), peer.Attrs().Index, mac); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 54)
	copy(packet[6:12], mac)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[22], packet[23] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[16:18], 40)
	copy(packet[26:30], net.ParseIP("198.51.100.10").To4())
	copy(packet[30:34], net.ParseIP("192.0.2.51").To4())
	binary.BigEndian.PutUint16(packet[34:36], 40000)
	binary.BigEndian.PutUint16(packet[36:38], 443)
	packet[46], packet[47] = 0x50, 2
	skb := make([]byte, 192)
	binary.LittleEndian.PutUint32(skb[40:44], uint32(link.Attrs().Index))
	verdict := func() uint32 {
		t.Helper()
		got, err := prog.Run(&ebpf.RunOptions{Data: packet, Context: skb})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := verdict(); got != 7 {
		t.Fatal("initial forwarding grant missing", got)
	}
	binding := &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: "retry-grant", Namespace: "tenant"}, Spec: sdnv1.VPCBindingSpec{VPCRef: port.Spec.VPCRef, AllowForwarding: false}}
	client := sdnfake.NewSimpleClientset(port, binding)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); factory.Shutdown() }()
	failed := make(chan struct{}, 8)
	var failures atomic.Int32
	log := slog.New(testLogObserver{Handler: slog.NewTextHandler(io.Discard, nil), message: "sync binding forwarding grants", seen: failed, count: &failures})
	// Only this test's fresh bpffs mount is touched. The loaded classifier
	// retains its map descriptor, so existing permissions remain observable.
	pin, held := filepath.Join(datapath.PinRoot, "ports"), filepath.Join(datapath.PinRoot, "audit-ports-held")
	if err := os.Rename(pin, held); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := os.Stat(held); err == nil {
			if err := os.Rename(held, pin); err != nil {
				t.Error(err)
			}
		}
	}()
	watchBindingGrants(ctx, factory, localFactory, corefake.NewSimpleClientset(), "local", log)
	ports, bindings := factory.Sdn().V1alpha1().Ports().Informer(), factory.Sdn().V1alpha1().VPCBindings().Informer()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), ports.HasSynced, bindings.HasSynced) {
		t.Fatal("grant caches did not sync")
	}
	select {
	case <-failed:
	case <-time.After(2 * time.Second):
		t.Fatal("real pinned-map failure was not observed")
	}
	last, stable, limit := failures.Load(), time.Now(), time.Now().Add(2*time.Second)
	for time.Since(stable) < 500*time.Millisecond {
		if count := failures.Load(); count != last {
			last, stable = count, time.Now()
		}
		if time.Now().After(limit) {
			t.Fatal("initial grant failure never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Rename(held, pin); err != nil {
		t.Fatal(err)
	}
	if got := verdict(); got != 7 {
		t.Fatal("fixture changed forwarding before recovery", got)
	}
	// No Binding, Port or Pod update; only the pin has recovered.
	deadline := time.Now().Add(16 * time.Second)
	for {
		if got := verdict(); got == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("withdrawn forwarding survived restored map without a new event", verdict(), failures.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, found, err := datapath.GetPortState(link.Attrs().Index)
	if err != nil || !found || raw != 105 || ctx.Err() != nil {
		t.Fatal("grant retry did not clear stale flags safely", raw, found, err, ctx.Err())
	}
}
