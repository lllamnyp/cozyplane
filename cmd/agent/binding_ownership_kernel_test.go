package main

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

// Called inside the isolated bpffs/veth fixture used for revocation tests.
func testKernelMixedForwardingBinding(t *testing.T, mgr *datapath.Manager, prog *ebpf.Program, localFactory localinformers.SharedInformerFactory) {
	port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v102.192-0-2-20", UID: "forward-owner", Labels: map[string]string{
		sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner",
	}}, Spec: sdnv1.PortSpec{Node: "local", PodNamespace: "tenant", PodName: "workload", IP: "192.0.2.20", MAC: "02:00:00:00:00:03", VPCRef: sdnv1.VPCRef{Namespace: "owner", Name: "net"}}}
	mac, err := net.ParseMAC(port.Spec.MAC)
	if err != nil {
		t.Fatal(err)
	}
	var links []netlink.Link
	for i, owner := range []string{string(port.UID), ""} {
		name, peer, cid, raw := "cphfwd176k", "fwd176kpeer", "known-sandbox", uint32(102)|datapath.PortForwardFlag
		if i == 1 {
			name, peer, cid, raw = "cphfwd176l", "fwd176lpeer", "sandbox", 102
		}
		link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(link)
		if err := datapath.ConfigureEndpoint(link, raw, []net.IP{net.ParseIP(port.Spec.IP)}, mac, cid, "eth0", datapath.PortVethIdentity{UID: owner}, nil); err != nil {
			t.Fatal(err)
		}
		links = append(links, link)
	}
	if err := mgr.SetNetwork(102, "192.0.2.0/24", 102); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("fwd176kpeer")
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.SetLocal(102, net.ParseIP("192.0.2.21"), peer.Attrs().Index, mac); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 54)
	copy(packet[6:12], mac)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[22], packet[23] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[16:18], 40)
	copy(packet[26:30], net.ParseIP("198.51.100.10").To4())
	copy(packet[30:34], net.ParseIP("192.0.2.21").To4())
	binary.BigEndian.PutUint16(packet[34:36], 40000)
	binary.BigEndian.PutUint16(packet[36:38], 443)
	packet[46], packet[47] = 0x50, 2
	ctx := make([]byte, 192)
	binary.LittleEndian.PutUint32(ctx[40:44], uint32(links[0].Attrs().Index))
	verdict := func() uint32 {
		t.Helper()
		got, err := prog.Run(&ebpf.RunOptions{Data: packet, Context: ctx})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := verdict(); got != 7 {
		t.Fatal("initial forwarding grant did not admit foreign source", got)
	}
	binding := &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "tenant"}, Spec: sdnv1.VPCBindingSpec{VPCRef: port.Spec.VPCRef, AllowForwarding: false}}
	client := sdnfake.NewSimpleClientset(port, binding)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	ports, bindings := factory.Sdn().V1alpha1().Ports().Informer(), factory.Sdn().V1alpha1().VPCBindings().Informer()
	workerCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer func() { cancel(); factory.Shutdown() }()
	factory.Start(workerCtx.Done())
	if !cache.WaitForCacheSync(workerCtx.Done(), ports.HasSynced, bindings.HasSynced) {
		t.Fatal("binding cache not ready")
	}
	core := corefake.NewSimpleClientset()
	core.PrependReactor("get", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("test legacy ownership API outage")
	})
	reconcileBindingGrants(t.Context(), factory, localFactory, core, "local", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := verdict(); got != 2 {
		t.Fatal("withdrawn forwarding grant survived legacy proof failure", got)
	}
	raw, found, err := datapath.GetPortState(links[0].Attrs().Index)
	if err != nil || !found || raw != 102 {
		t.Fatal("verified endpoint retained stale forwarding flags", raw, found, err)
	}
	current, err := netlink.LinkByIndex(links[1].Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if id := datapath.VethPortIdentity(current.Attrs().Alias); id.UID != "" {
		t.Fatal("uncertain legacy endpoint was adopted", id)
	}
	// A new scoped consent must recover only its declared foreign prefix.
	binding.Spec.AllowForwarding = true
	binding.Spec.ForwardingCIDRs = []string{"198.51.100.0/24"}
	if _, err := client.SdnV1alpha1().VPCBindings("tenant").Update(t.Context(), binding, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		obj, found, err := bindings.GetStore().GetByKey("tenant/grant")
		if err != nil {
			t.Fatal(err)
		}
		if found && obj.(*sdnv1.VPCBinding).Spec.AllowForwarding {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("current binding update not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	reconcileBindingGrants(t.Context(), factory, localFactory, core, "local", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := verdict(); got != 7 {
		t.Fatal("new scoped consent did not recover", got)
	}
	copy(packet[26:30], net.ParseIP("198.51.101.10").To4())
	if got := verdict(); got != 2 {
		t.Fatal("scoped recovery admitted undeclared source", got)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		reconcileBindingGrants(t.Context(), factory, localFactory, core, "local", slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(fds) {
		t.Fatal("binding retries leaked descriptors", len(fds), len(after), err)
	}
	current, err = netlink.LinkByIndex(links[1].Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if id := datapath.VethPortIdentity(current.Attrs().Alias); id.UID != "" {
		t.Fatal("retries adopted uncertain legacy owner", id)
	}
}
