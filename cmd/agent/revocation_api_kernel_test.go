package main

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

func TestKernelRevocationDuringPodAPIError(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" || os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if entries, err := os.ReadDir(datapath.PinRoot); err == nil && len(entries) > 0 {
		t.Fatal("refusing to touch existing pinned state")
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/sys/fs/bpf", 0)
	mgr := datapath.New()
	defer mgr.Close()
	if err := mgr.Load(0); err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(datapath.PinRoot, "cozyplane_from_pod"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	claim := &localv1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: localv1.FabricIPName("10.244.1.9")}, Spec: localv1.FabricIPSpec{
		Node: "local", PodNamespace: "tenant", PodName: "workload", PodUID: "pod-owner", Address: "10.244.1.9", ContainerID: "sandbox", IfName: "eth0",
	}}
	factory := localinformers.NewSharedInformerFactory(localfake.NewSimpleClientset(claim), 0)
	if err := factory.Local().V1alpha1().FabricIPs().Informer().AddIndexers(fabricClaimIndexers()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer func() { cancel(); factory.Shutdown() }()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), factory.Local().V1alpha1().FabricIPs().Informer().HasSynced) {
		t.Fatal("ownership cache did not synchronize")
	}
	core := corefake.NewSimpleClientset()
	core.PrependReactor("get", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("test API outage")
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name, owner    string
		wantQuarantine bool
		wantError      bool
	}{
		{"owned", "port-owner", true, false},
		{"replacement", "replacement-owner", false, false},
		{"legacy-unproved", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beforeReads := len(core.Actions())
			link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphrev174"}, PeerName: "rev174peer"}
			if err := netlink.LinkAdd(link); err != nil {
				t.Fatal(err)
			}
			defer netlink.LinkDel(link)
			port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.192-0-2-10", UID: "port-owner"}, Spec: sdnv1.PortSpec{
				Node: "local", PodNamespace: "tenant", PodName: "workload", IP: "192.0.2.10", MAC: "02:00:00:00:00:01",
			}}
			if tc.wantError {
				port.Labels = map[string]string{sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner"}
			}
			mac, err := net.ParseMAC(port.Spec.MAC)
			if err != nil {
				t.Fatal(err)
			}
			if err := datapath.ConfigureEndpoint(link, 100, []net.IP{net.ParseIP(port.Spec.IP)}, mac, "sandbox", "eth0", datapath.PortVethIdentity{UID: tc.owner}, nil); err != nil {
				t.Fatal(err)
			}
			verdict := func() uint32 {
				return revocationControlVerdict(t, prog, link.Attrs().Index, mac, net.ParseIP(port.Spec.IP))
			}
			if got := verdict(); got != 0 {
				t.Fatal("active endpoint control packet rejected", got)
			}
			err = severLocalPort(t.Context(), core, factory, port, "local", log)
			want := uint32(0)
			if tc.wantQuarantine {
				want = 2
			}
			if got := verdict(); got != want {
				t.Fatalf("revocation during Pod API failure: verdict=%d want=%d err=%v", got, want, err)
			}
			if (err != nil) != tc.wantError {
				t.Fatal("unexpected ownership proof result", err)
			}
			if tc.wantError {
				port.DeletionTimestamp = new(metav1.Now())
				port.Finalizers = []string{sdnv1.FinalizerSever}
				sdn := sdnfake.NewSimpleClientset(port)
				releaseSeveredPort(t.Context(), sdn, core, factory, port, log)
				latest, err := sdn.SdnV1alpha1().Ports().Get(t.Context(), port.Name, metav1.GetOptions{})
				if err != nil || len(latest.Finalizers) != 1 || latest.Finalizers[0] != sdnv1.FinalizerSever {
					t.Fatal("legacy ownership failure released the address barrier", latest, err)
				}
				if got := verdict(); got != 0 {
					t.Fatal("failed legacy proof modified endpoint", got)
				}
			} else if tc.wantQuarantine {
				fds, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal(err)
				}
				for range 100 {
					if err := severLocalPort(t.Context(), core, factory, port, "local", log); err != nil {
						t.Fatal(err)
					}
				}
				after, err := os.ReadDir("/proc/self/fd")
				if err != nil || len(after) != len(fds) {
					t.Fatal("repeated quarantine leaked descriptors", len(fds), len(after), err)
				}
				if _, _, found, err := datapath.GetLocal(100, net.ParseIP(port.Spec.IP)); err != nil || found {
					t.Fatal("revoked local delivery survived", found, err)
				}
			}
			current, err := netlink.LinkByIndex(link.Attrs().Index)
			if err != nil {
				t.Fatal(err)
			}
			veths, err := datapath.ListLocalPortVeths()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, v := range veths {
				if v.Ifindex != link.Attrs().Index {
					continue
				}
				found = true
				if v.PortUID != tc.owner || (v.RawNet == datapath.QuarantineNet) != tc.wantQuarantine || v.Alias != current.Attrs().Alias {
					t.Fatal("durable ownership/quarantine witness changed unexpectedly", v)
				}
			}
			if !found {
				t.Fatal("live endpoint missing")
			}
			wantReads := 0
			if tc.wantError {
				wantReads = 2
			}
			if len(core.Actions())-beforeReads != wantReads {
				t.Fatal("Pod reads must occur only for failed legacy ownership checks", core.Actions())
			}
		})
	}
	t.Run("mixed-forwarding", func(t *testing.T) { testKernelMixedForwardingBinding(t, mgr, prog, factory) })
	t.Run("acknowledgement-burst", func(t *testing.T) { testKernelSeverAcknowledgementBurst(t, mgr, prog, factory) })
	t.Run("acknowledgement-retry", func(t *testing.T) { testKernelSeverAcknowledgementRetry(t, mgr, factory) })
	t.Run("forwarding-retry", func(t *testing.T) { testKernelForwardingRetryAfterMapFailure(t, mgr, prog, factory) })
	for _, mode := range []string{"budget", "consent", "attachment", "port-terminating", "port-replaced", "endpoint-replaced", "scoped"} {
		t.Run("legacy-binding-"+mode, func(t *testing.T) { testKernelLegacyBindingWork(t, mgr, prog, mode) })
	}
	t.Run("mixed-generations", func(t *testing.T) {
		for _, legacyFirst := range []bool{false, true} {
			t.Run(map[bool]string{false: "known-first", true: "legacy-first"}[legacyFirst], func(t *testing.T) {
				port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.192-0-2-11", UID: "mixed-owner", Labels: map[string]string{
					sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner",
				}, Annotations: map[string]string{sdnv1.AnnotationContainerID: "source-sandbox", sdnv1.AnnotationCNIIfName: "eth0"}}, Spec: sdnv1.PortSpec{Node: "local", PodNamespace: "tenant", PodName: "workload", IP: "192.0.2.11", MAC: "02:00:00:00:00:02"}}
				mac, err := net.ParseMAC(port.Spec.MAC)
				if err != nil {
					t.Fatal(err)
				}
				var links []netlink.Link
				for i, owner := range []string{string(port.UID), "", ""} {
					name, peer := "cphrev175k", "rev175kpeer"
					cid := "known-sandbox"
					if i == 1 {
						name, peer = "cphrev175l", "rev175lpeer"
						cid = "sandbox"
					} else if i == 2 {
						name, peer = "cphrev175p", "rev175ppeer"
						cid = "source-sandbox"
					}
					link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
					if err := netlink.LinkAdd(link); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = netlink.LinkDel(link) })
					if err := datapath.ConfigureEndpoint(link, 101, []net.IP{net.ParseIP(port.Spec.IP)}, mac, cid, "eth0", datapath.PortVethIdentity{UID: owner}, nil); err != nil {
						t.Fatal(err)
					}
					links = append(links, link)
				}
				all, err := datapath.ListLocalPortVeths()
				if err != nil {
					t.Fatal(err)
				}
				var inventory []datapath.LocalPortVeth
				for _, link := range links {
					for _, v := range all {
						if v.Ifindex == link.Attrs().Index {
							inventory = append(inventory, v)
						}
					}
				}
				if len(inventory) != 3 {
					t.Fatal("mixed live endpoints missing", inventory)
				}
				if legacyFirst {
					inventory[0], inventory[1] = inventory[1], inventory[0]
				}
				err = severLocalPort(t.Context(), core, factory, port, "local", log, inventory)
				if err == nil {
					t.Fatal("unproven legacy endpoint was acknowledged")
				}
				for i, link := range links {
					got := revocationControlVerdict(t, prog, link.Attrs().Index, mac, net.ParseIP(port.Spec.IP))
					want := uint32(0)
					if i != 1 {
						want = 2
					}
					if got != want {
						t.Fatalf("mixed revocation: endpoint=%d verdict=%d want=%d err=%v", i, got, want, err)
					}
				}
				index, _, found, err := datapath.GetLocal(101, net.ParseIP(port.Spec.IP))
				if err != nil || found {
					t.Fatal("proven legacy delivery route survived", index, found, err)
				}
				port.DeletionTimestamp = new(metav1.Now())
				port.Finalizers = []string{sdnv1.FinalizerSever}
				sdn := sdnfake.NewSimpleClientset(port)
				releaseSeveredPort(t.Context(), sdn, core, factory, port, log)
				latest, err := sdn.SdnV1alpha1().Ports().Get(t.Context(), port.Name, metav1.GetOptions{})
				if err != nil || len(latest.Finalizers) != 1 || latest.Finalizers[0] != sdnv1.FinalizerSever {
					t.Fatal("incomplete mixed cleanup released the address barrier", latest, err)
				}
				fds, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal(err)
				}
				for range 50 {
					if err := severLocalPort(t.Context(), core, factory, port, "local", log); err == nil {
						t.Fatal("repeat acknowledged an uncertain endpoint")
					}
				}
				after, err := os.ReadDir("/proc/self/fd")
				if err != nil || len(after) != len(fds) {
					t.Fatal("mixed retries leaked descriptors", len(fds), len(after), err)
				}
				if got := revocationControlVerdict(t, prog, links[0].Attrs().Index, mac, net.ParseIP(port.Spec.IP)); got != 2 {
					t.Fatal("retry reactivated proven owner", got)
				}
				if got := revocationControlVerdict(t, prog, links[1].Attrs().Index, mac, net.ParseIP(port.Spec.IP)); got != 0 {
					t.Fatal("retry quarantined uncertain owner", got)
				}
			})
		}
	})
}

func revocationControlVerdict(t *testing.T, prog *ebpf.Program, index int, mac net.HardwareAddr, ip net.IP) uint32 {
	t.Helper()
	packet := make([]byte, 60)
	copy(packet[:6], []byte{255, 255, 255, 255, 255, 255})
	copy(packet[6:12], mac)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)
	binary.BigEndian.PutUint16(packet[14:16], 1)
	binary.BigEndian.PutUint16(packet[16:18], 0x0800)
	packet[18], packet[19] = 6, 4
	binary.BigEndian.PutUint16(packet[20:22], 1)
	copy(packet[22:28], mac)
	copy(packet[28:32], ip.To4())
	copy(packet[38:42], net.ParseIP("192.0.2.1").To4())
	ctx := make([]byte, 192)
	binary.LittleEndian.PutUint32(ctx[40:44], uint32(index))
	got, err := prog.Run(&ebpf.RunOptions{Data: packet, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	return got
}
