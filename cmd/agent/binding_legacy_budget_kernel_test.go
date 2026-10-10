package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Runs only within the fresh bpffs/network namespace of the revocation fixture.
func testKernelLegacyBindingWork(t *testing.T, mgr *datapath.Manager, prog *ebpf.Program, mode string) {
	stalled := mode == "budget"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	mac, _ := net.ParseMAC("02:00:00:00:00:09")
	ref := sdnv1.VPCRef{Namespace: "owner", Name: "net"}
	binding := &sdnv1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: "legacy-budget", Namespace: "tenant"}, Spec: sdnv1.VPCBindingSpec{VPCRef: ref, AllowForwarding: true}}
	objects := []runtime.Object{binding}
	var claims []runtime.Object
	var links []netlink.Link
	count := 1
	if stalled {
		count = 3
	}
	for i := 0; i <= count; i++ {
		ip, cid := fmt.Sprintf("192.0.2.%d", 60+i), fmt.Sprintf("budget-sandbox-%d", i)
		uid, node, raw := fmt.Sprintf("budget-owner-%d", i), "source", uint32(106)
		if i == 0 {
			node, raw = "local", 106|datapath.PortForwardFlag
		}
		port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("v106.192-0-2-%d", 60+i), UID: types.UID(uid), Labels: map[string]string{
			sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner",
		}}, Spec: sdnv1.PortSpec{Node: node, PodNamespace: "tenant", PodName: "launcher", IP: ip, VPCRef: ref}}
		objects = append(objects, port)
		identity := datapath.PortVethIdentity{}
		if i == 0 {
			identity.UID = uid
		} else {
			claims = append(claims, &localv1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: localv1.FabricIPName(fmt.Sprintf("10.244.2.%d", i))}, Spec: localv1.FabricIPSpec{
				Node: "local", PodNamespace: "tenant", PodName: "launcher", PodUID: "pod-owner", ContainerID: cid, IfName: "eth0",
			}})
		}
		link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("cphbudget%d", i)}, PeerName: fmt.Sprintf("budget%dpeer", i)}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(link)
		if err := datapath.ConfigureEndpoint(link, raw, []net.IP{net.ParseIP(ip)}, mac, cid, "eth0", identity, nil); err != nil {
			t.Fatal(err)
		}
		links = append(links, link)
	}
	if err := mgr.SetNetwork(106, "192.0.2.0/24", 106); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("budget0peer")
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.SetLocal(106, net.ParseIP("192.0.2.70"), peer.Attrs().Index, mac); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 54)
	copy(packet[6:12], mac)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[22], packet[23] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[16:18], 40)
	copy(packet[26:30], net.ParseIP("198.51.100.10").To4())
	copy(packet[30:34], net.ParseIP("192.0.2.70").To4())
	binary.BigEndian.PutUint16(packet[34:36], 40000)
	binary.BigEndian.PutUint16(packet[36:38], 443)
	packet[46], packet[47] = 0x50, 2
	verdict := func(link netlink.Link) uint32 {
		t.Helper()
		skb := make([]byte, 192)
		binary.LittleEndian.PutUint32(skb[40:44], uint32(link.Attrs().Index))
		got, err := prog.Run(&ebpf.RunOptions{Data: packet, Context: skb})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if verdict(links[0]) != 7 || verdict(links[1]) != 2 {
		t.Fatal("fixture must begin with a granted known endpoint and ungranted legacy endpoint")
	}
	client := sdnfake.NewSimpleClientset(objects...)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	localFactory := localinformers.NewSharedInformerFactory(localfake.NewSimpleClientset(claims...), 0)
	claimInformer := localFactory.Local().V1alpha1().FabricIPs().Informer()
	if err := claimInformer.AddIndexers(fabricClaimIndexers()); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); factory.Shutdown(); localFactory.Shutdown() }()
	var core kubernetes.Interface
	var entered <-chan struct{}
	resume := make(chan struct{})
	if stalled {
		core, entered, _ = blockedGuestCoreAPI(t)
	} else {
		requests := make(chan struct{}, 8)
		entered = requests
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/tenant/pods/launcher" {
				http.Error(w, "unexpected ownership request", http.StatusBadRequest)
				return
			}
			requests <- struct{}{}
			select {
			case <-r.Context().Done():
				return
			case <-resume:
			}
			flag := true
			pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "launcher", Namespace: "tenant", UID: "pod-owner", OwnerReferences: []metav1.OwnerReference{{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachineInstance", Name: "guest", UID: "instance-owner", Controller: &flag, BlockOwnerDeletion: &flag}}}, Spec: corev1.PodSpec{NodeName: "local"}}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(pod); err != nil {
				t.Error(err)
			}
		}))
		transport := &http.Transport{}
		t.Cleanup(func() { transport.CloseIdleConnections(); server.Close() })
		core, err = kubernetes.NewForConfigAndClient(&rest.Config{Host: server.URL, QPS: -1}, &http.Client{Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
	}
	ports, bindings := factory.Sdn().V1alpha1().Ports().Informer(), factory.Sdn().V1alpha1().VPCBindings().Informer()
	localFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), claimInformer.HasSynced) {
		t.Fatal("legacy claim cache did not sync")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if stalled {
		watchBindingGrants(ctx, factory, localFactory, core, "local", log)
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), ports.HasSynced, bindings.HasSynced) {
		t.Fatal("grant caches did not sync")
	}
	done := make(chan struct{})
	if !stalled {
		go func() { defer close(done); reconcileBindingGrants(ctx, factory, localFactory, core, "local", log) }()
		defer func() { cancel(); <-done }()
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("legacy proof did not enter the real HTTP client")
	}
	switch mode {
	case "attachment":
		if err := client.SdnV1alpha1().VPCBindings("tenant").Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	case "port-terminating", "port-replaced", "endpoint-replaced":
		port, err := client.SdnV1alpha1().Ports().Get(ctx, "v106.192-0-2-61", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if mode == "port-terminating" {
			port.DeletionTimestamp = new(metav1.Now())
			if _, err := client.SdnV1alpha1().Ports().Update(ctx, port, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := client.SdnV1alpha1().Ports().Delete(ctx, port.Name, metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			port.UID = "replacement-owner"
			if _, err := client.SdnV1alpha1().Ports().Create(ctx, port, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			if mode == "endpoint-replaced" {
				// CNI correctly refuses to overwrite a different live sandbox.
				// Recreate the veth as an actual replacement ADD would do.
				if err := netlink.LinkDel(links[1]); err != nil {
					t.Fatal(err)
				}
				replacement := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphbudget1"}, PeerName: "budget1peer"}
				if err := netlink.LinkAdd(replacement); err != nil {
					t.Fatal(err)
				}
				defer netlink.LinkDel(replacement)
				links[1] = replacement
				if err := datapath.ConfigureEndpoint(replacement, 106|datapath.PortForwardFlag, []net.IP{net.ParseIP(port.Spec.IP)}, mac, "replacement-sandbox", "eth0", datapath.PortVethIdentity{UID: string(port.UID)}, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
	default:
		binding = binding.DeepCopy()
		binding.Spec.AllowForwarding = mode == "scoped"
		if mode == "scoped" {
			binding.Spec.ForwardingCIDRs = []string{"198.51.100.0/24"}
		}
		if _, err := client.SdnV1alpha1().VPCBindings("tenant").Update(ctx, binding, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		obj, found, err := bindings.GetStore().GetByKey("tenant/legacy-budget")
		if err != nil {
			t.Fatal(err)
		}
		observed := found && !obj.(*sdnv1.VPCBinding).Spec.AllowForwarding
		switch mode {
		case "attachment":
			observed = !found
		case "scoped":
			observed = found && len(obj.(*sdnv1.VPCBinding).Spec.ForwardingCIDRs) == 1
		case "port-terminating", "port-replaced", "endpoint-replaced":
			port, err := factory.Sdn().V1alpha1().Ports().Lister().Get("v106.192-0-2-61")
			if err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
			observed = err == nil && (port.DeletionTimestamp != nil || port.UID == "replacement-owner")
		}
		if observed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("withdrawal did not reach the actual informer cache")
		}
		time.Sleep(time.Millisecond)
	}
	if stalled {
		deadline = time.Now().Add(6 * time.Second)
		for verdict(links[0]) != 2 {
			if time.Now().After(deadline) {
				t.Fatal("multiple legacy reads delayed known-owner forwarding withdrawal beyond one read budget", verdict(links[0]), ctx.Err())
			}
			time.Sleep(10 * time.Millisecond)
		}
	} else {
		close(resume)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("completed legacy proof did not finish reconciliation")
		}
		current, err := netlink.LinkByIndex(links[1].Attrs().Index)
		wantOwner := "budget-owner-1"
		if mode == "endpoint-replaced" {
			wantOwner = "replacement-owner"
		}
		if err != nil || datapath.VethPortIdentity(current.Attrs().Alias).UID != wantOwner {
			t.Fatal("protected ownership proof was not adopted", current, err)
		}
		wantRaw, wantVerdict := uint32(106), uint32(2)
		switch mode {
		case "attachment", "port-terminating", "port-replaced":
			wantRaw = datapath.QuarantineNet
		case "endpoint-replaced":
			wantRaw, wantVerdict = 106|datapath.PortForwardFlag, 7
		case "scoped":
			wantRaw, wantVerdict = 106|datapath.PortForwardFlag|datapath.PortForwardScopedFlag, 7
		}
		if raw, found, err := datapath.GetPortState(links[1].Attrs().Index); err != nil || !found || raw != wantRaw || verdict(links[1]) != wantVerdict {
			t.Fatal("completed proof republished obsolete forwarding consent", raw, found, err, verdict(links[1]))
		}
		if mode == "scoped" {
			copy(packet[26:30], net.ParseIP("198.51.101.10").To4())
			if verdict(links[1]) != 2 {
				t.Fatal("refreshed scoped consent admitted undeclared source")
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for range 50 {
				reconcileBindingGrants(ctx, factory, localFactory, core, "local", log)
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(before) != len(after) || verdict(links[1]) != 2 {
				t.Fatal("verified grant replay changed denial or leaked descriptors", len(before), len(after), err)
			}
			copy(packet[26:30], net.ParseIP("198.51.100.10").To4())
			if verdict(links[1]) != 7 {
				t.Fatal("verified scoped consent failed after replay")
			}
		}
	}
	if ctx.Err() != nil {
		t.Fatal("phase budget canceled the healthy agent context", ctx.Err())
	}
}
