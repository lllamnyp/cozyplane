package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnlisters "github.com/lllamnyp/cozyplane/pkg/generated/sdn/listers/sdn/v1alpha1"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestKernelGuestBindingRejectsLargeLabelsAndRecovers(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux network namespace")
	}
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphlab169"}, PeerName: "lab169peer"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, "192.0.2.10"), UID: "port-owner", Labels: map[string]string{
		sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner",
	}}, Spec: sdnv1.PortSpec{Node: "source", PodNamespace: "tenant", IP: "192.0.2.10", MAC: "02:00:00:00:00:01"}}
	mac, err := net.ParseMAC(port.Spec.MAC)
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.SetEndpointVethAlias(link, 100, []net.IP{net.ParseIP(port.Spec.IP)}, mac, "target-sandbox", "eth0", datapath.PortVethIdentity{UID: string(port.UID), Staged: true}); err != nil {
		t.Fatal(err)
	}
	veths, err := datapath.ListLocalPortVeths()
	if err != nil {
		t.Fatal(err)
	}
	var v datapath.LocalPortVeth
	for _, candidate := range veths {
		if candidate.Ifindex == link.Attrs().Index {
			v = candidate
		}
	}
	if v.Ifindex == 0 {
		t.Fatal("live migration endpoint missing")
	}
	claim := &localv1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: localv1.FabricIPName("10.244.1.9")}, Spec: localv1.FabricIPSpec{
		Node: "target", PodNamespace: "tenant", PodName: "target-pod", PodUID: "pod-owner", Address: "10.244.1.9", ContainerID: v.ContainerID, IfName: v.IfName,
	}}
	factory := localinformers.NewSharedInformerFactory(localfake.NewSimpleClientset(), 0)
	if err := factory.Local().V1alpha1().FabricIPs().Informer().AddIndexers(fabricClaimIndexers()); err != nil {
		t.Fatal(err)
	}
	if err := factory.Local().V1alpha1().FabricIPs().Informer().GetStore().Add(claim); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "target-pod", Namespace: "tenant", UID: "pod-owner", Labels: map[string]string{"role": "guest"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachineInstance", Name: "guest", UID: "instance-owner", Controller: new(true), BlockOwnerDeletion: new(true)}},
	}, Spec: corev1.PodSpec{NodeName: "target"}, Status: corev1.PodStatus{PodIP: claim.Spec.Address}}
	for _, count := range []int{15000, 2048, 0} {
		current := pod.DeepCopy()
		for i := range count {
			current.Labels[fmt.Sprintf("label%05d", i)] = strings.Repeat("x", 63)
		}
		binding, err := guestBindingForVeth(t.Context(), corefake.NewSimpleClientset(current), factory, port, v, "target")
		if count != 0 {
			if err == nil || binding != (guestSandboxBinding{}) {
				t.Fatal("oversized labels returned a usable cutover binding", count, err)
			}
			continue
		}
		if err != nil || binding.uid != string(pod.UID) || binding.containerID != v.ContainerID {
			t.Fatal("ordinary complete binding failed to recover", binding, err)
		}
		var decoded map[string]string
		if err := json.Unmarshal([]byte(binding.podLabels), &decoded); err != nil || !reflect.DeepEqual(decoded, pod.Labels) {
			t.Fatal("selector identity changed", decoded, err)
		}
	}
	if port.Spec.Node != "source" || port.Spec.IP != "192.0.2.10" || port.Spec.MAC != "02:00:00:00:00:01" {
		t.Fatal("binding lookup changed pinned identity")
	}
	// Secondary NIC ownership joins the sandbox's primary FabricIP claim, whose
	// ifname is eth0, while preserving this Port's own net1 interface identity.
	secondary := port.DeepCopy()
	secondary.UID = "secondary-port"
	secondary.Spec.IP = "192.0.2.11"
	secondary.Name = sdn.PortName(100, secondary.Spec.IP)
	secondary.Spec.MAC = "02:00:00:00:00:02"
	secondary.Annotations = map[string]string{sdnv1.AnnotationCNIIfName: "net1"}
	secondLink := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphlab173n1"}, PeerName: "lab173n1peer"}
	if err := netlink.LinkAdd(secondLink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(secondLink) })
	secondMAC, err := net.ParseMAC(secondary.Spec.MAC)
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.SetEndpointVethAlias(secondLink, 100, []net.IP{net.ParseIP(secondary.Spec.IP)}, secondMAC, v.ContainerID, "net1", datapath.PortVethIdentity{UID: string(secondary.UID), Staged: true}); err != nil {
		t.Fatal(err)
	}
	veths, err = datapath.ListLocalPortVeths()
	if err != nil {
		t.Fatal(err)
	}
	var secondVeth datapath.LocalPortVeth
	for _, candidate := range veths {
		if candidate.Ifindex == secondLink.Attrs().Index {
			secondVeth = candidate
		}
	}
	binding, err := guestBindingForVeth(t.Context(), corefake.NewSimpleClientset(pod), factory, secondary, secondVeth, "target")
	if err != nil || binding.uid != string(pod.UID) || binding.ifName != "net1" || binding.containerID != v.ContainerID {
		t.Fatal("secondary NIC could not join its primary sandbox claim", binding, err)
	}
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, p := range []*sdnv1.Port{port, secondary} {
		if err := store.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := guestPortCandidates(sdnlisters.NewPortLister(store), veths)
	if err != nil || len(candidates) != 2 {
		t.Fatal("local veth candidate lookup lost guest interfaces", candidates, err)
	}
	for _, p := range candidates {
		owned, err := ownedPortVeths(t.Context(), corefake.NewSimpleClientset(pod), factory, p, "target", veths)
		if err != nil || len(owned) != 1 || owned[0].PortUID != string(p.UID) {
			t.Fatal("candidate did not pass actual veth ownership", p.Name, owned, err)
		}
	}
}
