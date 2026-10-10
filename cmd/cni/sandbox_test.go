package main

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
)

func TestSandboxPortRetryAndStaleDEL(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Namespace: "tenant"}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.70.0.0/24"}}, Status: sdnv1alpha1.VPCStatus{VNI: 102}}
	_, cidr, _ := net.ParseCIDR(vpc.Spec.CIDRs[0])
	r := resolvedAttachment{attachment: attachment{VPCNamespace: "tenant", VPCName: "vpc", IfName: "eth0"}, vpc: vpc, cidr: cidr, cniIfName: "eth0"}
	state := &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}
	allocate := func(id string) *sdnv1alpha1.Port {
		t.Helper()
		r.containerID = id
		_, _, port, _, err := attachPort(t.Context(), client, r, state, "tenant", "pod", "uid", "", "")
		if err != nil {
			t.Fatal(err)
		}
		return port
	}
	old, current := allocate("old"), allocate("current")
	retry := allocate("current")
	if retry.Name != current.Name || old.Name == current.Name {
		t.Fatal("Port was not reused by sandbox")
	}
	cleaned := map[string]bool{}
	if err := releaseSandboxPorts(t.Context(), client, labelPodUID+"=uid", "old", "eth0", func(p *sdnv1alpha1.Port) { cleaned[p.Name] = true }); err != nil {
		t.Fatal(err)
	}
	if !cleaned[old.Name] || cleaned[current.Name] {
		t.Fatal("stale DEL cleaned current endpoint")
	}
	if _, err := client.SdnV1alpha1().Ports().Get(t.Context(), current.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("current Port was deleted", err)
	}
}

func TestSandboxPortConcurrentRetryUsesCreateWinner(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	client.PrependReactor("create", "ports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		port := action.(k8stesting.CreateAction).GetObject().(*sdnv1alpha1.Port)
		if err := client.Tracker().Create(sdnv1alpha1.SchemeGroupVersion.WithResource("ports"), port, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(sdnv1alpha1.Resource("ports"), port.Name)
	})
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "net", Namespace: "tenant"}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.70.0.0/24"}}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}
	_, cidr, _ := net.ParseCIDR(vpc.Spec.CIDRs[0])
	r := resolvedAttachment{attachment: attachment{VPCNamespace: "tenant", IfName: "eth0"}, vpc: vpc, cidr: cidr, containerID: "sandbox", cniIfName: "eth0"}
	ip, _, port, reused, err := attachPort(t.Context(), client, r, &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}, "tenant", "pod", "uid", "", "")
	if err != nil || !reused || port == nil || ip.String() != "10.70.0.2" {
		t.Fatal("concurrent retry allocated another address", ip, port, reused, err)
	}
	list, err := client.SdnV1alpha1().Ports().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 {
		t.Fatal("duplicate claims", list, err)
	}
}

func TestKernelSandboxVethRetry(t *testing.T) {
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
	id := strings.Repeat("a", 64)
	name := hostVethNameFor(id)
	setup := func() error {
		return pod.Do(func(ns.NetNS) error { return setupSandboxVeth(id, "eth0", "eth0", name, 1400, host) })
	}
	if err := setup(); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if err := datapath.SetVethAlias(link, 0, []net.IP{net.ParseIP("10.244.0.2")}, mac); err != nil {
		t.Fatal(err)
	}
	if err := datapath.SetVethSandbox(link, id, "eth0"); err != nil {
		t.Fatal(err)
	}
	if err := setup(); err != nil {
		t.Fatal("completed ADD retry failed", err)
	}
	again, err := netlink.LinkByName(name)
	if err != nil || again.Attrs().Index != link.Attrs().Index {
		t.Fatal("retry replaced veth")
	}
	if err := datapath.SetVethSandbox(link, "foreign", "eth0"); err != nil {
		t.Fatal(err)
	}
	if err := setup(); err == nil {
		t.Fatal("retry adopted foreign sandbox")
	}
}
func TestStagedPersistentPortKeepsSourceSandbox(t *testing.T) {
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Namespace: "tenant"}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.70.0.0/24"}}, Status: sdnv1alpha1.VPCStatus{VNI: 102}}
	_, cidr, _ := net.ParseCIDR(vpc.Spec.CIDRs[0])
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: portName(102, "10.70.0.2"), UID: "port-uid", Labels: map[string]string{labelVPCNamespace: "tenant", labelVPC: "vpc", labelVMName: "vm", labelVMNIC: "0", labelPodNS: "tenant", labelPodName: "source", labelPodUID: "source-uid", vmidentity.InstanceUIDLabel: "instance-uid"}, Annotations: map[string]string{sdnv1alpha1.AnnotationContainerID: "source-sandbox", sdnv1alpha1.AnnotationCNIIfName: "eth0", sdnv1alpha1.AnnotationCNIPrimary: "true"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "vpc"}, IP: "10.70.0.2", MAC: "02:00:00:00:00:01", Node: "source-node", PodNamespace: "tenant", PodName: "source"}}
	client := sdnfake.NewSimpleClientset(port)
	r := resolvedAttachment{attachment: attachment{VPCNamespace: "tenant", IfName: "eth0"}, vpc: vpc, cidr: cidr, containerID: "target-sandbox", cniIfName: "eth0"}
	_, _, got, bound, err := attachPort(t.Context(), client, r, &datapath.AgentState{NodeName: "target-node"}, "tenant", "target", "target-uid", "vm", `{"kubevirt.io/created-by":"instance-uid"}`)
	if err != nil || !bound {
		t.Fatal("target failed to bind pinned Port", err)
	}
	if err := recordPortSandbox(t.Context(), client, got, "target-sandbox", "eth0", true, "target-node"); err != nil {
		t.Fatal(err)
	}
	got, err = client.SdnV1alpha1().Ports().Get(t.Context(), port.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels[labelPodUID] != "source-uid" || got.Spec.PodName != "source" || got.Annotations[sdnv1alpha1.AnnotationContainerID] != "source-sandbox" || got.Spec.IP != port.Spec.IP || got.Spec.MAC != port.Spec.MAC {
		t.Fatal("staged ADD changed the active source's identity", got)
	}
}
