package main

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTenantPortCannotClaimPoolNetworkOrGateway(t *testing.T) {
	for _, test := range []struct{ pool, address string }{{"10.0.0.0/24", "10.0.0.0"}, {"10.0.0.0/24", "10.0.0.1"}, {"fd00::/64", "fd00::"}, {"fd00::/64", "fd00::1"}} {
		t.Run(test.address, func(t *testing.T) {
			client := sdnfake.NewSimpleClientset()
			vpc := newVPC("owner", "net", 100, test.pool)
			if address, _, _, _, err := attachPort(t.Context(), client, res(vpc, "owner", withIP(test.address)), &datapath.AgentState{NodeName: "node"}, "consumer", "pod", "pod-uid", "", ""); err == nil {
				t.Fatalf("tenant took reserved pool identity %s", address)
			}
			claims, err := client.SdnV1alpha1().Ports().List(t.Context(), metav1.ListOptions{})
			if err != nil || len(claims.Items) != 0 {
				t.Fatal("reserved claim created", claims, err)
			}
		})
	}
}

func TestReservedPoolClaimIsPreservedAndCannotBeRebound(t *testing.T) {
	for _, mode := range []string{"ordinary retry", "persistent bind"} {
		t.Run(mode, func(t *testing.T) {
			vpc := newVPC("owner", "net", 100, "10.0.0.0/24")
			claim := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: portName(100, "10.0.0.1"), Labels: map[string]string{labelVPCNamespace: "owner", labelVPC: "net", labelPodNS: "consumer", labelPodUID: "pod-uid", labelIfName: "eth0"}, Annotations: map[string]string{sdnv1alpha1.AnnotationContainerID: "sandbox", sdnv1alpha1.AnnotationCNIIfName: "eth0"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "owner", Name: "net"}, IP: "10.0.0.1", MAC: "02:00:00:00:00:10", Node: "node", PodNamespace: "consumer", PodName: "pod"}}
			vm := ""
			if mode == "persistent bind" {
				vm = "vm"
				claim.Labels[labelVMName] = vm
				claim.Labels[labelVMNIC] = "0"
				claim.Labels[vmidentity.InstanceUIDLabel] = "instance-uid"
			}
			client := sdnfake.NewSimpleClientset(claim)
			r := res(vpc, "owner")
			r.containerID = "sandbox"
			r.cniIfName = "eth0"
			_, _, _, _, err := attachPort(t.Context(), client, r, &datapath.AgentState{NodeName: "node"}, "consumer", "pod", "pod-uid", vm, `{"kubevirt.io/created-by":"instance-uid"}`)
			if err == nil {
				t.Fatal("reserved pool claim reused")
			}
			current, err := client.SdnV1alpha1().Ports().Get(t.Context(), claim.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if current.Spec != claim.Spec || current.Labels[labelPodUID] != claim.Labels[labelPodUID] {
				t.Fatal("pinned identity changed", current)
			}
		})
	}
}
