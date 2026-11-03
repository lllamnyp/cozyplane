package main

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestCNIPortOwnershipScansCompleteBeforeReuseOrCleanup(t *testing.T) {
	for _, mode := range []string{"retry", "retry partial", "retry ambiguous", "DEL", "DEL partial", "persistent ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			vpc := &sdnv1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net"}, Spec: sdnv1.VPCSpec{CIDRs: []string{"10.70.0.0/24"}}, Status: sdnv1.VPCStatus{VNI: 101}}
			_, pool, _ := net.ParseCIDR(vpc.Spec.CIDRs[0])
			r := resolvedAttachment{attachment: attachment{VPCNamespace: "tenant", IfName: "eth0"}, vpc: vpc, cidr: pool, containerID: "sandbox", cniIfName: "eth0"}
			state := &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}
			ports := make([]sdnv1.Port, ipam.ClaimPageSize+2)
			for i := range ports {
				ip := fmt.Sprintf("10.70.0.%d", i+2)
				ports[i] = sdnv1.Port{ObjectMeta: metav1.ObjectMeta{Name: portName(101, ip), Labels: map[string]string{labelPodUID: "pod-uid", labelIfName: "eth0"}, Annotations: map[string]string{sdnv1.AnnotationContainerID: fmt.Sprintf("foreign-%d", i), sdnv1.AnnotationCNIIfName: "eth0"}}, Spec: sdnv1.PortSpec{IP: ip, Node: "node", PodNamespace: "tenant", PodName: "pod", VPCRef: sdnv1.VPCRef{Namespace: "tenant", Name: "net"}}}
			}
			target := len(ports) - 1
			if mode == "retry partial" || mode == "DEL partial" || mode == "retry ambiguous" {
				target = 0
			}
			ports[target].Annotations[sdnv1.AnnotationContainerID] = "sandbox"
			if mode == "retry ambiguous" {
				ports[len(ports)-1].Annotations[sdnv1.AnnotationContainerID] = "sandbox"
			}
			vmName, podLabels := "", ""
			if mode == "persistent ambiguous" {
				vmName, podLabels = "vm", `{"kubevirt.io/created-by":"instance-uid"}`
				for i := range ports {
					ports[i].Labels = map[string]string{labelVPCNamespace: "tenant", labelVPC: "net", labelVMName: "vm", labelVMNIC: r.NICID(), labelPodNS: "tenant", vmidentity.InstanceUIDLabel: "instance-uid"}
					ports[i].Spec.MAC = "02:00:00:00:00:01"
				}
			}
			client := sdnfake.NewSimpleClientset()
			calls, mutations, cleanups := 0, 0, 0
			client.PrependReactor("list", "ports", func(action k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				opts := action.(k8stesting.ListActionImpl).GetListOptions()
				if opts.Limit != ipam.ClaimPageSize || opts.LabelSelector == "" {
					t.Errorf("ownership list missing bounds/selector: %+v", opts)
				}
				if (mode == "retry partial" || mode == "DEL partial") && calls == 2 {
					return true, nil, fmt.Errorf("page unavailable")
				}
				start, _ := strconv.Atoi(opts.Continue)
				end := len(ports)
				if opts.Limit > 0 && start+int(opts.Limit) < end {
					end = start + int(opts.Limit)
				}
				page := &sdnv1.PortList{Items: ports[start:end]}
				if end < len(ports) {
					page.Continue = strconv.Itoa(end)
				}
				return true, page, nil
			})
			for _, verb := range []string{"create", "patch", "delete"} {
				client.PrependReactor(verb, "ports", func(k8stesting.Action) (bool, runtime.Object, error) { mutations++; return true, &sdnv1.Port{}, nil })
			}
			var err error
			if mode == "DEL" || mode == "DEL partial" {
				err = releaseSandboxPorts(t.Context(), client, labelPodUID+"=pod-uid", "sandbox", "eth0", func(*sdnv1.Port) { cleanups++ })
				if mode == "DEL" && (err != nil || cleanups != 1 || mutations != 1) {
					t.Fatal(cleanups, mutations, err)
				}
			} else {
				ip, _, port, reused, e := attachPort(t.Context(), client, r, state, "tenant", "pod", "pod-uid", vmName, podLabels)
				err = e
				if mode == "retry" && (e != nil || !reused || port == nil || ip.String() != ports[target].Spec.IP) {
					t.Fatal(ip, port, reused, e)
				}
			}
			if mode != "retry" && mode != "DEL" && (err == nil || cleanups != 0 || mutations != 0) {
				t.Fatal("incomplete or ambiguous scan acted on a claim", mutations, cleanups, err)
			}
			if calls != 2 {
				t.Fatal("scan did not consume all pages", calls)
			}
		})
	}
}
