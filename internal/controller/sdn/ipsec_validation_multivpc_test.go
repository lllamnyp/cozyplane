package sdn

import (
	"slices"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestIPsecMultiVPCUsesSelectedEndpointPodOnEveryLeg(t *testing.T) {
	for _, failure := range []string{"none", "missing selected claim", "stale claim UID", "pod name reused"} {
		t.Run(failure, func(t *testing.T) {
			r, gw, primary, c := vpnApplianceIndexFixture(t, 0, true)
			gw.Spec.IPsec = &sdn.VPNGatewayIPsec{}
			gw.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeWarmStandby}
			selected := r.resolveAppliancePorts(t.Context(), gw, primary, 1)
			if len(selected) != 1 || selected[0].PodUID == "" {
				t.Fatal("fixture did not resolve selected appliance identity")
			}
			pod := &corev1.Pod{}
			if err := c.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: selected[0].PodName}, pod); err != nil {
				t.Fatal(err)
			}
			other := pod.DeepCopy()
			other.Name, other.UID, other.ResourceVersion = "standby", "standby-current", ""
			other.Status.PodIP = "192.0.2.11"
			if err := c.Create(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			secondary := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: "secondary", Namespace: gw.Namespace}, Spec: sdn.VPCSpec{CIDRs: []string{"10.1.0.0/24"}}, Status: sdn.VPCStatus{VNI: 202}}
			selectedPort := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v202.10-1-0-2", CreationTimestamp: metav1.NewTime(time.Unix(100, 0)), Labels: map[string]string{sdn.LabelVPCNamespace: gw.Namespace, sdn.LabelVPC: secondary.Name, sdn.LabelPodUID: string(pod.UID)}}, Spec: sdn.PortSpec{IP: "10.1.0.2", VPCRef: sdn.VPCRef{Namespace: secondary.Namespace, Name: secondary.Name}, PodNamespace: pod.Namespace, PodName: pod.Name}}
			standbyPort := selectedPort.DeepCopy()
			standbyPort.Name, standbyPort.Spec.IP = "v202.10-1-0-3", "10.1.0.3"
			standbyPort.Spec.PodName, standbyPort.Labels[sdn.LabelPodUID] = other.Name, string(other.UID)
			standbyPort.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
			if err := c.index.Add(standbyPort); err != nil {
				t.Fatal(err)
			}
			if failure != "missing selected claim" {
				if failure == "stale claim UID" {
					selectedPort.Labels[sdn.LabelPodUID] = "predecessor-uid"
				}
				if err := c.index.Add(selectedPort); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "pod name reused" {
				if err := c.Delete(t.Context(), pod); err != nil {
					t.Fatal(err)
				}
				pod.UID, pod.ResourceVersion = "replacement-current", ""
				if err := c.Create(t.Context(), pod); err != nil {
					t.Fatal(err)
				}
			}
			got := r.resolveVPCLegPorts(t.Context(), gw, secondary, selected)
			if failure == "none" {
				if !slices.Equal(got, []string{selectedPort.Name}) {
					t.Fatalf("secondary leg selected unrelated standby endpoint: %v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("failed selected endpoint identity silently fell back to standby: %v", got)
			}
		})
	}
}
