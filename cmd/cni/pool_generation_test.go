package main

import (
	"net"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPortAllocationIgnoresPredecessorVNIClaims(t *testing.T) {
	for _, kind := range []string{"Port", "ServiceVIP"} {
		t.Run(kind, func(t *testing.T) {
			client := sdnfake.NewSimpleClientset()
			ref := sdn.VPCRef{Namespace: "tenant", Name: "net"}
			meta := metav1.ObjectMeta{Labels: map[string]string{labelVPCNamespace: ref.Namespace, labelVPC: ref.Name}}
			if kind == "Port" {
				meta.Name = portName(100, "10.0.0.2")
				if _, err := client.SdnV1alpha1().Ports().Create(t.Context(), &sdn.Port{ObjectMeta: meta, Spec: sdn.PortSpec{IP: "10.0.0.2", VPCRef: ref}}, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			} else {
				meta.Name = "sv100.10-0-0-2"
				if _, err := client.SdnV1alpha1().ServiceVIPs().Create(t.Context(), &sdn.ServiceVIP{ObjectMeta: meta, Spec: sdn.ServiceVIPSpec{IP: "10.0.0.2", VPCRef: ref}}, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			vpc := newVPC(ref.Namespace, ref.Name, 101, "10.0.0.0/30")
			address, _, claim, _, err := attachPort(t.Context(), client, res(vpc, ref.Namespace), &datapath.AgentState{NodeName: "node"}, "tenant", "pod", "pod-uid", "", "")
			if err != nil || !address.Equal(net.ParseIP("10.0.0.2")) || claim.Name != portName(101, address.String()) {
				t.Fatal("old VNI occupied current pool", address, claim, err)
			}
			if kind == "Port" {
				if _, err := client.SdnV1alpha1().Ports().Get(t.Context(), meta.Name, metav1.GetOptions{}); err != nil {
					t.Fatal("predecessor claim was removed", err)
				}
			} else if _, err := client.SdnV1alpha1().ServiceVIPs().Get(t.Context(), meta.Name, metav1.GetOptions{}); err != nil {
				t.Fatal("predecessor claim was removed", err)
			}
		})
	}
}
