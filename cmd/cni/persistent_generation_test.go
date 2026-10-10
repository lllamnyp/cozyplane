package main

import (
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestPersistentPortCannotMoveToRecreatedVPC(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	state := &datapath.AgentState{NodeName: "node", NodeIP: "192.0.2.1"}
	vpc := newVPC("tenant", "net", 100, "10.10.0.0/24")
	labels := `{"kubevirt.io/created-by":"current-instance"}`
	address, mac, original, _, err := attachPort(t.Context(), client, res(vpc, "tenant"), state, "tenant", "old-launcher", "old-pod", "vm", labels)
	if err != nil {
		t.Fatal(err)
	}
	recreated := vpc.DeepCopy()
	recreated.Status.VNI = 101
	if ip, _, _, _, err := attachPort(t.Context(), client, res(recreated, "tenant"), state, "tenant", "new-launcher", "new-pod", "vm", labels); err == nil {
		t.Fatalf("previous network's pinned identity adopted: %s", ip)
	}
	current, err := client.SdnV1alpha1().Ports().Get(t.Context(), original.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if current.Spec.IP != address.String() || current.Spec.MAC != mac.String() || current.Labels[labelPodUID] != "old-pod" || current.Spec.PodName != "old-launcher" {
		t.Fatal("rejected attachment mutated pinned identity", current)
	}
	list, err := client.SdnV1alpha1().Ports().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 {
		t.Fatal("replacement identity allocated", list, err)
	}
	ip, reusedMAC, _, bound, err := attachPort(t.Context(), client, res(vpc, "tenant"), state, "tenant", "new-launcher", "new-pod", "vm", labels)
	if err != nil || !bound || !ip.Equal(address) || reusedMAC.String() != mac.String() {
		t.Fatal("legitimate rebind failed", ip, reusedMAC, bound, err)
	}
}
