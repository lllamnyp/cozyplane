package main

import (
	"fmt"
	"strconv"
	"testing"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestFabricIPSandboxLookupsUseCompletePages(t *testing.T) {
	for _, mode := range []string{"ADD retry", "DEL without UID", "ADD incomplete", "DEL incomplete"} {
		t.Run(mode, func(t *testing.T) {
			var objects []runtime.Object
			claims := make([]localv1alpha1.FabricIP, ipam.ClaimPageSize+2)
			for i := range claims {
				address := fmt.Sprintf("10.244.0.%d", i+2)
				claims[i] = localv1alpha1.FabricIP{
					ObjectMeta: metav1.ObjectMeta{Name: localv1alpha1.FabricIPName(address), Labels: map[string]string{labelFabricPodUID: "pod-uid"}},
					Spec:       localv1alpha1.FabricIPSpec{Address: address, Node: "node", PodNamespace: "tenant", PodName: "pod", PodUID: "pod-uid", ContainerID: fmt.Sprintf("foreign-%d", i), IfName: "eth0"},
				}
			}
			target := len(claims) - 1
			if mode == "ADD incomplete" || mode == "DEL incomplete" {
				target = 0 // owned object on page one must not be acted on before page two succeeds
			}
			claims[target].Spec.ContainerID = "sandbox"
			for i := range claims {
				objects = append(objects, &claims[i])
			}
			client := localfake.NewSimpleClientset(objects...)
			calls, mutations, bridges := 0, 0, 0
			client.PrependReactor("list", "fabricips", func(action k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if (mode == "ADD incomplete" || mode == "DEL incomplete") && calls == 2 {
					return true, nil, fmt.Errorf("second page unavailable")
				}
				opts := action.(k8stesting.ListActionImpl).GetListOptions()
				start, _ := strconv.Atoi(opts.Continue)
				end := len(claims)
				if opts.Limit != 0 && start+int(opts.Limit) < end {
					end = start + int(opts.Limit)
				}
				list := &localv1alpha1.FabricIPList{Items: claims[start:end]}
				if end < len(claims) {
					list.Continue = strconv.Itoa(end)
				}
				return true, list, nil
			})
			for _, verb := range []string{"create", "delete"} {
				client.PrependReactor(verb, "fabricips", func(k8stesting.Action) (bool, runtime.Object, error) {
					mutations++
					return false, nil, nil
				})
			}
			var err error
			if mode == "ADD retry" || mode == "ADD incomplete" {
				allocation, e := claimFabricIPs(t.Context(), client, []string{"10.244.0.0/24"}, "node", "tenant", "pod", "pod-uid", "sandbox", "eth0")
				err = e
				if mode == "ADD retry" && (e != nil || len(allocation.Addresses) != 1 || allocation.Addresses[0].String() != claims[target].Spec.Address || mutations != 0) {
					t.Fatal("retry did not reuse its final-page claim", e)
				}
			} else {
				err = releaseFabricIPs(t.Context(), client, "", "sandbox", "eth0", func(string) error { bridges++; return nil })
				if mode == "DEL without UID" && (err != nil || mutations != 1 || bridges != 1) {
					t.Fatalf("DEL mutations=%d bridges=%d err=%v", mutations, bridges, err)
				}
			}
			if mode == "ADD incomplete" || mode == "DEL incomplete" {
				if err == nil || mutations != 0 || bridges != 0 {
					t.Fatalf("partial scan acted on ownership: mutations=%d bridges=%d err=%v", mutations, bridges, err)
				}
			}
			if calls != 2 {
				t.Fatalf("ownership scan not paged: calls=%d", calls)
			}
		})
	}
}
