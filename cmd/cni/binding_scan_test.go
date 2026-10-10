package main

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestCNIBindingAuthorizationRequiresCompletePages(t *testing.T) {
	for _, mode := range []string{"last-page grant", "late blanket", "second-page error", "stuck continuation", "cancel after first page"} {
		t.Run(mode, func(t *testing.T) {
			client := sdnfake.NewSimpleClientset()
			bindings := make([]sdnv1alpha1.VPCBinding, ipam.ClaimPageSize+2)
			for i := range bindings {
				bindings[i] = sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: fmt.Sprintf("grant-%d", i)}, Spec: sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "owner", Name: "other"}}}
			}
			bindings[len(bindings)-1].Spec.VPCRef.Name = "net"
			bindings[len(bindings)-1].Spec.AllowForwarding = true
			bindings[len(bindings)-1].Spec.ForwardingCIDRs = []string{"192.0.2.0/24"}
			if mode == "late blanket" {
				bindings[0].Spec = bindings[len(bindings)-1].Spec
				bindings[0].Spec.ForwardingCIDRs = make([]string, sdnv1alpha1.MaxForwardingPrefixes+1)
				bindings[len(bindings)-1].Spec.ForwardingCIDRs = nil
			} else if mode != "last-page grant" {
				bindings[0].Spec = bindings[len(bindings)-1].Spec
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			client.PrependReactor("list", "vpcbindings", func(action k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				opts := action.(k8stesting.ListActionImpl).GetListOptions()
				if opts.Limit != ipam.ClaimPageSize || action.GetNamespace() != "consumer" {
					t.Errorf("unbounded or wrong namespace list: %+v", opts)
				}
				if mode == "second-page error" && calls == 2 {
					return true, nil, fmt.Errorf("page unavailable")
				}
				start, _ := strconv.Atoi(opts.Continue)
				end := len(bindings)
				if opts.Limit > 0 && start+int(opts.Limit) < end {
					end = start + int(opts.Limit)
				}
				page := &sdnv1alpha1.VPCBindingList{Items: bindings[start:end]}
				if end < len(bindings) {
					page.Continue = strconv.Itoa(end)
				}
				if mode == "stuck continuation" {
					page.Continue = "128"
				}
				if mode == "cancel after first page" {
					cancel()
				}
				return true, page, nil
			})
			allow, cidrs, err := requireVPCBinding(ctx, client, "consumer", "owner", "net")
			if mode == "last-page grant" {
				if err != nil || !allow || len(cidrs) != 1 || cidrs[0] != "192.0.2.0/24" {
					t.Fatal(allow, cidrs, err)
				}
			} else if mode == "late blanket" {
				if err != nil || !allow || cidrs != nil {
					t.Fatal(allow, cidrs, err)
				}
			} else if err == nil || allow || cidrs != nil {
				t.Fatal("partial scan granted rights", allow, cidrs, err)
			}
			wantCalls := 2
			if mode == "cancel after first page" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("incomplete page traversal", calls, wantCalls)
			}
		})
	}
}
