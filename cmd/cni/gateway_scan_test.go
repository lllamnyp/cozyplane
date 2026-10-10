package main

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestCNIGatewayConsentConsumesAllPages(t *testing.T) {
	for _, partial := range []bool{false, true} {
		client := sdnfake.NewSimpleClientset()
		gws := make([]sdnv1.VPCGateway, ipam.ClaimPageSize+2)
		for i := range gws {
			gws[i] = sdnv1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "owner", Name: fmt.Sprintf("gateway-%03d", i), CreationTimestamp: metav1.NewTime(time.Unix(10, 0))}, Spec: sdnv1.VPCGatewaySpec{VPCRef: sdnv1.LocalVPCRef{Name: "net"}}}
			gws[i].Spec.NAT.Enabled = true
		}
		// Last page's older gateway disables NAT. A partial page must not
		// authorize the younger NAT-enabled boundary seen on page one.
		gws[len(gws)-1].CreationTimestamp = metav1.NewTime(time.Unix(5, 0))
		gws[len(gws)-1].Spec.NAT.Enabled = false
		now := metav1.Now()
		gws[0].DeletionTimestamp = &now
		gws[0].CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
		gws[1].Spec.VPCRef.Name = "other"
		gws[1].CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
		gws[len(gws)-2].CreationTimestamp = gws[len(gws)-1].CreationTimestamp
		gws[len(gws)-2].Name = "zzz-loses-tie"
		calls := 0
		client.PrependReactor("list", "vpcgateways", func(action k8stesting.Action) (bool, runtime.Object, error) {
			calls++
			opts := action.(k8stesting.ListActionImpl).GetListOptions()
			if opts.Limit != ipam.ClaimPageSize || action.GetNamespace() != "owner" {
				t.Errorf("gateway list unbounded/wrong namespace: %+v", opts)
			}
			if partial && calls == 2 {
				return true, nil, fmt.Errorf("page unavailable")
			}
			start, _ := strconv.Atoi(opts.Continue)
			end := len(gws)
			if start+int(opts.Limit) < end {
				end = start + int(opts.Limit)
			}
			page := &sdnv1.VPCGatewayList{Items: gws[start:end]}
			if end < len(gws) {
				page.Continue = strconv.Itoa(end)
			}
			return true, page, nil
		})
		gateway, err := lookupEffectiveGateway(t.Context(), client, "owner", "net")
		if partial {
			if err == nil || gateway != nil {
				t.Fatal("partial consent exposed", gateway, err)
			}
		} else if err != nil || gateway == nil || gateway.Name != gws[len(gws)-1].Name || gateway.Spec.NAT.Enabled {
			t.Fatal("last-page authority lost", gateway, err)
		}
		if calls != 2 {
			t.Fatal("gateway pages not consumed", calls)
		}
	}
}
