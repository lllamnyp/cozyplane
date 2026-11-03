package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
)

func TestPortAllocationBoundsConflictsAndCancellation(t *testing.T) {
	for _, mode := range []string{"conflict budget", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := sdnfake.NewSimpleClientset()
			attempts := 0
			client.PrependReactor("create", "ports", func(k8stesting.Action) (bool, runtime.Object, error) {
				attempts++
				if mode == "cancellation" {
					cancel()
					if attempts > 2 {
						return true, nil, errors.New("test stopped uncancelled allocation")
					}
				}
				if attempts > 65536 {
					return true, nil, errors.New("test stopped unlimited allocation")
				}
				return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: "sdn.cozystack.io", Resource: "ports"}, "concurrent-claim")
			})
			vpc := newVPC("tenant", "net", 100, "fd00::/64")
			_, _, _, _, err := attachPort(ctx, client, res(vpc, "tenant"), &datapath.AgentState{NodeName: "node"}, "tenant", "pod", "pod-uid", "", "")
			if mode == "cancellation" {
				if !errors.Is(err, context.Canceled) || attempts != 1 {
					t.Fatalf("cancelled ADD issued %d attempts and returned %v", attempts, err)
				}
			} else if err == nil || attempts != ipam.MaxClaimAttempts {
				t.Fatalf("unbounded ADD issued %d attempts, err=%v", attempts, err)
			}
		})
	}
}

func TestPortAllocationBoundsOccupiedAddressWalk(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	list := &sdnv1alpha1.PortList{}
	address := net.ParseIP("fd00::2")
	for i := 0; i < ipam.MaxCandidateWalk; i++ {
		list.Items = append(list.Items, sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: portName(100, address.String()), Labels: map[string]string{labelVPCNamespace: "tenant", labelVPC: "net"}}, Spec: sdnv1alpha1.PortSpec{IP: address.String()}})
		address = nextIP(address)
	}
	client.PrependReactor("list", "ports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		options := action.(interface{ GetListOptions() metav1.ListOptions }).GetListOptions()
		start := 0
		if options.Continue != "" {
			start, _ = strconv.Atoi(options.Continue)
		}
		end := len(list.Items)
		if options.Limit > 0 && end-start > int(options.Limit) {
			end = start + int(options.Limit)
		}
		page := &sdnv1alpha1.PortList{Items: list.Items[start:end]}
		if end < len(list.Items) {
			page.Continue = fmt.Sprint(end)
		}
		return true, page, nil
	})
	created := 0
	client.PrependReactor("create", "ports", func(k8stesting.Action) (bool, runtime.Object, error) {
		created++
		return true, nil, errors.New("unexpected allocation beyond occupied-walk budget")
	})
	vpc := newVPC("tenant", "net", 100, "fd00::/64")
	_, _, _, _, err := attachPort(t.Context(), client, res(vpc, "tenant"), &datapath.AgentState{NodeName: "node"}, "tenant", "pod", "pod-uid", "", "")
	if err == nil || created != 0 {
		t.Fatalf("walk escaped budget: %d allocation calls, err=%v", created, err)
	}
}

func TestPortAllocationRejectsIncompleteClaimScan(t *testing.T) {
	for _, mode := range []string{"oversized page", "stalled continuation", "cancelled page"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := sdnfake.NewSimpleClientset()
			calls := 0
			client.PrependReactor("list", "ports", func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				page := &sdnv1alpha1.PortList{}
				switch mode {
				case "oversized page":
					page.Items = make([]sdnv1alpha1.Port, 129)
					for i := range page.Items {
						page.Items[i].Labels = map[string]string{labelVPCNamespace: "tenant", labelVPC: "net"}
					}
				case "stalled continuation":
					page.Continue = "same-token"
				case "cancelled page":
					cancel()
				}
				return true, page, nil
			})
			created := 0
			client.PrependReactor("create", "ports", func(k8stesting.Action) (bool, runtime.Object, error) {
				created++
				return true, &sdnv1alpha1.Port{}, nil
			})
			vpc := newVPC("tenant", "net", 100, "10.0.0.0/24")
			_, _, _, _, err := attachPort(ctx, client, res(vpc, "tenant"), &datapath.AgentState{NodeName: "node"}, "tenant", "pod", "pod-uid", "", "")
			if err == nil || created != 0 || calls > 2 {
				t.Fatalf("incomplete scan created a claim: calls=%d created=%d err=%v", calls, created, err)
			}
		})
	}
}
