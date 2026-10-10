package sdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type vpnQuotaPageReader struct {
	client.Reader
	list func(context.Context, *sdnv1alpha1.VPNGatewayList, client.ListOptions) error
}

func (r vpnQuotaPageReader) List(ctx context.Context, out client.ObjectList, opts ...client.ListOption) error {
	options := client.ListOptions{}
	options.ApplyOptions(opts)
	return r.list(ctx, out.(*sdnv1alpha1.VPNGatewayList), options)
}

func vpnQuotaGateways(n int) []sdnv1alpha1.VPNGateway {
	items := make([]sdnv1alpha1.VPNGateway, n)
	for i := range items {
		name := fmt.Sprintf("gateway-%04d", i)
		items[i].ObjectMeta = metav1.ObjectMeta{Namespace: "tenant-a", Name: name, UID: types.UID(name), CreationTimestamp: metav1.NewTime(time.Unix(100+int64(i), 0))}
	}
	return items
}

func TestVPNNamespaceQuotaRequiresCurrentTarget(t *testing.T) {
	items := vpnQuotaGateways(3)
	for _, scenario := range []string{"missing", "replaced", "terminating"} {
		t.Run(scenario, func(t *testing.T) {
			actual := append([]sdnv1alpha1.VPNGateway(nil), items...)
			switch scenario {
			case "missing":
				actual = actual[1:]
			case "replaced":
				actual[0].UID = "replacement"
			case "terminating":
				now := metav1.Now()
				actual[0].DeletionTimestamp = &now
			}
			r := &VPNGatewayReconciler{Reader: vpnQuotaPageReader{list: func(_ context.Context, out *sdnv1alpha1.VPNGatewayList, _ client.ListOptions) error {
				out.Items = actual
				return nil
			}}}
			if reason, err := r.overQuota(t.Context(), &items[0], nil); err == nil {
				t.Fatalf("absent/current-UID mismatch was admitted: scenario=%s reason=%q", scenario, reason)
			}
		})
	}
}

func TestVPNNamespaceQuotaUsesBoundedLivePages(t *testing.T) {
	items := vpnQuotaGateways(257)
	var requests, unbounded atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.URL.Path != "/apis/sdn.cozystack.io/v1alpha1/namespaces/tenant-a/vpngateways" {
			http.Error(w, "unexpected namespace/resource", http.StatusBadRequest)
			return
		}
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		start, _ := strconv.Atoi(req.URL.Query().Get("continue"))
		if limit <= 0 || limit > 128 {
			unbounded.Add(1)
			limit = len(items)
		}
		end := min(start+limit, len(items))
		list := &sdnv1alpha1.VPNGatewayList{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1alpha1.SchemeGroupVersion.String(), Kind: "VPNGatewayList"}, ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: items[start:end]}
		if end < len(items) {
			list.Continue = strconv.Itoa(end)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(list); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{sdnv1alpha1.SchemeGroupVersion})
	mapper.AddSpecific(sdnv1alpha1.SchemeGroupVersion.WithKind("VPNGateway"), sdnv1alpha1.SchemeGroupVersion.WithResource("vpngateways"), sdnv1alpha1.SchemeGroupVersion.WithResource("vpngateway"), meta.RESTScopeNamespace)
	reader, err := client.New(&rest.Config{Host: server.URL}, client.Options{Scheme: svcScheme(t), Mapper: mapper})
	if err != nil {
		t.Fatal(err)
	}
	r := &VPNGatewayReconciler{Reader: reader, Config: VPNGatewayConfig{MaxGatewaysPerNamespace: 4}}
	for _, i := range []int{0, 3, 4, 256} {
		before := requests.Load()
		reason, err := r.overQuota(t.Context(), &items[i], nil)
		if err != nil || (reason != "") != (i >= 4) {
			t.Fatalf("oldest-wins verdict changed at rank%d: reason=%q err=%v", i+1, reason, err)
		}
		if unbounded.Load() != 0 || requests.Load()-before != 3 {
			t.Fatalf("quota count requested an unbounded response: unbounded=%d requests=%d", unbounded.Load(), requests.Load()-before)
		}
	}
}

func TestVPNNamespaceQuotaRejectsIncompleteSnapshots(t *testing.T) {
	gw := vpnQuotaGateways(1)[0]
	for _, scenario := range []string{"first error", "second error", "stalled continuation", "oversized page", "foreign namespace", "changed creation time", "page budget"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			r := &VPNGatewayReconciler{Reader: vpnQuotaPageReader{list: func(ctx context.Context, out *sdnv1alpha1.VPNGatewayList, opts client.ListOptions) error {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 30*time.Second || opts.Limit != 128 || opts.Namespace != gw.Namespace {
					t.Fatal("quota read lacks shared deadline or bounded namespace page")
				}
				if scenario == "first error" || scenario == "second error" && calls == 2 {
					return errors.New("transport unavailable")
				}
				out.Items = []sdnv1alpha1.VPNGateway{gw}
				switch scenario {
				case "second error", "stalled continuation":
					out.Continue = "same-token"
				case "oversized page":
					out.Items = make([]sdnv1alpha1.VPNGateway, 129)
				case "foreign namespace":
					out.Items[0].Namespace = "tenant-b"
				case "changed creation time":
					out.Items[0].CreationTimestamp = metav1.NewTime(time.Unix(200, 0))
				case "page budget":
					out.Continue = strconv.Itoa(calls)
				}
				return nil
			}}}
			if reason, err := r.overQuota(t.Context(), &gw, nil); err == nil || reason != "" {
				t.Fatalf("incomplete snapshot admitted or partially ranked: reason=%q err=%v", reason, err)
			}
			wantCalls := 1
			if scenario == "second error" || scenario == "stalled continuation" {
				wantCalls = 2
			} else if scenario == "page budget" {
				wantCalls = 512
			}
			if calls != wantCalls {
				t.Fatalf("failed quota scan kept requesting pages: calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}

func TestVPNNamespaceQuotaTieOrderAndCachedFallback(t *testing.T) {
	items := vpnQuotaGateways(4)
	var objects []client.Object
	for i := range items {
		items[i].CreationTimestamp = items[0].CreationTimestamp
		objects = append(objects, &items[i])
	}
	r := &VPNGatewayReconciler{Client: vpnIndexClient(t, objects...), Config: VPNGatewayConfig{MaxGatewaysPerNamespace: 2}}
	for i := range items {
		reason, err := r.overQuota(t.Context(), &items[i], nil)
		if err != nil || (reason != "") != (i >= 2) {
			t.Fatalf("equal-time name rank changed: i=%d reason=%q err=%v", i, reason, err)
		}
	}
	items = vpnQuotaGateways(128)
	objects = nil
	for i := range items {
		objects = append(objects, &items[i])
	}
	r.Client = vpnIndexClient(t, objects...)
	if reason, err := r.overQuota(t.Context(), &items[0], nil); err == nil || reason != "" {
		t.Fatalf("saturated cache ranking admitted an arbitrary truncated set: reason=%q err=%v", reason, err)
	}
}

func TestVPNNamespaceQuotaCancellation(t *testing.T) {
	gw := vpnQuotaGateways(1)[0]
	calls := 0
	r := &VPNGatewayReconciler{Reader: vpnQuotaPageReader{list: func(ctx context.Context, _ *sdnv1alpha1.VPNGatewayList, _ client.ListOptions) error {
		calls++
		<-ctx.Done()
		return ctx.Err()
	}}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.overQuota(ctx, &gw, nil); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled quota continued reading: calls=%d err=%v", calls, err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.overQuota(ctx, &gw, nil); !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("stalled reader exceeded shorter parent deadline: calls=%d err=%v", calls, err)
	}
}
