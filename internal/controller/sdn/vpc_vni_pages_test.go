package sdn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVNILiveScansUseBoundedPagesAndKeepLateClaims(t *testing.T) {
	vpcs := make([]sdnv1alpha1.VPC, 257)
	ports := make([]sdnv1alpha1.Port, 257)
	vips := make([]sdnv1alpha1.ServiceVIP, 257)
	for i := range vpcs {
		vpcs[i].ObjectMeta = metav1.ObjectMeta{Namespace: "tenant-a", Name: fmt.Sprintf("vpc-%04d", i), CreationTimestamp: metav1.NewTime(time.Unix(100+int64(i), 0))}
		vpcs[i].Spec.CIDRs = make([]string, 1024)
		for j := range vpcs[i].Spec.CIDRs {
			vpcs[i].Spec.CIDRs[j] = "10.0.0.0/24"
		}
		vpcs[i].Status.VNI = 100 + int32(i)
		ip := fmt.Sprintf("10.10.%d.%d", i/250, 1+i%250)
		ports[i].Name = api.PortName(900, ip)
		vips[i].Name = api.ServiceVIPName(1001, ip)
	}
	vpcs[256].Namespace = "tenant-b"
	vpcs[256].Status.VNI = vpcs[1].Status.VNI
	vpcs[256].CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
	// A terminating high-water holder remains reserved, just like orphan claims.
	now := metav1.Now()
	vpcs[255].DeletionTimestamp = &now
	vpcs[255].Status.VNI = 1100
	var requests, unbounded, largest atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		start, _ := strconv.Atoi(req.URL.Query().Get("continue"))
		if limit <= 0 || limit > 128 {
			unbounded.Add(1)
			limit = len(vpcs)
		}
		end := min(start+limit, len(vpcs))
		for end-start > int(largest.Load()) && !largest.CompareAndSwap(largest.Load(), int32(end-start)) {
		}
		meta := metav1.ListMeta{ResourceVersion: "1"}
		if end < len(vpcs) {
			meta.Continue = strconv.Itoa(end)
		}
		var out client.ObjectList
		switch req.URL.Path {
		case "/apis/sdn.cozystack.io/v1alpha1/vpcs":
			out = &sdnv1alpha1.VPCList{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1alpha1.SchemeGroupVersion.String(), Kind: "VPCList"}, ListMeta: meta, Items: vpcs[start:end]}
		case "/apis/sdn.cozystack.io/v1alpha1/ports":
			out = &sdnv1alpha1.PortList{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1alpha1.SchemeGroupVersion.String(), Kind: "PortList"}, ListMeta: meta, Items: ports[start:end]}
		case "/apis/sdn.cozystack.io/v1alpha1/servicevips":
			out = &sdnv1alpha1.ServiceVIPList{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1alpha1.SchemeGroupVersion.String(), Kind: "ServiceVIPList"}, ListMeta: meta, Items: vips[start:end]}
		default:
			http.Error(w, "unexpected resource", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(out); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{sdnv1alpha1.SchemeGroupVersion})
	for _, resource := range []struct{ kind, plural, singular string }{{"VPC", "vpcs", "vpc"}, {"Port", "ports", "port"}, {"ServiceVIP", "servicevips", "servicevip"}} {
		scope := meta.RESTScopeRoot
		if resource.kind == "VPC" {
			scope = meta.RESTScopeNamespace
		}
		mapper.AddSpecific(sdnv1alpha1.SchemeGroupVersion.WithKind(resource.kind), sdnv1alpha1.SchemeGroupVersion.WithResource(resource.plural), sdnv1alpha1.SchemeGroupVersion.WithResource(resource.singular), scope)
	}
	reader, err := client.New(&rest.Config{Host: server.URL}, client.Options{Scheme: svcScheme(t), Mapper: mapper})
	if err != nil {
		t.Fatal(err)
	}
	r := &VPCReconciler{Reader: reader}
	t.Run("bootstrap high water", func(t *testing.T) {
		requests.Store(0)
		unbounded.Store(0)
		largest.Store(0)
		high, err := r.initialVNIHighWater(t.Context())
		if err != nil || high != 1100 {
			t.Fatalf("orphan identity was not retained: high=%d err=%v", high, err)
		}
		if unbounded.Load() != 0 || largest.Load() > 128 || requests.Load() != 9 {
			t.Fatalf("bootstrap reads: unbounded=%d largest response=%d requests=%d; want 0, at most128, 9", unbounded.Load(), largest.Load(), requests.Load())
		}
	})
	t.Run("older duplicate on last page", func(t *testing.T) {
		requests.Store(0)
		unbounded.Store(0)
		largest.Store(0)
		lost, err := r.lostVNIToDuplicate(t.Context(), &vpcs[1])
		if err != nil || !lost {
			t.Fatalf("late older duplicate not detected: lost=%v err=%v", lost, err)
		}
		if unbounded.Load() != 0 || largest.Load() > 128 || requests.Load() != 3 {
			t.Fatalf("duplicate reads: unbounded=%d largest response=%d requests=%d; want 0, at most128, 3", unbounded.Load(), largest.Load(), requests.Load())
		}
	})
}
