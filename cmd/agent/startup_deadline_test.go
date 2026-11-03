package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localclient "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func startupAdvertisementRoute(t *testing.T) {
	t.Helper()
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated privileged Linux network namespace")
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Gw != nil && (route.Dst == nil || route.Dst.IP.IsUnspecified()) {
			t.Fatal("refusing to modify a namespace with an existing default route")
		}
	}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "auditstartup"}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	addr, err := netlink.ParseAddr("192.0.2.80/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	if got, err := datapath.DefaultRouteSrcIP(); err != nil || !got.Equal(addr.IP) {
		t.Fatal("owned startup fixture did not select its source address", got, err)
	}
}

// Uses real generated HTTP clients for every best-effort request stage.
func blockedStartupRequest(t *testing.T, stage string) (func(context.Context) error, <-chan struct{}, func()) {
	t.Helper()
	if stage == "advertisement" {
		startupAdvertisementRoute(t)
	}
	entered := make(chan struct{}, 64)
	claimPath := "/apis/" + localv1.GroupName + "/v1alpha1/fabricips"
	claimURL := claimPath + "/" + localv1.FabricIPName("10.244.4.2")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read PATCH/POST bodies before waiting for peer cancellation.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		blocked := stage == "dns" && r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/kube-system/services/kube-dns" ||
			stage == "advertisement" && r.Method == http.MethodPatch && r.URL.Path == "/api/v1/nodes/local" ||
			stage == "repair-list" && r.Method == http.MethodGet && r.URL.Path == "/api/v1/pods" ||
			stage == "repair-read" && r.Method == http.MethodGet && r.URL.Path == claimURL ||
			(stage == "repair-create" || stage == "repair-budget") && r.Method == http.MethodPost && r.URL.Path == claimPath
		if blocked {
			entered <- struct{}{}
			<-r.Context().Done()
			return
		}
		if stage == "repair-budget" {
			delay := time.NewTimer(2 * time.Second)
			defer delay.Stop()
			select {
			case <-delay.C:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/pods":
			if r.URL.Query().Get("fieldSelector") != "spec.nodeName=local,status.phase=Running" {
				t.Error("local repair omitted node scoping")
			}
			pods := &corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "launcher", Namespace: "tenant", UID: "pod-owner"}, Spec: corev1.PodSpec{NodeName: "local"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: "10.244.4.2"}}}}}}
			if err := json.NewEncoder(w).Encode(pods); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodGet && r.URL.Path == claimURL:
			w.WriteHeader(http.StatusNotFound)
			if err := json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound}); err != nil {
				t.Error(err)
			}
		default:
			http.Error(w, "unexpected startup request", http.StatusBadRequest)
		}
	}))
	transport := &http.Transport{}
	httpClient := &http.Client{Transport: transport}
	config := &rest.Config{Host: server.URL, QPS: -1}
	core, err := kubernetes.NewForConfigAndClient(config, httpClient)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	local, err := localclient.NewForConfigAndClient(config, httpClient)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { transport.CloseIdleConnections(); server.Close() }) }
	t.Cleanup(stop)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	call := func(ctx context.Context) error {
		switch stage {
		case "dns":
			v4, v6 := discoverClusterDNS(ctx, core)
			if v4 != nil || v6 != nil {
				t.Error("stalled DNS discovery invented an address")
			}
			return nil
		case "advertisement":
			advertiseNodeAddrs(ctx, core, "local", log)
			return nil
		default:
			return healLocalFabricIPs(ctx, core, local, "local", []datapath.LocalFabricIP{{Address: "10.244.4.2", ContainerID: "sandbox", IfName: "eth0"}}, log)
		}
	}
	return call, entered, stop
}

func TestStartupBestEffortRequestLifetime(t *testing.T) {
	for _, stage := range []string{"dns", "advertisement", "repair-list", "repair-read", "repair-create"} {
		t.Run(stage, func(t *testing.T) {
			call, entered, _ := blockedStartupRequest(t, stage)
			ctx, cancel := context.WithCancel(t.Context())
			returned := make(chan error, 1)
			done := make(chan struct{})
			go func() { defer close(done); returned <- call(ctx) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("startup request did not drain on shutdown")
				}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("startup request did not reach real HTTP")
			}
			select {
			case err := <-returned:
				if stage != "dns" && stage != "advertisement" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("repair request did not report its deadline", err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("best-effort startup remained blocked on the healthy agent context")
			}
			if ctx.Err() != nil {
				t.Fatal("startup timeout canceled the agent", ctx.Err())
			}
		})
	}
}

func TestStartupRequestCancellationReleasesResources(t *testing.T) {
	for _, stage := range []string{"dns", "advertisement", "repair-list", "repair-read", "repair-create"} {
		t.Run(stage, func(t *testing.T) {
			beforeFD, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			beforeGo := runtime.NumGoroutine()
			call, entered, stop := blockedStartupRequest(t, stage)
			for range 25 {
				ctx, cancel := context.WithCancel(t.Context())
				returned := make(chan error, 1)
				go func() { returned <- call(ctx) }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					cancel()
					t.Fatal("startup request did not start")
				}
				cancel()
				select {
				case <-returned:
				case <-time.After(time.Second):
					t.Fatal("startup request ignored cancellation")
				}
			}
			stop()
			deadline := time.Now().Add(time.Second)
			for runtime.NumGoroutine() > beforeGo+2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			afterFD, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(afterFD) != len(beforeFD) || runtime.NumGoroutine() > beforeGo+2 {
				t.Fatal("startup cancellations retained resources", len(beforeFD), len(afterFD), beforeGo, runtime.NumGoroutine(), err)
			}
		})
	}
}

func TestStartupRequestsHonorShorterParent(t *testing.T) {
	for _, stage := range []string{"dns", "advertisement", "repair-list", "repair-read", "repair-create"} {
		t.Run(stage, func(t *testing.T) {
			call, entered, _ := blockedStartupRequest(t, stage)
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			start := time.Now()
			_ = call(ctx)
			if time.Since(start) > 2*time.Second || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("startup helper extended its caller deadline", time.Since(start), ctx.Err())
			}
			select {
			case <-entered:
			default:
				t.Fatal("short-parent test did not reach the real HTTP stage")
			}
		})
	}
}

func TestStartupRepairSharesOperationBudget(t *testing.T) {
	call, entered, _ := blockedStartupRequest(t, "repair-budget")
	ctx, cancel := context.WithCancel(t.Context())
	returned, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); returned <- call(ctx) }()
	defer func() { cancel(); <-done }()
	start := time.Now()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delayed List/Get did not reach the actual Create")
	}
	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 6*time.Second || ctx.Err() != nil {
			t.Fatal("repair reset its operation budget between API requests", err, time.Since(start), ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("repair granted a new full timeout after its List/Get")
	}
}
