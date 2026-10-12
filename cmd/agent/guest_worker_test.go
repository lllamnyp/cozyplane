package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func blockedGuestAPI(t *testing.T) (func(context.Context) error, <-chan struct{}, func()) {
	core, entered, stop := blockedGuestCoreAPI(t)
	return func(ctx context.Context) error {
		_, err := core.CoreV1().Pods("tenant").Get(ctx, "launcher", metav1.GetOptions{})
		return err
	}, entered, stop
}

func blockedGuestCoreAPI(t *testing.T) (kubernetes.Interface, <-chan struct{}, func()) {
	t.Helper()
	entered := make(chan struct{}, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/tenant/pods/launcher" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		entered <- struct{}{}
		<-r.Context().Done() // Established HTTP connection, no response headers.
	}))
	transport := &http.Transport{}
	core, err := kubernetes.NewForConfigAndClient(&rest.Config{Host: server.URL, QPS: -1}, &http.Client{Transport: transport})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var closeOnce sync.Once
	stop := func() { closeOnce.Do(func() { transport.CloseIdleConnections(); server.Close() }) }
	t.Cleanup(stop)
	return core, entered, stop
}

func TestGuestWorkerRetainsSlotAndCancelsChildAPIRequest(t *testing.T) {
	getPod, entered, _ := blockedGuestAPI(t)
	root, cancelRoot := context.WithCancel(t.Context())
	child, cancelChild := context.WithCancel(root)
	returned := make(chan error, 1)
	done := make(chan struct{})
	var finishes atomic.Int32
	go func() {
		defer close(done)
		runGuestCutover(child, func(context.Context) error { return nil },
			func(ctx context.Context) { returned <- getPod(ctx) },
			func() { finishes.Add(1) })
	}()
	t.Cleanup(func() {
		cancelChild()
		cancelRoot()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("guest worker did not drain after shutdown")
		}
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("guest API request did not start")
	}
	if finishes.Load() != 0 {
		t.Error("listener slot released while live API request still blocked")
	}
	cancelChild() // Endpoint/Port replacement; the agent root remains healthy.
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Error("child cancellation did not reach the real HTTP client", err)
		}
	case <-time.After(time.Second):
		t.Error("child cancellation left the real HTTP request blocked on the agent root")
	}
	if root.Err() != nil {
		t.Error("test unexpectedly canceled the whole agent")
	}
}

func TestGuestWorkerBoundsStalledAPIWithDeadline(t *testing.T) {
	getPod, entered, _ := blockedGuestAPI(t)
	ctx, cancel := context.WithCancel(t.Context())
	returned := make(chan error, 1)
	done := make(chan struct{})
	var finishes atomic.Int32
	go func() {
		defer close(done)
		runGuestCutover(ctx, func(context.Context) error { return nil }, func(apiCtx context.Context) {
			deadline, ok := apiCtx.Deadline()
			if !ok || time.Until(deadline) > guestCutoverTimeout {
				t.Error("cutover context has no bounded deadline")
			}
			returned <- getPod(apiCtx)
		}, func() { finishes.Add(1) })
	}()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("API request did not start")
	}
	if finishes.Load() != 0 {
		t.Error("listener released before bounded API work completed")
	}
	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("stalled API did not respect the cutover deadline", err)
		}
	case <-time.After(guestCutoverTimeout + time.Second):
		t.Fatal("stalled API outlived cutover deadline")
	}
	<-done
	if finishes.Load() != 1 || ctx.Err() != nil {
		t.Fatal("bounded failure did not release exactly one slot while parent stayed healthy", finishes.Load(), ctx.Err())
	}
}

func TestGuestWorkerCanceledAnnouncementDoesNotCallAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fires, finishes := 0, 0
	runGuestCutover(ctx, func(context.Context) error { return nil }, func(context.Context) { fires++ }, func() { finishes++ })
	if fires != 0 || finishes != 1 {
		t.Fatal("late packet on a canceled listener invoked API work", fires, finishes)
	}
	runGuestCutover(t.Context(), func(context.Context) error { return context.Canceled }, func(context.Context) { fires++ }, func() { finishes++ })
	if fires != 0 || finishes != 2 {
		t.Fatal("failed receive leaked registration or invoked API work", fires, finishes)
	}
}

func TestGuestWorkerRepeatedChildCancellationReleasesResources(t *testing.T) {
	countFD := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	beforeFD, beforeGo := countFD(), runtime.NumGoroutine()
	getPod, entered, stop := blockedGuestAPI(t)
	root, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()
	for range 25 {
		child, cancelChild := context.WithCancel(root)
		done := make(chan struct{})
		var finishes atomic.Int32
		go func() {
			defer close(done)
			runGuestCutover(child, func(context.Context) error { return nil }, func(ctx context.Context) { _ = getPod(ctx) }, func() { finishes.Add(1) })
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			cancelChild()
			t.Fatal("request did not start")
		}
		cancelChild()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("child cancellation did not drain the worker")
		}
		if finishes.Load() != 1 || root.Err() != nil {
			t.Fatal("child cancellation did not release its slot independently", finishes.Load())
		}
	}
	stop() // Drain the real HTTP server and close idle transport connections.
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > beforeGo+2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if after := countFD(); after != beforeFD {
		t.Fatalf("FD changed after 25 canceled requests: %d -> %d", beforeFD, after)
	}
	if after := runtime.NumGoroutine(); after > beforeGo+2 {
		t.Fatalf("goroutines retained after 25 canceled requests: %d -> %d", beforeGo, after)
	}
}
