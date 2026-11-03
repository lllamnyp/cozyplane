package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func blockedSeverAPI(t *testing.T, stage string) (*sdnclient.Clientset, *sdnv1.Port, <-chan struct{}, func()) {
	t.Helper()
	port := severTestPort()
	payload, err := json.Marshal(port)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 64)
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/sdn.cozystack.io/v1alpha1/ports/"+port.Name {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		// Read the SDK's PUT body before simulating a stalled response. Go's
		// HTTP server cannot observe peer closure while that body is unread.
		if r.Method == http.MethodPut {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
		}
		read := int32(0)
		if r.Method == http.MethodGet {
			read = reads.Add(1)
		}
		block := (stage == "initial" && read > 0) || (stage == "confirmation" && read > 1) || (stage == "update" && r.Method == http.MethodPut)
		if block {
			entered <- struct{}{}
			<-r.Context().Done()
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected write", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	transport := &http.Transport{}
	client, err := sdnclient.NewForConfigAndClient(&rest.Config{Host: server.URL, QPS: -1}, &http.Client{Transport: transport})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { transport.CloseIdleConnections(); server.Close() }) }
	t.Cleanup(stop)
	return client, port, entered, stop
}

func severTestPort() *sdnv1.Port {
	return &sdnv1.Port{
		TypeMeta:   metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "Port"},
		ObjectMeta: metav1.ObjectMeta{Name: "v100.192-0-2-10", UID: "port-owner", ResourceVersion: "1", DeletionTimestamp: new(metav1.Now()), Finalizers: []string{sdnv1.FinalizerSever}},
		Spec:       sdnv1.PortSpec{Node: "local", PodNamespace: "tenant", PodName: "workload", IP: "192.0.2.10"},
	}
}

func TestSeverAcknowledgementBoundsStalledInitialRead(t *testing.T) {
	assertBoundedSeverAcknowledgement(t, "initial", 0)
}

func TestSeverAcknowledgementBoundsConfirmationAndUpdate(t *testing.T) {
	for _, stage := range []string{"confirmation", "update"} {
		t.Run(stage, func(t *testing.T) { assertBoundedSeverAcknowledgement(t, stage, 0) })
	}
}

func TestSeverAcknowledgementPreservesShorterParent(t *testing.T) {
	assertBoundedSeverAcknowledgement(t, "initial", 250*time.Millisecond)
}

func assertBoundedSeverAcknowledgement(t *testing.T, stage string, parentBudget time.Duration) {
	t.Helper()
	client, port, entered, _ := blockedSeverAPI(t, stage)
	ctx, cancel := context.WithCancel(t.Context())
	if parentBudget > 0 {
		cancel()
		ctx, cancel = context.WithTimeout(t.Context(), parentBudget)
	}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		releaseSeveredPort(ctx, client, corefake.NewSimpleClientset(), emptySeverOwnershipFactory(), port, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("sever request did not drain after shutdown")
		}
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real SDN request did not start")
	}
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("sever acknowledgement remained blocked on healthy agent context")
	}
	if parentBudget == 0 && ctx.Err() != nil || len(port.Finalizers) != 1 {
		t.Fatal("failed read canceled parent or released barrier", ctx.Err(), port.Finalizers)
	}
	if parentBudget > 0 && (ctx.Err() != context.DeadlineExceeded || time.Since(start) > 2*time.Second) {
		t.Fatal("sever operation extended shorter parent budget", ctx.Err(), time.Since(start))
	}
}

func emptySeverOwnershipFactory() localinformers.SharedInformerFactory {
	return localinformers.NewSharedInformerFactory(localfake.NewSimpleClientset(), 0)
}

func TestSeverAcknowledgementCancellationReleasesResources(t *testing.T) {
	countFD := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	beforeFD, beforeGo := countFD(), runtime.NumGoroutine()
	client, port, entered, stop := blockedSeverAPI(t, "initial")
	root, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()
	for range 25 {
		child, cancel := context.WithCancel(root)
		done := make(chan struct{})
		go func() {
			defer close(done)
			releaseSeveredPort(child, client, corefake.NewSimpleClientset(), nil, port, slog.New(slog.NewTextHandler(io.Discard, nil)))
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("real sever request did not start")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("sever cancellation did not drain")
		}
		if root.Err() != nil || len(port.Finalizers) != 1 {
			t.Fatal("sever cancellation changed parent or barrier")
		}
	}
	stop()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > beforeGo+2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if after := countFD(); after != beforeFD {
		t.Fatal("sever cancellations leaked descriptors", beforeFD, after)
	}
	if after := runtime.NumGoroutine(); after > beforeGo+2 {
		t.Fatal("sever cancellations retained goroutines", beforeGo, after)
	}
}
