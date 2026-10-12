package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

type metricsSnapshotSource struct {
	collections atomic.Int64
	failed      atomic.Bool
	packets     atomic.Uint64
}

func (s *metricsSnapshotSource) VPCCounters() (map[uint32]datapath.VPCCounter, error) {
	s.collections.Add(1)
	if s.failed.Load() {
		return nil, errors.New("counter map unavailable")
	}
	return map[uint32]datapath.VPCCounter{101: {TxPackets: s.packets.Load()}}, nil
}

func TestMetricsSnapshotRefreshesCountersAndCachesFailures(t *testing.T) {
	source := &metricsSnapshotSource{}
	source.packets.Store(42)
	factory := sdninformers.NewSharedInformerFactory(sdnfake.NewSimpleClientset(), 0)
	handler := agentMetricsHandler(source, factory.Sdn().V1alpha1().VPCs(), "node", nil).(*metricsSnapshotHandler)
	var millis atomic.Int64
	handler.now = func() time.Time { return time.UnixMilli(millis.Load()) }
	request := func(status int, value string) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
		if response.Code != status || !strings.Contains(response.Body.String(), value) {
			t.Fatalf("unexpected snapshot: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	line := "cozyplane_vpc_tx_packets_total{vni=\"101\",vpc_namespace=\"\",vpc=\"\",node=\"node\"} "
	request(200, line+"42\n")
	source.packets.Store(84)
	millis.Store(999)
	request(200, line+"42\n")
	source.failed.Store(true)
	millis.Store(1000)
	request(500, "counter map unavailable")
	source.failed.Store(false)
	request(500, "counter map unavailable")
	if source.collections.Load() != 2 {
		t.Fatal("failure bypassed retry budget")
	}
	millis.Store(2000)
	request(200, line+"84\n")
	if source.collections.Load() != 3 {
		t.Fatal("expiration did not collect fresh counters")
	}
}

func TestMetricsSnapshotConcurrentRequestsShareOneCollection(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var collections atomic.Int64
	handler := cacheMetricsSnapshot(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if collections.Add(1) == 1 {
			close(started)
		}
		<-release
		_, _ = w.Write([]byte("snapshot\n"))
	})).(*metricsSnapshotHandler)
	handler.now = func() time.Time { return time.UnixMilli(0) }
	var workers sync.WaitGroup
	for range 128 {
		workers.Go(func() {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			if response.Code != 200 || response.Body.String() != "snapshot\n" {
				t.Error("inconsistent shared response")
			}
		})
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("collection did not start")
	}
	close(release)
	workers.Wait()
	if collections.Load() != 1 {
		t.Fatal("concurrent requests multiplied collection work", collections.Load())
	}
}

func TestMetricsSnapshotRejectsOversizedResponseWithoutPartialMetrics(t *testing.T) {
	var collections atomic.Int64
	handler := &metricsSnapshotHandler{
		limit: 5, now: func() time.Time { return time.UnixMilli(0) },
		collect: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			collections.Add(1)
			_, _ = w.Write([]byte("abc"))
			_, _ = w.Write([]byte("too large"))
		}),
	}
	for range 10 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
		if response.Code != 503 || strings.Contains(response.Body.String(), "abc") {
			t.Fatal("oversized partial metrics escaped", response.Code, response.Body.String())
		}
	}
	if collections.Load() != 1 {
		t.Fatal("oversized response busy retried")
	}
}

type blockedMetricsWriter struct {
	header           http.Header
	started, release chan struct{}
}

func (w *blockedMetricsWriter) Header() http.Header { return w.header }
func (*blockedMetricsWriter) WriteHeader(int)       {}
func (w *blockedMetricsWriter) Write(body []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(body), nil
}

func TestMetricsSnapshotSlowHTTPWriterDoesNotBlockRefresh(t *testing.T) {
	var collections, millis atomic.Int64
	handler := cacheMetricsSnapshot(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { collections.Add(1); _, _ = w.Write([]byte("snapshot\n")) })).(*metricsSnapshotHandler)
	handler.now = func() time.Time { return time.UnixMilli(millis.Load()) }
	writer := &blockedMetricsWriter{header: make(http.Header), started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, httptest.NewRequest("GET", "/metrics", nil)); close(done) }()
	defer func() { close(writer.release); <-done }()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("write did not start")
	}
	millis.Store(1000)
	refreshed := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/metrics", nil))
		close(refreshed)
	}()
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("slow socket held collection lock")
	}
	if collections.Load() != 2 {
		t.Fatal("fresh snapshot not collected")
	}
}
func (*metricsSnapshotSource) MapMemlock() (map[string]uint64, error) {
	return map[string]uint64{"vpc_counters": 1024}, nil
}
func (*metricsSnapshotSource) SGDrops() (map[uint32]uint64, error) {
	return map[uint32]uint64{101: 2}, nil
}
func (*metricsSnapshotSource) NPDrops() (map[uint8]uint64, error) {
	return map[uint8]uint64{datapath.NPDirIn: 3}, nil
}
func (*metricsSnapshotSource) HFDrops() (map[uint8]uint64, error) {
	return map[uint8]uint64{datapath.NPDirIn: 4}, nil
}

func TestMetricsBurstDoesNotMultiplyCollectionWork(t *testing.T) {
	source := &metricsSnapshotSource{}
	factory := sdninformers.NewSharedInformerFactory(sdnfake.NewSimpleClientset(), 0)
	handler := agentMetricsHandler(source, factory.Sdn().V1alpha1().VPCs(), "node", nil)
	for range 1000 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
		if response.Code != 200 {
			t.Fatal(response.Code)
		}
	}
	if got := source.collections.Load(); got != 1 {
		t.Fatalf("one burst repeated full kernel collection %d times", got)
	}
}
