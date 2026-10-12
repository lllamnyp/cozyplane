package main

import (
	"bytes"
	"errors"
	"net/http"
	"sync"
	"time"
)

const maxMetricsSnapshotBytes = 128 << 20

type metricsSnapshotHandler struct {
	collect http.Handler
	mu      sync.Mutex
	now     func() time.Time
	limit   int
	expires time.Time
	body    []byte
	header  http.Header
	status  int
}

func cacheMetricsSnapshot(collect http.Handler) http.Handler {
	return &metricsSnapshotHandler{collect: collect, now: time.Now, limit: maxMetricsSnapshotBytes}
}

func (h *metricsSnapshotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		return
	}
	body, header, status := h.snapshot(r)
	// The immutable snapshot may be shared by concurrent clients. A slow HTTP
	// write must not keep the collection lock or delay another client's refresh.
	for key, values := range header {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (h *metricsSnapshotHandler) snapshot(r *http.Request) ([]byte, http.Header, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.expires.IsZero() || !h.now().Before(h.expires) {
		capture := &metricsSnapshotResponse{header: make(http.Header), limit: h.limit}
		h.collect.ServeHTTP(capture, r)
		if capture.tooLarge {
			h.body = []byte("metrics snapshot exceeds response budget\n")
			h.header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
			h.status = http.StatusServiceUnavailable
		} else {
			h.body, h.header, h.status = capture.body.Bytes(), capture.header, capture.status
			if h.status == 0 {
				h.status = http.StatusOK
			}
		}
		// Failures have the same retry budget; no busy retry or polling worker.
		h.expires = h.now().Add(time.Second)
	}
	return h.body, h.header, h.status
}

type metricsSnapshotResponse struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	limit    int
	tooLarge bool
}

func (w *metricsSnapshotResponse) Header() http.Header { return w.header }

func (w *metricsSnapshotResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *metricsSnapshotResponse) Write(data []byte) (int, error) {
	if w.tooLarge || len(data) > w.limit-w.body.Len() {
		w.tooLarge = true
		return 0, errors.New("metrics snapshot exceeds response budget")
	}
	w.WriteHeader(http.StatusOK)
	return w.body.Write(data)
}
