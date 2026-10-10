package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnclient "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func TestTerminatingPortIndexTracksOnlyCurrentClaims(t *testing.T) {
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{terminatingPortIndex: terminatingPortKeys})
	p := severTestPort()
	if err := store.Add(p); err != nil {
		t.Fatal(err)
	}
	current := p.DeepCopy()
	current.UID = "replacement"
	current.DeletionTimestamp = nil
	if err := store.Update(current); err != nil {
		t.Fatal(err)
	}
	objects, err := store.ByIndex(terminatingPortIndex, "terminating")
	if err != nil || len(objects) != 0 {
		t.Fatal("index retained obsolete generation", objects, err)
	}
	for i := range 1000 {
		p = severTestPort()
		p.Name = fmt.Sprintf("claim-%04d", i)
		if err := store.Add(p); err != nil {
			t.Fatal(err)
		}
		objects, err = store.ByIndex(terminatingPortIndex, "terminating")
		if err != nil || len(objects) != 1 || objects[0] != p {
			t.Fatal("index materialized unrelated or historical claims", objects, err)
		}
		if err := store.Delete(p); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.ListIndexFuncValues(terminatingPortIndex)) != 0 {
		t.Fatal("terminating index retained historical membership")
	}
}

type severRecovery struct {
	entered    chan struct{}
	resume     chan struct{}
	gets, puts atomic.Int32
	fail       atomic.Bool
	failed     chan struct{}
}

// The HTTP client reads the same tracker that feeds the watch. The first read
// stalls; recovery then exposes live UID/RV and validates the conditional PUT.
func recoverableSeverAPI(t *testing.T, backend sdnclient.Interface, port *sdnv1.Port) (*sdnclient.Clientset, *severRecovery) {
	t.Helper()
	state := &severRecovery{entered: make(chan struct{}, 1), resume: make(chan struct{}), failed: make(chan struct{}, 16)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/sdn.cozystack.io/v1alpha1/ports/"+port.Name {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodGet && state.gets.Add(1) == 1 {
			state.entered <- struct{}{}
			select {
			case <-state.resume:
			case <-r.Context().Done():
				return
			}
		}
		if state.fail.Load() {
			select {
			case state.failed <- struct{}{}:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable, Message: "temporary audit API failure"})
			return
		}
		current, err := backend.SdnV1alpha1().Ports().Get(r.Context(), port.Name, metav1.GetOptions{})
		if err != nil {
			http.Error(w, "claim unavailable", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			state.puts.Add(1)
			var update sdnv1.Port
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				http.Error(w, "invalid update", http.StatusBadRequest)
				return
			}
			if update.UID != current.UID || update.ResourceVersion != current.ResourceVersion {
				http.Error(w, "claim replaced", http.StatusConflict)
				return
			}
			current, err = backend.SdnV1alpha1().Ports().Update(r.Context(), &update, metav1.UpdateOptions{})
			if err != nil {
				http.Error(w, "update failed", http.StatusInternalServerError)
				return
			}
		} else if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current)
	}))
	transport := &http.Transport{}
	client, err := sdnclient.NewForConfigAndClient(&rest.Config{Host: server.URL, QPS: -1}, &http.Client{Transport: transport})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { transport.CloseIdleConnections(); server.Close() }) })
	return client, state
}
