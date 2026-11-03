package podrepair

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lllamnyp/cozyplane/internal/ipam"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func snapshotPod(name, ip string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: name, UID: types.UID(name)}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: ip}}}}
}

func snapshotClient(t testing.TB, handler http.HandlerFunc) *kubernetes.Clientset {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: 10000, Burst: 10000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CoreV1().RESTClient().(*rest.RESTClient).Client.CloseIdleConnections)
	return client
}

func writePodPage(t testing.TB, w http.ResponseWriter, pods []corev1.Pod, token string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: metav1.ListMeta{Continue: token}, Items: pods}); err != nil {
		t.Error(err)
	}
}

func TestLocalPodSnapshotNoCandidatesMakesNoRequests(t *testing.T) {
	client := corefake.NewClientset()
	owners, err := ListLocalRunningPodAddresses(t.Context(), client, "node-a", nil)
	if err != nil || len(owners) != 0 || len(client.Actions()) != 0 {
		t.Fatalf("no-work path contacted the API: %v %v %v", owners, err, client.Actions())
	}
}

func TestLocalPodSnapshotRealSDKPaginationAndOwnership(t *testing.T) {
	var calls atomic.Int32
	client := snapshotClient(t, func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		q := r.URL.Query()
		if r.URL.Path != "/api/v1/pods" || q.Get("fieldSelector") != "spec.nodeName=node-a,status.phase=Running" || q.Get("limit") != "128" {
			t.Errorf("unexpected list request: %s", r.URL)
		}
		if call == 1 {
			if q.Get("continue") != "" {
				t.Error("first request carries a continuation")
			}
			writePodPage(t, w, []corev1.Pod{snapshotPod("live", "10.244.0.10"), snapshotPod("conflict-a", "10.244.0.12")}, "next")
			return
		}
		if call != 2 || q.Get("continue") != "next" {
			t.Errorf("incorrect continuation request: %s", r.URL)
		}
		fallback := snapshotPod("ipv6", "")
		fallback.Status.PodIPs = nil
		fallback.Status.PodIP = "fd00:0:0::10"
		invalid := []corev1.Pod{snapshotPod("foreign-node", "10.244.0.13"), snapshotPod("host", "10.244.0.14"), snapshotPod("historical", "10.244.0.15"), snapshotPod("terminating", "10.244.0.16"), snapshotPod("no-uid", "10.244.0.17")}
		invalid[0].Spec.NodeName = "node-b"
		invalid[1].Spec.HostNetwork = true
		invalid[2].Status.Phase = corev1.PodSucceeded
		invalid[3].DeletionTimestamp = new(metav1.Now())
		invalid[4].UID = ""
		pods := append([]corev1.Pod{fallback, snapshotPod("conflict-b", "10.244.0.12"), snapshotPod("live", "10.244.0.10"), snapshotPod("unrelated", "10.244.0.99")}, invalid...)
		writePodPage(t, w, pods, "")
	})
	candidates := map[string]struct{}{"10.244.0.10": {}, "fd00::10": {}, "10.244.0.12": {}}
	for i := 13; i <= 17; i++ {
		candidates["10.244.0."+strconv.Itoa(i)] = struct{}{}
	}
	owners, err := ListLocalRunningPodAddresses(t.Context(), client, "node-a", candidates)
	if err != nil || calls.Load() != 2 || len(owners) != 2 {
		t.Fatalf("unexpected snapshot: %v %v calls=%d", owners, err, calls.Load())
	}
	got := make(map[string]string)
	for _, owner := range owners {
		got[owner.Address] = owner.UID
	}
	if got["10.244.0.10"] != "live" || got["fd00::10"] != "ipv6" {
		t.Fatalf("canonical address or ownership lost: %v", got)
	}
}

func TestLocalPodSnapshotRejectsIncompleteLists(t *testing.T) {
	for _, mode := range []string{"API failure", "repeated token", "oversized page", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := snapshotClient(t, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					writePodPage(t, w, []corev1.Pod{snapshotPod("live", "10.244.0.10")}, "next")
					return
				}
				switch mode {
				case "API failure":
					http.Error(w, "snapshot expired", http.StatusGone)
				case "repeated token":
					writePodPage(t, w, nil, "next")
				case "oversized page":
					writePodPage(t, w, make([]corev1.Pod, ipam.ClaimPageSize+1), "")
				case "cancellation":
					cancel()
					writePodPage(t, w, nil, "")
				}
			})
			owners, err := ListLocalRunningPodAddresses(ctx, client, "node-a", map[string]struct{}{"10.244.0.10": {}})
			if err == nil || len(owners) != 0 || calls.Load() != 2 {
				t.Fatalf("incomplete list published repair authority: %v %v calls=%d", owners, err, calls.Load())
			}
		})
	}
}

func TestLocalPodSnapshotRealSDKHonorsSharedDeadline(t *testing.T) {
	client := snapshotClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continue") == "" {
			writePodPage(t, w, []corev1.Pod{snapshotPod("live", "10.244.0.10")}, "next")
			return
		}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	owners, err := ListLocalRunningPodAddresses(ctx, client, "node-a", map[string]struct{}{"10.244.0.10": {}})
	if err == nil || len(owners) != 0 || time.Since(start) > time.Second {
		t.Fatalf("page reset the shared operation deadline: %v %v", owners, err)
	}
}

// Exercise the actual client-go HTTP decoder for the old unfiltered snapshot
// and the bounded server-filtered path. Setup allocations are outside timing.
func BenchmarkLocalPodRepairHistoricalSnapshots(b *testing.B) {
	live := snapshotPod("live", "10.244.0.10")
	history := make([]corev1.Pod, 1024)
	for i := range history {
		history[i] = snapshotPod("retired-"+strconv.Itoa(i), "10.244.0.99")
		history[i].Status.Phase = corev1.PodSucceeded
		history[i].Annotations = map[string]string{"example.invalid/history": strings.Repeat("x", 8192)}
	}
	all, _ := json.Marshal(&corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, Items: append(history, live)})
	filtered, _ := json.Marshal(&corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, Items: []corev1.Pod{live}})
	client := snapshotClient(b, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Query().Get("fieldSelector"), "status.phase=Running") {
			_, _ = w.Write(filtered)
		} else {
			_, _ = w.Write(all)
		}
	})
	b.Run("previous-full-history", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pods, err := client.CoreV1().Pods("").List(b.Context(), metav1.ListOptions{FieldSelector: "spec.nodeName=node-a"})
			if err != nil || len(pods.Items) != 1025 {
				b.Fatal(err)
			}
		}
	})
	b.Run("running-bounded-snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			owners, err := ListLocalRunningPodAddresses(b.Context(), client, "node-a", map[string]struct{}{"10.244.0.10": {}})
			if err != nil || len(owners) != 1 {
				b.Fatal(err)
			}
		}
	})
}
