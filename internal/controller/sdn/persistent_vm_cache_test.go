package sdn

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func persistentVMCacheFixture(tb testing.TB, unrelated int) (*PersistentPortReconciler, *vpnCachedPortClient) {
	tb.Helper()
	ports := make([]sdn.Port, unrelated+2)
	for i := range ports {
		ports[i] = sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("port-%d", i), Labels: map[string]string{sdn.LabelVMName: "vm"}, Annotations: map[string]string{"test-payload": strings.Repeat("a", 4096)}}, Spec: sdn.PortSpec{PodNamespace: "tenant-b", IP: fmt.Sprintf("10.%d.%d.2", i/256, i%256), MAC: "02:00:00:00:00:01"}}
	}
	ports[0].Spec.PodNamespace, ports[1].Spec.PodNamespace = "tenant-a", "tenant-a"
	now := metav1.Now()
	ports[1].DeletionTimestamp = &now // Old/terminating claims must still be notified.
	cache, index := vpnObjectCache(tb, &sdn.Port{}, &sdn.PortList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: ports}, persistentVMIndex, persistentVMKeys)
	c := &vpnCachedPortClient{cache: cache, index: index}
	return &PersistentPortReconciler{Client: c}, c
}

func TestPersistentVMNotificationsScopeActualCache(t *testing.T) {
	r, c := persistentVMCacheFixture(t, 1024)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "launcher", Labels: map[string]string{sdn.KubeVirtLabelVMName: "vm"}}}
	instance := newVMI()
	instance.SetNamespace("tenant-a")
	instance.SetName("vm")
	for _, source := range []client.Object{pod, instance} {
		c.copied = 0
		var count int
		if source == pod {
			count = len(r.mapPodToPort(t.Context(), source))
		} else {
			count = len(r.mapVMIToPort(t.Context(), source))
		}
		if count != 2 || c.copied != 2 {
			t.Fatalf("VM event returned %d requests after copying %d Ports; want2 related claims only", count, c.copied)
		}
	}
}

func BenchmarkPersistentVMNotificationCopies(b *testing.B) {
	r, _ := persistentVMCacheFixture(b, 1024)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "launcher", Labels: map[string]string{sdn.KubeVirtLabelVMName: "vm"}}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.mapPodToPort(b.Context(), pod)
	}
}

func TestPersistentVMIndexRetargetRemovalAndPinnedIdentity(t *testing.T) {
	r, c := persistentVMCacheFixture(t, 8)
	port := &sdn.Port{}
	if err := c.cache.Get(t.Context(), client.ObjectKey{Name: "port-0"}, port); err != nil {
		t.Fatal(err)
	}
	originalIP, originalMAC := port.Spec.IP, port.Spec.MAC
	initialKeys := len(c.index.ListIndexFuncValues("field:" + persistentVMIndex))
	if initialKeys == 0 {
		t.Fatal("fixture lacks real field index memberships")
	}
	for i := 0; i < 1000; i++ {
		port = port.DeepCopy() // Store objects remain immutable, matching informer replacement.
		port.Spec.PodNamespace = fmt.Sprintf("tenant-%d", i)
		port.Labels[sdn.LabelVMName] = fmt.Sprintf("vm-%d", i)
		if err := c.index.Update(port); err != nil {
			t.Fatal(err)
		}
		c.copied = 0
		if got := r.mapVMToPort(t.Context(), "tenant-a", "vm"); len(got) != 1 || c.copied != 1 {
			t.Fatal("old key retained the retargeted Port or lost terminating claim")
		}
		c.copied = 0
		if got := r.mapVMToPort(t.Context(), port.Spec.PodNamespace, port.Labels[sdn.LabelVMName]); len(got) != 1 || c.copied != 1 || got[0].Name != port.Name {
			t.Fatal("current key lost its Port")
		}
		if port.Spec.IP != originalIP || port.Spec.MAC != originalMAC {
			t.Fatal("VM identity changed")
		}
		// Each root-scoped Port uses both the all-namespace and namespace key.
		if keys := len(c.index.ListIndexFuncValues("field:" + persistentVMIndex)); keys > initialKeys+2 {
			t.Fatalf("historical VM index keys retained: %d", keys)
		}
	}
	current := &sdn.Port{}
	if err := c.cache.Get(t.Context(), client.ObjectKey{Name: port.Name}, current); err != nil {
		t.Fatal(err)
	}
	if current.Spec.IP != originalIP || current.Spec.MAC != originalMAC {
		t.Fatal("lookup mutated pinned identity")
	}
	if err := c.index.Delete(port); err != nil {
		t.Fatal(err)
	}
	c.copied = 0
	if got := r.mapVMToPort(t.Context(), port.Spec.PodNamespace, port.Labels[sdn.LabelVMName]); len(got) != 0 || c.copied != 0 {
		t.Fatal("deleted Port remains indexed")
	}
}

func TestPersistentVMInvalidEventAndMissingIndexHaveNoFallback(t *testing.T) {
	r, c := persistentVMCacheFixture(t, 8)
	for _, pair := range [][2]string{{"", "vm"}, {"tenant-a", ""}, {strings.Repeat("a", 64), "vm"}, {"tenant-a", strings.Repeat("a", 128<<10)}, {"tenant-a", "vm/foreign"}} {
		c.calls, c.copied = 0, 0
		if got := r.mapVMToPort(t.Context(), pair[0], pair[1]); len(got) != 0 || c.calls != 0 || c.copied != 0 {
			t.Fatal("invalid tuple reached cache lookup")
		}
		port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{sdn.LabelVMName: pair[1]}}, Spec: sdn.PortSpec{PodNamespace: pair[0]}}
		if keys := persistentVMKeys(port); len(keys) != 0 {
			t.Fatal("invalid tuple retained in index")
		}
	}
	if err := c.cache.RemoveInformer(t.Context(), &sdn.Port{}); err != nil {
		t.Fatal(err)
	}
	c.calls, c.copied = 0, 0
	if got := r.mapVMToPort(t.Context(), "tenant-a", "vm"); len(got) != 0 || c.calls != 1 || c.copied != 0 {
		t.Fatal("missing index fell back to cluster scan")
	}
}

func TestPersistentVMIndexTupleDoesNotConflateNamespaces(t *testing.T) {
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{sdn.LabelVMName: "vm"}}, Spec: sdn.PortSpec{PodNamespace: "tenant-a"}}
	if got := persistentVMKeys(port); !reflect.DeepEqual(got, []string{"tenant-a/vm"}) {
		t.Fatal(got)
	}
	port.Spec.PodNamespace = "tenant-b"
	if got := persistentVMKeys(port); !reflect.DeepEqual(got, []string{"tenant-b/vm"}) {
		t.Fatal(got)
	}
	if got := persistentVMKeys(&corev1.Pod{}); len(got) != 0 {
		t.Fatal("non-Port object indexed")
	}
}
