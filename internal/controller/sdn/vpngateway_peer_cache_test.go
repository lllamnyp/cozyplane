package sdn

import (
	"context"
	"fmt"
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type vpnPeerListWatch struct{ *toolscache.ListWatch }

func (*vpnPeerListWatch) IsWatchListSemanticsUnSupported() bool { return true }

// Use the production cache reader, indexer and informer. Only the upstream
// list/watch transport is in-memory; fake.Client does not implement List Limit.
func vpnPeerCache(tb testing.TB, peers []sdnv1alpha1.VPNConnection) (cache.Cache, toolscache.Indexer) {
	return vpnObjectCache(tb, &sdnv1alpha1.VPNConnection{}, &sdnv1alpha1.VPNConnectionList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: peers}, vpnConnectionGatewayIndex, vpnConnectionGatewayKeys)
}

func vpnObjectCache(tb testing.TB, object client.Object, list client.ObjectList, field string, extract client.IndexerFunc) (cache.Cache, toolscache.Indexer) {
	tb.Helper()
	listMeta, err := meta.ListAccessor(list)
	if err != nil || listMeta.GetContinue() != "" {
		tb.Fatal("cache fixture upstream must provide a complete API list")
	}
	upstream := list.DeepCopyObject() // Caller cache queries must not mutate the transport snapshot.
	scheme := runtime.NewScheme()
	if err := sdnv1alpha1.AddToScheme(scheme); err != nil {
		tb.Fatal(err)
	}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{sdnv1alpha1.SchemeGroupVersion})
	kinds, _, err := scheme.ObjectKinds(object)
	if err != nil || len(kinds) != 1 {
		tb.Fatalf("unexpected cache object kinds: %v %v", kinds, err)
	}
	scope := meta.RESTScopeNamespace
	if _, ok := object.(*sdnv1alpha1.Port); ok {
		scope = meta.RESTScopeRoot
	}
	mapper.Add(kinds[0], scope)
	w := watch.NewRaceFreeFake()
	tb.Cleanup(w.Stop)
	var informer toolscache.SharedIndexInformer
	c, err := cache.New(&rest.Config{Host: "http://127.0.0.1"}, cache.Options{
		Scheme: scheme, Mapper: mapper,
		NewInformer: func(_ toolscache.ListerWatcher, obj runtime.Object, resync time.Duration, indices toolscache.Indexers) toolscache.SharedIndexInformer {
			lw := &toolscache.ListWatch{
				ListWithContextFunc: func(ctx context.Context, _ metav1.ListOptions) (runtime.Object, error) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return upstream.DeepCopyObject(), nil
				},
				WatchFuncWithContext: func(ctx context.Context, _ metav1.ListOptions) (watch.Interface, error) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return w, nil
				},
			}
			informer = toolscache.NewSharedIndexInformer(&vpnPeerListWatch{lw}, obj, resync, indices)
			return informer
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithCancel(tb.Context())
	if err := c.IndexField(ctx, object, field, extract); err != nil {
		cancel()
		tb.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	tb.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				tb.Error(err)
			}
		case <-time.After(3 * time.Second):
			tb.Error("peer cache did not stop")
		}
	})
	syncCtx, syncCancel := context.WithTimeout(ctx, 5*time.Second)
	defer syncCancel()
	if !c.WaitForCacheSync(syncCtx) {
		tb.Fatal("peer cache did not synchronize")
	}
	return c, informer.GetIndexer()
}

type vpnCachedPeerClient struct {
	client.Client
	cache  cache.Cache
	copied int
}

func (c *vpnCachedPeerClient) List(ctx context.Context, out client.ObjectList, opts ...client.ListOption) error {
	if rows, ok := out.(*sdnv1alpha1.VPNConnectionList); ok {
		if err := c.cache.List(ctx, out, opts...); err != nil {
			return err
		}
		c.copied += len(rows.Items)
		return nil
	}
	return c.Client.List(ctx, out, opts...)
}

func vpnPeerFlood(n int) []sdnv1alpha1.VPNConnection {
	peers := make([]sdnv1alpha1.VPNConnection, n)
	for i := range peers {
		peers[i].ObjectMeta = metav1.ObjectMeta{Namespace: "tenant-a", Name: fmt.Sprintf("peer-%04d", i), ResourceVersion: "1"}
		peers[i].Spec.GatewayRef.Name = "gateway"
		peers[i].Spec.RemoteCIDRs = make([]string, 256)
		for j := range peers[i].Spec.RemoteCIDRs {
			peers[i].Spec.RemoteCIDRs[j] = "203.0.113.0/24"
		}
	}
	return peers
}

func TestVPNPeerQuotaBoundsActualCacheCopies(t *testing.T) {
	peers := vpnPeerFlood(2048)
	cached, index := vpnPeerCache(t, peers)
	c := &vpnCachedPeerClient{cache: cached}
	r := &VPNGatewayReconciler{Client: c}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}}
	conns, err := r.connectionsFor(t.Context(), gw)
	if err != nil {
		t.Fatal(err)
	}
	if c.copied > 17 || len(conns) != 17 {
		t.Fatalf("quota lookup copied %d objects and returned %d peers; want one overflow witness beyond quota16", c.copied, len(conns))
	}
	if reason, err := r.overQuota(t.Context(), gw, conns); err != nil || reason == "" {
		t.Fatalf("truncated peer set was admitted: reason=%q err=%v", reason, err)
	}
	for i := 16; i < len(peers); i++ {
		if err := index.Delete(&peers[i]); err != nil {
			t.Fatal(err)
		}
	}
	c.copied = 0
	conns, err = r.connectionsFor(t.Context(), gw)
	if err != nil || c.copied != 16 || len(conns) != 16 {
		t.Fatalf("fitting peer set did not recover completely: copied=%d peers=%d err=%v", c.copied, len(conns), err)
	}
	for i := range conns {
		if conns[i].Name != fmt.Sprintf("peer-%04d", i) {
			t.Fatalf("fitting set omitted or reordered a peer: %s", conns[i].Name)
		}
	}
}

func TestVPNPeerLookupExcludesTerminatingPeersBeforeLimit(t *testing.T) {
	peers := vpnPeerFlood(2064)
	now := metav1.Now()
	for i := range 2048 {
		peers[i].DeletionTimestamp = &now
		peers[i].Finalizers = []string{"example.invalid/cleanup"}
	}
	cached, index := vpnPeerCache(t, peers)
	c := &vpnCachedPeerClient{cache: cached}
	r := &VPNGatewayReconciler{Client: c}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}}
	conns, err := r.connectionsFor(t.Context(), gw)
	if err != nil || c.copied != 16 || len(conns) != 16 {
		t.Fatalf("terminating peers truncated a fitting set: copied=%d peers=%d err=%v", c.copied, len(conns), err)
	}
	conns[0].Spec.RemoteCIDRs[0] = "192.0.2.0/24"
	stored := &sdnv1alpha1.VPNConnection{}
	if err := cached.Get(t.Context(), client.ObjectKeyFromObject(&conns[0]), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Spec.RemoteCIDRs[0] != "203.0.113.0/24" {
		t.Fatal("peer configuration mutation corrupted the shared cache")
	}
	stored.DeletionTimestamp = &now
	if err := index.Update(stored); err != nil {
		t.Fatal(err)
	}
	c.copied = 0
	conns, err = r.connectionsFor(t.Context(), gw)
	if err != nil || c.copied != 15 || len(conns) != 15 {
		t.Fatalf("termination retained an active index entry: copied=%d peers=%d err=%v", c.copied, len(conns), err)
	}
	stored = conns[0].DeepCopy()
	stored.Spec.GatewayRef.Name = "other-gateway"
	if err := index.Update(stored); err != nil {
		t.Fatal(err)
	}
	conns, err = r.connectionsFor(t.Context(), gw)
	if err != nil || len(conns) != 14 {
		t.Fatalf("retargeting left an old gateway index entry: peers=%d err=%v", len(conns), err)
	}
	gw.Name = "other-gateway"
	conns, err = r.connectionsFor(t.Context(), gw)
	if err != nil || len(conns) != 1 || conns[0].Name != stored.Name {
		t.Fatalf("retargeting did not follow current gateway: peers=%d err=%v", len(conns), err)
	}
}

func TestVPNPeerLookupHonorsConfiguredQuota(t *testing.T) {
	cached, _ := vpnPeerCache(t, vpnPeerFlood(100))
	c := &vpnCachedPeerClient{cache: cached}
	r := &VPNGatewayReconciler{Client: c, Config: VPNGatewayConfig{MaxConnectionsPerGateway: 3}}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}}
	conns, err := r.connectionsFor(t.Context(), gw)
	if err != nil || c.copied != 4 || len(conns) != 4 {
		t.Fatalf("configured quota ignored: copied=%d peers=%d err=%v", c.copied, len(conns), err)
	}
	if reason, err := r.overQuota(t.Context(), gw, conns); err != nil || reason == "" {
		t.Fatalf("configured overflow admitted: reason=%q err=%v", reason, err)
	}
}

func BenchmarkVPNPeerQuotaActualCache(b *testing.B) {
	cached, _ := vpnPeerCache(b, vpnPeerFlood(1024))
	c := &vpnCachedPeerClient{cache: cached}
	r := &VPNGatewayReconciler{Client: c}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway"}}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := r.connectionsFor(b.Context(), gw); err != nil {
			b.Fatal(err)
		}
	}
}
