package claim

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/storage/storagebackend"
)

type firstCommitBarrier struct {
	clientv3.KV
	commits atomic.Int64
	ready   chan struct{}
}

func (b *firstCommitBarrier) Txn(ctx context.Context) clientv3.Txn {
	return &barrierTransaction{Txn: b.KV.Txn(ctx), barrier: b, ctx: ctx}
}

type barrierTransaction struct {
	clientv3.Txn
	barrier *firstCommitBarrier
	ctx     context.Context
}

func (t *barrierTransaction) If(c ...clientv3.Cmp) clientv3.Txn  { t.Txn = t.Txn.If(c...); return t }
func (t *barrierTransaction) Then(o ...clientv3.Op) clientv3.Txn { t.Txn = t.Txn.Then(o...); return t }
func (t *barrierTransaction) Else(o ...clientv3.Op) clientv3.Txn { t.Txn = t.Txn.Else(o...); return t }
func (t *barrierTransaction) Commit() (*clientv3.TxnResponse, error) {
	if n := t.barrier.commits.Add(1); n <= 2 {
		if n == 2 {
			close(t.barrier.ready)
		}
		select {
		case <-t.barrier.ready:
		case <-t.ctx.Done():
			return nil, t.ctx.Err()
		}
	}
	return t.Txn.Commit()
}

func TestEtcdPersistentNICConcurrentDifferentAddresses(t *testing.T) {
	endpoint := os.Getenv("COZYPLANE_ETCD_TEST_ADDR")
	if endpoint == "" {
		t.Skip("requires isolated etcd integration server")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	prefix := fmt.Sprintf("/nic-security-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = client.Delete(c, prefix+"/", clientv3.WithPrefix())
	})
	scheme := runtime.NewScheme()
	install.Install(scheme)
	codec := serializer.NewCodecFactory(scheme).LegacyCodec(sdnv1.SchemeGroupVersion)
	barrier := &firstCommitBarrier{KV: client, ready: make(chan struct{})}
	store := &atomicStorage{Interface: versionedBacking{}, kv: barrier, config: &storagebackend.ConfigForResource{Config: storagebackend.Config{Prefix: prefix, Codec: codec}}, resourcePrefix: "/ports", transformer: keyBoundTransformer{}, twinKey: func(_ context.Context, name string) (string, error) { return "/servicevips/" + name, nil }}
	results := make(chan error, 2)
	for i := range 2 {
		port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(101, fmt.Sprintf("10.0.0.%d", i+2)), UID: types.UID(fmt.Sprintf("claim-%d", i)), Labels: map[string]string{sdnv1.LabelVMName: "vm", sdnv1.LabelVMNIC: "eth0"}}, Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}, PodNamespace: "tenant", IP: fmt.Sprintf("10.0.0.%d", i+2), MAC: fmt.Sprintf("02:00:00:00:00:%02x", i+1)}}
		go func() { results <- store.Create(ctx, "/ports/"+port.Name, port, &sdn.Port{}, 0) }()
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("persistent NIC must have one winner, got %v and %v", first, second)
	}
	loser := first
	if loser == nil {
		loser = second
	}
	if !apierrors.IsAlreadyExists(loser) {
		t.Fatalf("loser must report actual holding Port: %v", loser)
	}
	response, err := client.Get(ctx, prefix+"/ports/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Kvs) != 1 {
		t.Fatal("NIC identity split", len(response.Kvs))
	}
}

func persistentEtcdFixture(t *testing.T) (*atomicStorage, *clientv3.Client) {
	t.Helper()
	endpoint := os.Getenv("COZYPLANE_ETCD_TEST_ADDR")
	if endpoint == "" {
		t.Skip("requires isolated etcd integration server")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	prefix := fmt.Sprintf("/nic-fixture-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = client.Delete(ctx, prefix+"/", clientv3.WithPrefix())
	})
	scheme := runtime.NewScheme()
	install.Install(scheme)
	codec := serializer.NewCodecFactory(scheme).LegacyCodec(sdnv1.SchemeGroupVersion)
	return &atomicStorage{Interface: versionedBacking{}, kv: client, config: &storagebackend.ConfigForResource{Config: storagebackend.Config{Prefix: prefix, Codec: codec}}, resourcePrefix: "/ports", transformer: keyBoundTransformer{}, twinKey: func(_ context.Context, name string) (string, error) { return "/servicevips/" + name, nil }}, client
}

func nicClaim(vni int32, address string) *sdn.Port {
	return &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(vni, address), Labels: map[string]string{sdnv1.LabelVMName: "vm", sdnv1.LabelVMNIC: "0"}}, Spec: sdn.PortSpec{IP: address, MAC: "02:00:00:00:00:01", PodNamespace: "consumer", VPCRef: sdn.VPCRef{Namespace: "owner", Name: "net"}}}
}

func putLegacyNIC(t *testing.T, store *atomicStorage, client *clientv3.Client, p *sdn.Port) {
	t.Helper()
	key := store.config.Prefix + "/ports/" + p.Name
	data, err := runtime.Encode(store.config.Codec, p)
	if err != nil {
		t.Fatal(err)
	}
	data, err = store.transformer.TransformToStorage(t.Context(), data, authenticatedKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Put(t.Context(), key, string(data)); err != nil {
		t.Fatal(err)
	}
}

func TestEtcdPersistentNICPagingLegacyAndDeletion(t *testing.T) {
	store, client := persistentEtcdFixture(t)
	// Lexically early ordinary claims force the holding claim onto page two.
	for i := 0; i < 129; i++ {
		p := nicClaim(101, fmt.Sprintf("10.0.0.%d", i+2))
		p.Labels = nil
		putLegacyNIC(t, store, client, p)
	}
	held := nicClaim(101, "10.0.1.200")
	putLegacyNIC(t, store, client, held)
	request := nicClaim(101, "10.0.2.2")
	err := store.Create(t.Context(), "/ports/"+request.Name, request, &sdn.Port{}, 0)
	status, ok := err.(apierrors.APIStatus)
	if !ok || !apierrors.IsAlreadyExists(err) || status.Status().Details.Name != held.Name {
		t.Fatal("legacy holding claim not returned", err)
	}
	if _, err = client.Delete(t.Context(), store.config.Prefix+"/ports/"+held.Name); err != nil {
		t.Fatal(err)
	}
	if err = store.Create(t.Context(), "/ports/"+request.Name, request, &sdn.Port{}, 0); err != nil {
		t.Fatal("deleted NIC still reserved", err)
	}
	second := nicClaim(101, "10.0.2.3")
	putLegacyNIC(t, store, client, second)
	third := nicClaim(101, "10.0.2.4")
	if err = store.Create(t.Context(), "/ports/"+third.Name, third, &sdn.Port{}, 0); !apierrors.IsInvalid(err) {
		t.Fatal("ambiguous legacy NIC accepted", err)
	}
	response, err := client.Get(t.Context(), store.config.Prefix+"/ports/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Kvs) != 131 {
		t.Fatal("legacy claims changed", len(response.Kvs))
	}
}

func TestEtcdPersistentNICFullIdentityScopes(t *testing.T) {
	store, _ := persistentEtcdFixture(t)
	base := nicClaim(101, "10.0.0.2")
	if err := store.Create(t.Context(), "/ports/"+base.Name, base, &sdn.Port{}, 0); err != nil {
		t.Fatal(err)
	}
	for i, mutate := range []func(*sdn.Port){
		func(p *sdn.Port) { p.Spec.PodNamespace = "other-consumer" },
		func(p *sdn.Port) { p.Spec.VPCRef.Namespace = "other-owner" },
		func(p *sdn.Port) { p.Spec.VPCRef.Name = "other-net" },
		func(p *sdn.Port) { p.Labels[sdnv1.LabelVMName] = "other-vm" },
		func(p *sdn.Port) { p.Labels[sdnv1.LabelVMNIC] = "1" },
	} {
		p := nicClaim(101, fmt.Sprintf("10.0.0.%d", i+3))
		mutate(p)
		if err := store.Create(t.Context(), "/ports/"+p.Name, p, &sdn.Port{}, 0); err != nil {
			t.Fatal("distinct NIC refused", i, err)
		}
	}
	otherVNI := nicClaim(102, "10.0.0.2")
	if err := store.Create(t.Context(), "/ports/"+otherVNI.Name, otherVNI, &sdn.Port{}, 0); err != nil {
		t.Fatal("overlapping VNI refused", err)
	}
}

type beforeCommitKV struct {
	clientv3.KV
	hook    func()
	commits int
}

func (b *beforeCommitKV) Txn(ctx context.Context) clientv3.Txn {
	return &beforeCommitTxn{Txn: b.KV.Txn(ctx), owner: b}
}

type beforeCommitTxn struct {
	clientv3.Txn
	owner *beforeCommitKV
}

func (t *beforeCommitTxn) If(c ...clientv3.Cmp) clientv3.Txn  { t.Txn = t.Txn.If(c...); return t }
func (t *beforeCommitTxn) Then(o ...clientv3.Op) clientv3.Txn { t.Txn = t.Txn.Then(o...); return t }
func (t *beforeCommitTxn) Else(o ...clientv3.Op) clientv3.Txn { t.Txn = t.Txn.Else(o...); return t }
func (t *beforeCommitTxn) Commit() (*clientv3.TxnResponse, error) {
	t.owner.commits++
	if t.owner.commits == 1 {
		t.owner.hook()
	}
	return t.Txn.Commit()
}

func TestEtcdPersistentNICRevisionScope(t *testing.T) {
	for _, sameVNI := range []bool{false, true} {
		t.Run(fmt.Sprint(sameVNI), func(t *testing.T) {
			store, client := persistentEtcdFixture(t)
			vni := int32(102)
			expectedCommits := 1
			if sameVNI {
				vni = 101
				expectedCommits = 2
			}
			other := nicClaim(vni, "10.0.0.3")
			other.Labels = nil
			interleave := &beforeCommitKV{KV: client, hook: func() { putLegacyNIC(t, store, client, other) }}
			store.kv = interleave
			p := nicClaim(101, "10.0.0.2")
			if err := store.Create(t.Context(), "/ports/"+p.Name, p, &sdn.Port{}, 0); err != nil {
				t.Fatal(err)
			}
			if interleave.commits != expectedCommits {
				t.Fatal("incorrect VNI revision scope", interleave.commits, expectedCommits)
			}
		})
	}
}

func TestEtcdPersistentNICReceiveBudget(t *testing.T) {
	store, client := persistentEtcdFixture(t)
	// Legacy direct etcd data can exceed current API metadata limits. Each
	// object fits etcd's default request limit, but the range response does not.
	for i := 0; i < 18; i++ {
		p := nicClaim(101, fmt.Sprintf("10.0.0.%d", i+2))
		p.Labels = nil
		p.Annotations = map[string]string{"legacy": strings.Repeat("x", 1<<20)}
		putLegacyNIC(t, store, client, p)
	}
	bounded, err := newClient(storagebackend.TransportConfig{ServerList: []string{os.Getenv("COZYPLANE_ETCD_TEST_ADDR")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bounded.Close() })
	store.kv = bounded
	p := nicClaim(101, "10.0.1.2")
	err = store.Create(t.Context(), "/ports/"+p.Name, p, &sdn.Port{}, 0)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatal("oversized range not rejected by transport", err)
	}
	result, err := client.Get(t.Context(), store.config.Prefix+"/ports/"+p.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Kvs) != 0 {
		t.Fatal("oversized snapshot created partial claim")
	}
}
