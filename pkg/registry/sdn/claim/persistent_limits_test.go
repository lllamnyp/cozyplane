package claim

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/storage/storagebackend"
)

type persistentFakeKV struct {
	clientv3.KV
	page           *clientv3.GetResponse
	reads, commits int
}

func (f *persistentFakeKV) Get(ctx context.Context, key string, options ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	f.reads++
	return f.page, nil
}
func (f *persistentFakeKV) Txn(ctx context.Context) clientv3.Txn {
	return &persistentDeniedTxn{fake: f}
}

type persistentDeniedTxn struct{ fake *persistentFakeKV }

func (t *persistentDeniedTxn) If(...clientv3.Cmp) clientv3.Txn  { return t }
func (t *persistentDeniedTxn) Then(...clientv3.Op) clientv3.Txn { return t }
func (t *persistentDeniedTxn) Else(...clientv3.Op) clientv3.Txn { return t }
func (t *persistentDeniedTxn) Commit() (*clientv3.TxnResponse, error) {
	t.fake.commits++
	return &clientv3.TxnResponse{Header: &pb.ResponseHeader{Revision: 2}}, nil
}

func persistentFakeStore(fake *persistentFakeKV) *atomicStorage {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return &atomicStorage{Interface: versionedBacking{}, kv: fake, config: &storagebackend.ConfigForResource{Config: storagebackend.Config{Prefix: "/test", Codec: serializer.NewCodecFactory(scheme).LegacyCodec(sdnv1.SchemeGroupVersion)}}, resourcePrefix: "/ports", transformer: keyBoundTransformer{}, twinKey: func(_ context.Context, name string) (string, error) { return "/servicevips/" + name, nil }}
}

func TestPersistentNICContentionAndCancellationBounded(t *testing.T) {
	fake := &persistentFakeKV{page: &clientv3.GetResponse{Header: &pb.ResponseHeader{Revision: 1}}}
	store := persistentFakeStore(fake)
	p := nicClaim(101, "10.0.0.2")
	err := store.Create(t.Context(), "/ports/"+p.Name, p, &sdn.Port{}, 0)
	if !apierrors.IsTimeout(err) || fake.reads != 8 || fake.commits != 8 {
		t.Fatal("unbounded or wrong contention behavior", fake.reads, fake.commits, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = store.Create(ctx, "/ports/"+p.Name, p, &sdn.Port{}, 0); err != context.Canceled || fake.reads != 8 || fake.commits != 8 {
		t.Fatal("canceled allocation accessed etcd", err)
	}
}

func TestPersistentNICIncompleteSnapshotNeverCreates(t *testing.T) {
	for name, page := range map[string]*clientv3.GetResponse{
		"nil":                  nil,
		"no header":            {},
		"empty continuation":   {Header: &pb.ResponseHeader{Revision: 1}, More: true},
		"outside VNI":          {Header: &pb.ResponseHeader{Revision: 1}, Kvs: []*mvccpb.KeyValue{{Key: []byte("/test/ports/v102.10.0.0.2")}}},
		"unauthenticated data": {Header: &pb.ResponseHeader{Revision: 1}, Kvs: []*mvccpb.KeyValue{{Key: []byte("/test/ports/v101.10.0.0.2"), Value: []byte("invalid")}}},
		"oversized page":       {Header: &pb.ResponseHeader{Revision: 1}, Kvs: make([]*mvccpb.KeyValue, persistentPageSize+1)},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &persistentFakeKV{page: page}
			store := persistentFakeStore(fake)
			p := nicClaim(101, "10.0.0.2")
			if err := store.Create(t.Context(), "/ports/"+p.Name, p, &sdn.Port{}, 0); err == nil || fake.commits != 0 {
				t.Fatal("incomplete scan wrote claim", err, fake.commits)
			}
		})
	}
}
