package claim

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/value"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

type versionedBacking struct{ storage.Interface }

func (versionedBacking) Versioner() storage.Versioner { return storage.APIObjectVersioner{} }

// Test encryption checks the same authenticated key as the stock etcd store.
type keyBoundTransformer struct{}

func (keyBoundTransformer) TransformToStorage(_ context.Context, data []byte, ctx value.Context) ([]byte, error) {
	return append(append(ctx.AuthenticatedData(), '\n'), data...), nil
}
func (keyBoundTransformer) TransformFromStorage(_ context.Context, data []byte, ctx value.Context) ([]byte, bool, error) {
	prefix := string(ctx.AuthenticatedData()) + "\n"
	if !strings.HasPrefix(string(data), prefix) {
		return nil, false, fmt.Errorf("wrong authenticated key")
	}
	return data[len(prefix):], false, nil
}

func TestEtcdConcurrentCrossKindClaims(t *testing.T) {
	endpoint := os.Getenv("COZYPLANE_ETCD_TEST_ADDR")
	if endpoint == "" {
		t.Skip("isolated etcd integration test; set COZYPLANE_ETCD_TEST_ADDR")
	}
	scheme := runtime.NewScheme()
	install.Install(scheme)
	codec := serializer.NewCodecFactory(scheme).LegacyCodec(sdnv1alpha1.SchemeGroupVersion)
	clients := make([]*clientv3.Client, 2)
	for i := range clients {
		var err error
		clients[i], err = clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = clients[i].Close() })
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prefix := fmt.Sprintf("/security-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = clients[0].Delete(cleanup, prefix+"/", clientv3.WithPrefix())
	})
	makeStore := func(client *clientv3.Client, resource, twin string) *atomicStorage {
		return &atomicStorage{Interface: versionedBacking{}, kv: client,
			config:         &storagebackend.ConfigForResource{Config: storagebackend.Config{Prefix: prefix, Codec: codec}},
			resourcePrefix: "/" + resource, transformer: keyBoundTransformer{},
			twinKey: func(_ context.Context, name string) (string, error) { return "/" + twin + "/" + name, nil },
		}
	}
	portStore := makeStore(clients[0], "ports", "servicevips")
	vipStore := makeStore(clients[1], "servicevips", "ports")
	for i := 2; i < 66; i++ {
		ip := fmt.Sprintf("10.10.0.%d", i)
		port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(42, ip), UID: types.UID(fmt.Sprintf("port-%d", i))}, Spec: sdn.PortSpec{IP: ip}}
		vip := &sdn.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(42, ip), UID: types.UID(fmt.Sprintf("vip-%d", i))}, Spec: sdn.ServiceVIPSpec{IP: ip}}
		start := make(chan struct{})
		var workers sync.WaitGroup
		errs := make([]error, 2)
		outPort, outVIP := &sdn.Port{}, &sdn.ServiceVIP{}
		workers.Go(func() { <-start; errs[0] = portStore.Create(ctx, "/ports/"+port.Name, port, outPort, 0) })
		workers.Go(func() { <-start; errs[1] = vipStore.Create(ctx, "/servicevips/"+vip.Name, vip, outVIP, 0) })
		close(start)
		workers.Wait()
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("expected one winner at %s, got %v", ip, errs)
		}
		loser, out, store, name := errs[1], runtime.Object(outPort), portStore, port.Name
		if errs[0] != nil {
			loser, out, store, name = errs[0], outVIP, vipStore, vip.Name
		}
		if !storage.IsExist(loser) {
			t.Fatalf("wrong conflict result: %v", loser)
		}
		key := prefix + store.resourcePrefix + "/" + name
		response, err := clients[0].Get(ctx, key)
		if err != nil || len(response.Kvs) != 1 {
			t.Fatalf("winner not persisted: %v", err)
		}
		data, _, err := store.transformer.TransformFromStorage(ctx, response.Kvs[0].Value, authenticatedKey(key))
		if err != nil {
			t.Fatal(err)
		}
		persisted := out.DeepCopyObject()
		if err := runtime.DecodeInto(codec, data, persisted); err != nil {
			t.Fatal(err)
		}
		if rv, err := store.Versioner().ObjectResourceVersion(out); err != nil || rv == 0 {
			t.Fatalf("missing output resourceVersion: %v", err)
		}
		if _, err := clients[0].Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if errs[0] != nil {
			if err := portStore.Create(ctx, "/ports/"+port.Name, port, outPort, 0); err != nil {
				t.Fatalf("cannot reuse deleted claim: %v", err)
			}
		} else if err := vipStore.Create(ctx, "/servicevips/"+vip.Name, vip, outVIP, 0); err != nil {
			t.Fatalf("cannot reuse deleted claim: %v", err)
		}
	}
}
