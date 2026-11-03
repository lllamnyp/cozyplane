package claim

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/server/egressselector"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

// Install preserves the existing storage codec, encryption transformer, key
// prefixes, watchers and ordinary operations. Only Create is replaced: both
// claim keys must be absent when the object's key is written. No expiring lock
// or second reservation can outlive, or expire before, an in-flight write.
func Install(ports, vips *genericregistry.Store, getter generic.RESTOptionsGetter) error {
	portOpts, err := getter.GetRESTOptions(sdn.Resource("ports"), ports.NewFunc())
	if err != nil {
		return err
	}
	vipOpts, err := getter.GetRESTOptions(sdn.Resource("servicevips"), vips.NewFunc())
	if err != nil {
		return err
	}
	p, v := portOpts.StorageConfig, vipOpts.StorageConfig
	if p == nil || v == nil {
		return fmt.Errorf("address claims require etcd storage configuration")
	}
	if p.Type != "" && p.Type != "etcd3" || v.Type != "" && v.Type != "etcd3" {
		return fmt.Errorf("address claims require etcd3")
	}
	if p.Prefix != v.Prefix || !reflect.DeepEqual(p.Transport.ServerList, v.Transport.ServerList) ||
		p.Transport.CertFile != v.Transport.CertFile || p.Transport.KeyFile != v.Transport.KeyFile || p.Transport.TrustedCAFile != v.Transport.TrustedCAFile {
		return fmt.Errorf("Port and ServiceVIP claims must use the same etcd backend")
	}
	client, err := newClient(p.Transport)
	if err != nil {
		return err
	}
	for _, pair := range []struct {
		store, twin *genericregistry.Store
		config      *storagebackend.ConfigForResource
	}{{ports, vips, p}, {vips, ports, v}} {
		transformer := pair.config.Transformer
		if transformer == nil {
			transformer = identity.NewEncryptCheckTransformer()
		}
		pair.store.Storage.Storage = &atomicStorage{
			Interface: pair.store.Storage.Storage, kv: client, config: pair.config,
			resourcePrefix: pair.store.KeyRootFunc(context.Background()), transformer: transformer,
			twinKey: pair.twin.KeyFunc,
		}
	}
	previousDestroy := ports.DestroyFunc
	var once sync.Once
	ports.DestroyFunc = func() {
		once.Do(func() {
			_ = client.Close()
			if previousDestroy != nil {
				previousDestroy()
			}
		})
	}
	return nil
}

func newClient(config storagebackend.TransportConfig) (*clientv3.Client, error) {
	tlsInfo := transport.TLSInfo{CertFile: config.CertFile, KeyFile: config.KeyFile, TrustedCAFile: config.TrustedCAFile}
	tlsConfig, err := tlsInfo.ClientConfig()
	if err != nil {
		return nil, err
	}
	if config.CertFile == "" && config.KeyFile == "" && config.TrustedCAFile == "" {
		tlsConfig = nil
	}
	options := []grpc.DialOption{grpc.WithBlock()}
	if config.EgressLookup != nil {
		dial, err := config.EgressLookup(egressselector.Etcd.AsNetworkContext())
		if err != nil {
			return nil, err
		}
		if dial != nil {
			options = append(options, grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
				if strings.Contains(address, "://") {
					endpoint, err := url.Parse(address)
					if err != nil {
						return nil, err
					}
					address = endpoint.Host
				}
				return dial(ctx, "tcp", address)
			}))
		}
	}
	return clientv3.New(clientv3.Config{Endpoints: config.ServerList, TLS: tlsConfig, DialTimeout: 20 * time.Second, DialKeepAliveTime: 30 * time.Second, DialKeepAliveTimeout: 10 * time.Second, DialOptions: options, MaxCallRecvMsgSize: claimMaxReceiveBytes})
}

type atomicStorage struct {
	storage.Interface
	kv             clientv3.KV
	config         *storagebackend.ConfigForResource
	resourcePrefix string
	transformer    value.Transformer
	twinKey        func(context.Context, string) (string, error)
}

type authenticatedKey string

func (key authenticatedKey) AuthenticatedData() []byte { return []byte(key) }

func (s *atomicStorage) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	var twinName string
	switch claim := obj.(type) {
	case *sdn.Port:
		vni, _, valid := sdn.ParseClaim(sdn.ClaimPrefixPort, claim.Name)
		if !valid {
			return fmt.Errorf("invalid Port claim")
		}
		twinName = sdn.ServiceVIPName(vni, claim.Spec.IP)
	case *sdn.ServiceVIP:
		vni, _, valid := sdn.ParseClaim(sdn.ClaimPrefixServiceVIP, claim.Name)
		if !valid {
			return fmt.Errorf("invalid ServiceVIP claim")
		}
		twinName = sdn.PortName(vni, claim.Spec.IP)
	default:
		return fmt.Errorf("unsupported address claim type %T", obj)
	}
	if ttl != 0 {
		return fmt.Errorf("address claims cannot expire")
	}
	prepared, err := storage.PrepareKey(s.resourcePrefix, key, false)
	if err != nil {
		return err
	}
	twin, err := s.twinKey(ctx, twinName)
	if err != nil {
		return err
	}
	prefix := strings.TrimSuffix(s.config.Prefix, "/") + "/"
	prepared = prefix + strings.TrimPrefix(prepared, "/")
	twin = prefix + strings.TrimPrefix(twin, "/")
	versioner := s.Versioner()
	if rv, err := versioner.ObjectResourceVersion(obj); err != nil {
		return err
	} else if rv != 0 {
		return storage.ErrResourceVersionSetOnCreate
	}
	if err := versioner.PrepareObjectForStorage(obj); err != nil {
		return err
	}
	data, err := runtime.Encode(s.config.Codec, obj)
	if err != nil {
		return err
	}
	encrypted, err := s.transformer.TransformToStorage(ctx, data, authenticatedKey(prepared))
	if err != nil {
		return storage.NewInternalError(err)
	}
	for attempt := 0; attempt < persistentCreateAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		checks := []clientv3.Cmp{clientv3.Compare(clientv3.Version(prepared), "=", 0), clientv3.Compare(clientv3.Version(twin), "=", 0)}
		if port, ok := obj.(*sdn.Port); ok && IsPersistent(port) {
			guard, err := s.persistentGuard(ctx, prepared, port)
			if err != nil {
				return err
			}
			checks = append(checks, guard)
		}
		response, err := s.kv.Txn(ctx).If(checks...).Then(clientv3.OpPut(prepared, string(encrypted))).Else(clientv3.OpGet(prepared), clientv3.OpGet(twin)).Commit()
		if err != nil {
			return err
		}
		if response.Succeeded {
			if out != nil {
				return etcd3.NewDefaultDecoder(s.config.Codec, versioner).Decode(data, out, response.Header.Revision)
			}
			return nil
		}
		for _, result := range response.Responses {
			if got := result.GetResponseRange(); got != nil && len(got.Kvs) != 0 {
				return storage.NewKeyExistsError(prepared, 0)
			}
		}
	}
	return persistentContention()
}
