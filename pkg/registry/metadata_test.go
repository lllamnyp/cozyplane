package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	"github.com/lllamnyp/cozyplane/pkg/registry"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/claim"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/floatingip"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/hostfirewall"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/port"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/securitygroup"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/servicevip"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpc"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcbinding"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcgateway"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcpeering"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpnconnection"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpngateway"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	request "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"
)

// Only persistence is substituted: tests run the actual generic Store and
// production NewREST factory, including BeforeCreate/BeforeUpdate and hooks.
type metadataStorage struct {
	storage.Interface
	stored runtime.Object
	writes int
}

func (*metadataStorage) Versioner() storage.Versioner { return storage.APIObjectVersioner{} }
func (*metadataStorage) ReadinessCheck() error        { return nil }
func (s *metadataStorage) Create(_ context.Context, _ string, obj, out runtime.Object, _ uint64) error {
	s.stored = obj.DeepCopyObject()
	_ = s.Versioner().UpdateObject(s.stored, 1)
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(s.stored.DeepCopyObject()).Elem())
	s.writes++
	return nil
}
func (s *metadataStorage) GuaranteedUpdate(_ context.Context, _ string, out runtime.Object, _ bool, _ *storage.Preconditions, update storage.UpdateFunc, _ runtime.Object) error {
	next, _, err := update(s.stored.DeepCopyObject(), storage.ResponseMeta{ResourceVersion: 1})
	if err != nil {
		return err
	}
	s.stored = next.DeepCopyObject()
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(s.stored.DeepCopyObject()).Elem())
	s.writes++
	return nil
}

type metadataOptions struct{ backing *metadataStorage }

func (o metadataOptions) GetRESTOptions(resource schema.GroupResource, _ runtime.Object) (generic.RESTOptions, error) {
	return generic.RESTOptions{
		ResourcePrefix: resource.Resource,
		StorageConfig:  &storagebackend.ConfigForResource{},
		Decorator: func(_ *storagebackend.ConfigForResource, _ string, _ func(runtime.Object) (string, error), _, _ func() runtime.Object, _ storage.AttrFunc, _ storage.IndexerFuncs, _ *cache.Indexers) (storage.Interface, factory.DestroyFunc, error) {
			return o.backing, func() {}, nil
		},
	}, nil
}

func metadataScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return scheme
}

func invalidMetadataVPC() *sdn.VPC {
	obj := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Labels: map[string]string{}}, Spec: sdn.VPCSpec{CIDRs: []string{"192.0.2.0/24"}}}
	for i := 0; i < 1024; i++ {
		obj.Labels[fmt.Sprintf("invalid key %04d", i)] = "value"
	}
	return obj
}

func metadataStatus(t testing.TB, err error) []byte {
	t.Helper()
	status, ok := err.(apierrors.APIStatus)
	if !ok || !apierrors.IsInvalid(err) {
		t.Fatalf("expected Invalid APIStatus, got %T", err)
	}
	raw, marshalErr := json.Marshal(status.Status())
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	return raw
}

func TestMetadataActualCreateBoundsDiagnostics(t *testing.T) {
	backing := &metadataStorage{}
	rest, _, err := vpc.NewREST(metadataScheme(), metadataOptions{backing}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rest.Destroy)
	ctx := request.WithNamespace(t.Context(), "tenant-a")
	_, err = rest.Create(ctx, invalidMetadataVPC(), nil, &metav1.CreateOptions{})
	raw := metadataStatus(t, err)
	status := err.(apierrors.APIStatus).Status()
	if len(status.Details.Causes) != 1 || len(raw) > 2048 || backing.writes != 0 {
		t.Fatalf("metadata rejection: %d causes, %d response bytes, %d writes", len(status.Details.Causes), len(raw), backing.writes)
	}
}

func BenchmarkMetadataActualCreateDiagnostics(b *testing.B) {
	rest, _, err := vpc.NewREST(metadataScheme(), metadataOptions{&metadataStorage{}}, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(rest.Destroy)
	obj := invalidMetadataVPC()
	ctx := request.WithNamespace(b.Context(), "tenant-a")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rest.Create(ctx, obj, nil, &metav1.CreateOptions{})
		_ = metadataStatus(b, err)
	}
}

type metadataFactory func(*runtime.Scheme, generic.RESTOptionsGetter) (*registry.REST, rest.Updater, error)

func metadataFactoryWithStatus[S rest.Updater](newREST func(*runtime.Scheme, generic.RESTOptionsGetter) (*registry.REST, S, error)) metadataFactory {
	return func(scheme *runtime.Scheme, options generic.RESTOptionsGetter) (*registry.REST, rest.Updater, error) {
		main, status, err := newREST(scheme, options)
		return main, status, err
	}
}

func metadataFactories() map[string]metadataFactory {
	return map[string]metadataFactory{
		"vpc": metadataFactoryWithStatus(func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, *vpc.StatusREST, error) {
			main, status, err := vpc.NewREST(s, o, nil)
			if main == nil {
				return nil, status, err
			}
			return main.REST, status, err
		}),
		"floatingip":   metadataFactoryWithStatus(floatingip.NewREST),
		"hostfirewall": metadataFactoryWithStatus(hostfirewall.NewREST),
		"securitygroup": metadataFactoryWithStatus(func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, *securitygroup.StatusREST, error) {
			main, status, err := securitygroup.NewREST(s, o, nil)
			if main == nil {
				return nil, status, err
			}
			return main.REST, status, err
		}),
		"vpcgateway": metadataFactoryWithStatus(func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, *vpcgateway.StatusREST, error) {
			main, status, err := vpcgateway.NewREST(s, o, nil)
			if main == nil {
				return nil, status, err
			}
			return main.REST, status, err
		}),
		"vpnconnection": metadataFactoryWithStatus(vpnconnection.NewREST),
		"vpngateway":    metadataFactoryWithStatus(vpngateway.NewREST),
		"vpcbinding": func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, rest.Updater, error) {
			main, err := vpcbinding.NewREST(s, o, nil)
			return main, nil, err
		},
		"vpcpeering": metadataFactoryWithStatus(func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, *vpcpeering.StatusREST, error) {
			main, status, err := vpcpeering.NewREST(s, o, nil)
			if main == nil {
				return nil, status, err
			}
			return main.REST, status, err
		}),
		"port": metadataFactoryWithStatus(func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, *port.StatusREST, error) {
			return port.NewREST(s, o, &claim.Twin{})
		}),
		"servicevip": metadataFactoryWithStatus(func(s *runtime.Scheme, o generic.RESTOptionsGetter) (*registry.REST, *servicevip.StatusREST, error) {
			return servicevip.NewREST(s, o, &claim.Twin{})
		}),
	}
}

func assertMetadataRejected(t *testing.T, err error, backing *metadataStorage) {
	t.Helper()
	raw := metadataStatus(t, err)
	status := err.(apierrors.APIStatus).Status()
	if status.Code != 422 || len(status.Details.Causes) != 1 || !strings.HasPrefix(status.Details.Causes[0].Field, "metadata.") || len(raw) > 2048 || strings.Contains(string(raw), "input-canary") || backing.writes != 0 {
		t.Fatalf("unbounded/incorrect rejection: %d causes, %d bytes, %d writes", len(status.Details.Causes), len(raw), backing.writes)
	}
}

func TestMetadataAllActualStoresAndStatusRejectBeforePersistence(t *testing.T) {
	for name, newREST := range metadataFactories() {
		t.Run(name, func(t *testing.T) {
			backing := &metadataStorage{}
			main, status, err := newREST(metadataScheme(), metadataOptions{backing})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(main.Destroy)
			ctx := request.WithNamespace(t.Context(), "tenant-a")
			if !main.CreateStrategy.NamespaceScoped() {
				ctx = request.WithNamespace(t.Context(), "")
			}
			obj := main.New()
			m, _ := meta.Accessor(obj)
			m.SetName("object")
			m.SetLabels(invalidMetadataVPC().Labels)
			_, err = main.Create(ctx, obj.DeepCopyObject(), nil, &metav1.CreateOptions{})
			assertMetadataRejected(t, err, backing)
			m.SetResourceVersion("1")
			backing.stored = obj.DeepCopyObject()
			oldMeta, _ := meta.Accessor(backing.stored)
			oldMeta.SetLabels(nil)
			_, _, err = main.Update(ctx, "object", rest.DefaultUpdatedObjectInfo(obj.DeepCopyObject()), nil, nil, false, &metav1.UpdateOptions{})
			assertMetadataRejected(t, err, backing)
			if status != nil {
				_, _, err = status.Update(ctx, "object", rest.DefaultUpdatedObjectInfo(obj.DeepCopyObject()), nil, nil, false, &metav1.UpdateOptions{})
				assertMetadataRejected(t, err, backing)
			}
		})
	}
}

func TestMetadataCollectionDiagnosticsAndRecovery(t *testing.T) {
	canary := "input-canary-" + strings.Repeat("a", 1<<20)
	controller := true
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: "pod", UID: "owner", Controller: &controller}
	mutations := map[string]func(*metav1.ObjectMeta){
		"label key":   func(m *metav1.ObjectMeta) { m.Labels = map[string]string{canary: "value"} },
		"label value": func(m *metav1.ObjectMeta) { m.Labels = map[string]string{"key": canary} },
		"annotations": func(m *metav1.ObjectMeta) {
			m.Annotations = map[string]string{}
			for i := 0; i < 1024; i++ {
				m.Annotations[fmt.Sprintf("bad key %d", i)] = "value"
			}
		},
		"annotation key":   func(m *metav1.ObjectMeta) { m.Annotations = map[string]string{canary: "value"} },
		"annotation bytes": func(m *metav1.ObjectMeta) { m.Annotations = map[string]string{"example.invalid/key": canary} },
		"finalizers": func(m *metav1.ObjectMeta) {
			for i := 0; i < 1024; i++ {
				m.Finalizers = append(m.Finalizers, fmt.Sprintf("bad finalizer %d", i))
			}
		},
		"finalizer value": func(m *metav1.ObjectMeta) { m.Finalizers = []string{canary} },
		"conflicting deletion finalizers": func(m *metav1.ObjectMeta) {
			m.Finalizers = []string{metav1.FinalizerOrphanDependents, metav1.FinalizerDeleteDependents}
		},
		"owner references": func(m *metav1.ObjectMeta) { m.OwnerReferences = make([]metav1.OwnerReference, 1024) },
		"multiple controllers": func(m *metav1.ObjectMeta) {
			for i := 0; i < 1024; i++ {
				ref := owner
				ref.Name = fmt.Sprintf("pod-%d", i)
				m.OwnerReferences = append(m.OwnerReferences, ref)
			}
		},
		"owner diagnostic": func(m *metav1.ObjectMeta) {
			ref := owner
			ref.Kind = "Event"
			ref.Name = canary
			m.OwnerReferences = []metav1.OwnerReference{ref}
		},
		"managed fields": func(m *metav1.ObjectMeta) { m.ManagedFields = make([]metav1.ManagedFieldsEntry, 1024) },
		"managed field manager": func(m *metav1.ObjectMeta) {
			m.ManagedFields = []metav1.ManagedFieldsEntry{{Operation: metav1.ManagedFieldsOperationUpdate, Manager: strings.Repeat("\x00", 1<<20)}}
		},
		"late finalizer": func(m *metav1.ObjectMeta) {
			for i := 0; i < 1024; i++ {
				m.Finalizers = append(m.Finalizers, fmt.Sprintf("example.invalid/finalizer-%d", i))
			}
			m.Finalizers[1023] = "invalid finalizer"
		},
		"late owner": func(m *metav1.ObjectMeta) {
			for i := 0; i < 1024; i++ {
				ref := owner
				ref.Controller = nil
				m.OwnerReferences = append(m.OwnerReferences, ref)
			}
			m.OwnerReferences[1023].Name = ""
		},
		"late managed field": func(m *metav1.ObjectMeta) {
			for i := 0; i < 1024; i++ {
				m.ManagedFields = append(m.ManagedFields, metav1.ManagedFieldsEntry{Operation: metav1.ManagedFieldsOperationUpdate, Manager: "manager"})
			}
			m.ManagedFields[1023].Operation = "invalid"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			backing := &metadataStorage{}
			main, status, err := vpc.NewREST(metadataScheme(), metadataOptions{backing}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(main.Destroy)
			ctx := request.WithNamespace(t.Context(), "tenant-a")
			valid := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Namespace: "tenant-a", ResourceVersion: "1"}, Spec: sdn.VPCSpec{CIDRs: []string{"192.0.2.0/24"}}}
			bad := valid.DeepCopy()
			mutate(&bad.ObjectMeta)
			_, err = main.Create(ctx, bad.DeepCopy(), nil, &metav1.CreateOptions{})
			assertMetadataRejected(t, err, backing)
			backing.stored = valid.DeepCopy()
			_, _, err = main.Update(ctx, "vpc", rest.DefaultUpdatedObjectInfo(bad.DeepCopy()), nil, nil, false, &metav1.UpdateOptions{})
			assertMetadataRejected(t, err, backing)
			_, _, err = status.Update(ctx, "vpc", rest.DefaultUpdatedObjectInfo(bad.DeepCopy()), nil, nil, false, &metav1.UpdateOptions{})
			assertMetadataRejected(t, err, backing)
			_, err = main.Create(ctx, valid.DeepCopy(), nil, &metav1.CreateOptions{})
			if err != nil || backing.writes != 1 {
				t.Fatalf("valid recovery failed: %v, %d writes", err, backing.writes)
			}
		})
	}
}

func TestMetadataValidCollectionsAndDefaultsPreserved(t *testing.T) {
	backing := &metadataStorage{}
	main, status, err := vpc.NewREST(metadataScheme(), metadataOptions{backing}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(main.Destroy)
	ctx := request.WithNamespace(t.Context(), "tenant-a")
	controller := true
	obj := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{GenerateName: "vpc-", Labels: map[string]string{}, Annotations: map[string]string{"example.invalid/key": strings.Repeat("a", 256*1024-len("example.invalid/key"))}, Finalizers: []string{metav1.FinalizerDeleteDependents}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "pod", UID: types.UID("owner"), Controller: &controller}}, ManagedFields: []metav1.ManagedFieldsEntry{{Operation: metav1.ManagedFieldsOperationUpdate, Manager: strings.Repeat("a", 128), FieldsType: "FieldsV1"}}}, Spec: sdn.VPCSpec{CIDRs: []string{"192.0.2.0/24"}}}
	for i := 0; i < 1024; i++ {
		obj.Labels[fmt.Sprintf("example.invalid/key-%d", i)] = "value"
	}
	created, err := main.Create(ctx, obj, nil, &metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stored := created.(*sdn.VPC)
	if stored.Namespace != "tenant-a" || !strings.HasPrefix(stored.Name, "vpc-") || len(stored.Labels) != 1024 || stored.Annotations["example.invalid/key"] != obj.Annotations["example.invalid/key"] || stored.UID == "" {
		t.Fatal("metadata/defaults changed")
	}
	updated := stored.DeepCopy()
	updated.Namespace = ""
	updated.UID = ""
	updated.Generation = -1 // BeforeUpdate restores these system fields.
	if _, _, err = main.Update(ctx, stored.Name, rest.DefaultUpdatedObjectInfo(updated), nil, nil, false, &metav1.UpdateOptions{}); err != nil {
		t.Fatal("valid update rejected", err)
	}
	if _, _, err = status.Update(ctx, stored.Name, rest.DefaultUpdatedObjectInfo(stored.DeepCopy()), nil, nil, false, &metav1.UpdateOptions{}); err != nil {
		t.Fatal("valid status update rejected", err)
	}
}

func TestMetadataPreservesActualCrossKindClaimHooks(t *testing.T) {
	for _, kind := range []string{"port", "servicevip"} {
		t.Run(kind, func(t *testing.T) {
			calls, taken := 0, true
			twin := &claim.Twin{Exists: func(context.Context, string) (bool, error) { calls++; return taken, nil }}
			backing := &metadataStorage{}
			var main *registry.REST
			var err error
			var obj runtime.Object
			if kind == "port" {
				main, _, err = port.NewREST(metadataScheme(), metadataOptions{backing}, twin)
				obj = &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(142, "192.0.2.2")}, Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "tenant-a", Name: "vpc"}, IP: "192.0.2.2"}}
			} else {
				main, _, err = servicevip.NewREST(metadataScheme(), metadataOptions{backing}, twin)
				obj = &sdn.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(142, "192.0.2.2")}, Spec: sdn.ServiceVIPSpec{VPCRef: sdn.VPCRef{Namespace: "tenant-a", Name: "vpc"}, IP: "192.0.2.2"}}
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(main.Destroy)
			ctx := request.WithNamespace(t.Context(), "tenant-a")
			metadata, _ := meta.Accessor(obj)
			metadata.SetLabels(invalidMetadataVPC().Labels)
			_, err = main.Create(ctx, obj.DeepCopyObject(), nil, &metav1.CreateOptions{})
			assertMetadataRejected(t, err, backing)
			if calls != 0 {
				t.Fatal("malformed metadata reached twin lookup")
			}
			metadata.SetLabels(nil)
			_, err = main.Create(ctx, obj.DeepCopyObject(), nil, &metav1.CreateOptions{})
			if !apierrors.IsConflict(err) || calls != 1 || backing.writes != 0 {
				t.Fatalf("claim hook lost: err=%v, calls=%d, writes=%d", err, calls, backing.writes)
			}
			taken = false
			_, err = main.Create(ctx, obj.DeepCopyObject(), nil, &metav1.CreateOptions{})
			if err != nil || calls != 2 || backing.writes != 1 {
				t.Fatalf("free claim recovery failed: err=%v, calls=%d, writes=%d", err, calls, backing.writes)
			}
		})
	}
}

func TestMetadataPreservesTransactionFinishHooks(t *testing.T) {
	backing := &metadataStorage{}
	main, _, err := vpc.NewREST(metadataScheme(), metadataOptions{backing}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(main.Destroy)
	createCalls, updateCalls := 0, 0
	var createFinishes, updateFinishes []bool
	var reject error
	main.BeginCreate = func(context.Context, runtime.Object, *metav1.CreateOptions) (genericregistry.FinishFunc, error) {
		createCalls++
		if reject != nil {
			return nil, reject
		}
		return func(_ context.Context, ok bool) { createFinishes = append(createFinishes, ok) }, nil
	}
	main.BeginUpdate = func(context.Context, runtime.Object, runtime.Object, *metav1.UpdateOptions) (genericregistry.FinishFunc, error) {
		updateCalls++
		return func(_ context.Context, ok bool) { updateFinishes = append(updateFinishes, ok) }, nil
	}
	registry.InstallMetadataValidation(main.Store)
	ctx := request.WithNamespace(t.Context(), "tenant-a")
	obj := invalidMetadataVPC()
	_, err = main.Create(ctx, obj.DeepCopy(), nil, &metav1.CreateOptions{})
	assertMetadataRejected(t, err, backing)
	if createCalls != 0 {
		t.Fatal("invalid metadata invoked wrapped transaction")
	}
	obj.Labels = nil
	obj.Spec.CIDRs = []string{"invalid"}
	_, err = main.Create(ctx, obj.DeepCopy(), nil, &metav1.CreateOptions{})
	if !apierrors.IsInvalid(err) || !reflect.DeepEqual(createFinishes, []bool{false}) {
		t.Fatal("failed create not reverted", createFinishes)
	}
	obj.Spec.CIDRs = []string{"192.0.2.0/24"}
	_, err = main.Create(ctx, obj.DeepCopy(), nil, &metav1.CreateOptions{})
	if err != nil || !reflect.DeepEqual(createFinishes, []bool{false, true}) {
		t.Fatal("successful create not committed", err, createFinishes)
	}
	updated := backing.stored.(*sdn.VPC).DeepCopy()
	updated.Labels = invalidMetadataVPC().Labels
	_, _, err = main.Update(ctx, updated.Name, rest.DefaultUpdatedObjectInfo(updated.DeepCopy()), nil, nil, false, &metav1.UpdateOptions{})
	if !apierrors.IsInvalid(err) || updateCalls != 0 {
		t.Fatal("invalid metadata invoked wrapped update", err)
	}
	updated.Labels = nil
	updated.Spec.CIDRs = []string{"invalid"}
	_, _, err = main.Update(ctx, updated.Name, rest.DefaultUpdatedObjectInfo(updated.DeepCopy()), nil, nil, false, &metav1.UpdateOptions{})
	if !apierrors.IsInvalid(err) || !reflect.DeepEqual(updateFinishes, []bool{false}) {
		t.Fatal("failed update not reverted", updateFinishes)
	}
	updated.Spec.CIDRs = []string{"192.0.2.0/24"}
	_, _, err = main.Update(ctx, updated.Name, rest.DefaultUpdatedObjectInfo(updated.DeepCopy()), nil, nil, false, &metav1.UpdateOptions{})
	if err != nil || !reflect.DeepEqual(updateFinishes, []bool{false, true}) {
		t.Fatal("successful update not committed", err, updateFinishes)
	}
	reject = errors.New("transaction unavailable")
	_, err = main.Create(ctx, obj.DeepCopy(), nil, &metav1.CreateOptions{})
	if !errors.Is(err, reject) || len(createFinishes) != 2 {
		t.Fatal("hook error/finish changed", err, createFinishes)
	}
}

func TestMetadataQualifiedNameAndValueBoundaries(t *testing.T) {
	prefix := strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 61)
	key := prefix + "/" + strings.Repeat("a", 63)
	if len(key) != 317 {
		t.Fatal("invalid boundary fixture")
	}
	backing := &metadataStorage{}
	main, _, err := vpc.NewREST(metadataScheme(), metadataOptions{backing}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(main.Destroy)
	ctx := request.WithNamespace(t.Context(), "tenant-a")
	obj := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc", Labels: map[string]string{key: strings.Repeat("v", 63)}, Annotations: map[string]string{strings.ToUpper(key): "value"}, Finalizers: []string{key}}, Spec: sdn.VPCSpec{CIDRs: []string{"192.0.2.0/24"}}}
	if _, err = main.Create(ctx, obj.DeepCopy(), nil, &metav1.CreateOptions{}); err != nil {
		t.Fatal("valid Kubernetes maximum rejected", err)
	}
	for _, mutate := range []func(*sdn.VPC){
		func(obj *sdn.VPC) { obj.Labels = map[string]string{key + "a": "value"} },
		func(obj *sdn.VPC) { obj.Labels[key] = strings.Repeat("v", 64) },
		func(obj *sdn.VPC) { obj.Annotations = map[string]string{key + "a": "value"} },
		func(obj *sdn.VPC) { obj.Finalizers = []string{key + "a"} },
	} {
		bad := obj.DeepCopy()
		mutate(bad)
		backing.writes = 0
		_, err = main.Create(ctx, bad, nil, &metav1.CreateOptions{})
		assertMetadataRejected(t, err, backing)
	}
}
