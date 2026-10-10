package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	filters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	request "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	basecompatibility "k8s.io/component-base/compatibility"
)

type optionStorage struct {
	calls   int
	manager string
}

func (*optionStorage) New() runtime.Object { return &sdn.VPC{} }
func (s *optionStorage) Create(_ context.Context, _ runtime.Object, _ rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	s.calls++
	s.manager = options.FieldManager
	return nil, apierrors.NewBadRequest("storage reached")
}

func (s *optionStorage) Update(context.Context, string, rest.UpdatedObjectInfo, rest.ValidateObjectFunc, rest.ValidateObjectUpdateFunc, bool, *metav1.UpdateOptions) (runtime.Object, bool, error) {
	s.calls++
	return nil, false, apierrors.NewBadRequest("storage reached")
}
func (s *optionStorage) Get(context.Context, string, *metav1.GetOptions) (runtime.Object, error) {
	s.calls++
	return nil, apierrors.NewBadRequest("storage reached")
}

func optionScope() *handlers.RequestScope {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	scheme.AddUnversionedTypes(schema.GroupVersion{Version: "v1"}, &metav1.Status{})
	scope := &handlers.RequestScope{
		Namer:      handlers.ContextBasedNaming{Namer: meta.NewAccessor()},
		Serializer: JSONCodecFactory{serializer.NewCodecFactory(scheme)},
		Creater:    scheme, Convertor: scheme, Defaulter: scheme, Typer: scheme, UnsafeConvertor: scheme,
		Resource: sdnv1alpha1.SchemeGroupVersion.WithResource("vpcs"), Kind: sdnv1alpha1.SchemeGroupVersion.WithKind("VPC"),
		MetaGroupVersion: metav1.SchemeGroupVersion, HubGroupVersion: sdn.SchemeGroupVersion, MaxRequestBodyBytes: 3 << 20,
	}
	manager, err := managedfields.NewDefaultFieldManager(managedfields.NewDeducedTypeConverter(), scheme, scheme, scheme, scope.Kind, scope.HubGroupVersion, "", nil)
	if err != nil {
		panic(err)
	}
	scope.FieldManager = manager
	return scope
}

func optionRequest(method, manager string) *http.Request {
	path := "/apis/sdn.cozystack.io/v1alpha1/namespaces/tenant-a/vpcs"
	name := ""
	if method != http.MethodPost {
		path += "/vpc"
		name = "vpc"
	}
	req := httptest.NewRequest(method, path+"?fieldManager="+url.QueryEscape(manager), strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodPatch {
		req.Header.Set("Content-Type", string(types.MergePatchType))
	}
	req.Header.Set("Accept", "application/json")
	return req.WithContext(request.WithRequestInfo(req.Context(), &request.RequestInfo{IsResourceRequest: true, APIGroup: sdn.GroupName, APIVersion: "v1alpha1", Resource: "vpcs", Namespace: "tenant-a", Name: name}))
}

func TestOptionsActualCreateBoundsDiagnostics(t *testing.T) {
	storage := &optionStorage{}
	scope := optionScope()
	handler := withBoundedFieldManager(handlers.CreateResource(storage, scope, nil), scope.Serializer)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, optionRequest(http.MethodPost, strings.Repeat("\x00", 256)))
	var status metav1.Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if response.Code != 422 || status.Details == nil || len(status.Details.Causes) != 1 || response.Body.Len() > 2048 || storage.calls != 0 {
		causes := 0
		if status.Details != nil {
			causes = len(status.Details.Causes)
		}
		t.Fatalf("request option rejection: %d status, %d causes, %d bytes, %d storage calls", response.Code, causes, response.Body.Len(), storage.calls)
	}
}

func BenchmarkOptionsActualCreateDiagnostics(b *testing.B) {
	scope := optionScope()
	handler := withBoundedFieldManager(handlers.CreateResource(&optionStorage{}, scope, nil), scope.Serializer)
	req := optionRequest(http.MethodPost, strings.Repeat("\x00", 256))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req.Clone(req.Context()))
	}
}

type optionBody struct{ reads int }

func (b *optionBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*optionBody) Close() error               { return nil }

func TestOptionsActualHTTPHandlersRejectBeforeBodyAndStorage(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		for _, manager := range []string{strings.Repeat("\x00", 256), strings.Repeat("a", 129), "input-canary\n", strings.Repeat("\x00", 128), strings.Repeat("a", 1<<20)} {
			storage := &optionStorage{}
			scope := optionScope()
			var handler http.Handler
			switch method {
			case http.MethodPost:
				handler = handlers.CreateResource(storage, scope, nil)
			case http.MethodPut:
				handler = handlers.UpdateResource(storage, scope, nil)
			case http.MethodPatch:
				handler = handlers.PatchResource(storage, scope, nil, []string{string(types.MergePatchType)})
			}
			request := optionRequest(method, manager)
			body := &optionBody{}
			request.Body = body
			response := httptest.NewRecorder()
			withBoundedFieldManager(handler, scope.Serializer).ServeHTTP(response, request)
			var status metav1.Status
			if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if response.Code != 422 || status.Reason != metav1.StatusReasonInvalid || status.Details == nil || len(status.Details.Causes) != 1 || status.Details.Causes[0].Field != "fieldManager" || response.Body.Len() > 2048 || strings.Contains(response.Body.String(), "input-canary") || body.reads != 0 || storage.calls != 0 {
				t.Fatalf("%s rejection failed: %d status/%d bytes/%d body reads/%d storage calls", method, response.Code, response.Body.Len(), body.reads, storage.calls)
			}
		}
	}
}

func TestOptionsValidManagerReachesActualCreateUnchanged(t *testing.T) {
	for _, manager := range []string{"", strings.Repeat("a", 128), strings.Repeat("é", 64), "controller + client"} {
		storage := &optionStorage{}
		scope := optionScope()
		req := optionRequest(http.MethodPost, manager)
		req.Body = io.NopCloser(strings.NewReader(`{"apiVersion":"sdn.cozystack.io/v1alpha1","kind":"VPC","metadata":{"name":"vpc","namespace":"tenant-a"},"spec":{"cidrs":["192.0.2.0/24"]}}`))
		response := httptest.NewRecorder()
		withBoundedFieldManager(handlers.CreateResource(storage, scope, nil), scope.Serializer).ServeHTTP(response, req)
		if storage.calls != 1 || storage.manager != manager || response.Code != 400 || !strings.Contains(response.Body.String(), "storage reached") {
			t.Fatalf("valid manager %d bytes did not reach storage: %d status/%d calls", len(manager), response.Code, storage.calls)
		}
	}
}

func TestOptionsConfiguredHandlerChainPreservesAuthorization(t *testing.T) {
	scope := optionScope()
	cfg := genericapiserver.NewRecommendedConfig(scope.Serializer.(JSONCodecFactory).CodecFactory)
	cfg.ExternalAddress = "127.0.0.1:443"
	cfg.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString("", "", "")
	authCalls, apiCalls := 0, 0
	authenticationCalls, authenticated := 0, false
	authentication := authenticator.RequestFunc(func(*http.Request) (*authenticator.Response, bool, error) {
		authenticationCalls++
		if !authenticated {
			return nil, false, nil
		}
		return &authenticator.Response{User: &user.DefaultInfo{Name: "audit-user"}}, true, nil
	})
	decision := authorizer.DecisionDeny
	auth := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		authCalls++
		return decision, "test authorization", nil
	})
	buildCalls := 0
	cfg.BuildHandlerChainFunc = func(handler http.Handler, _ *genericapiserver.Config) http.Handler {
		buildCalls++
		return filters.WithAuthentication(filters.WithAuthorization(handler, auth, scope.Serializer), authentication, filters.Unauthorized(scope.Serializer), nil, nil)
	}
	config := Config{GenericConfig: cfg}
	_ = config.Complete() // Production installation point, without starting a server or storage.
	handler := cfg.BuildHandlerChainFunc(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { apiCalls++ }), &cfg.Config)
	req := optionRequest(http.MethodPost, strings.Repeat("\x00", 256))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 401 || authenticationCalls != 1 || authCalls != 0 || apiCalls != 0 {
		t.Fatal("authentication bypassed", response.Code, authenticationCalls, authCalls, apiCalls)
	}
	authenticated = true
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 403 || authCalls != 1 || apiCalls != 0 || buildCalls != 1 {
		t.Fatalf("existing authorization bypassed: %d status/%d auth/%d API/%d builds", response.Code, authCalls, apiCalls, buildCalls)
	}
	decision = authorizer.DecisionAllow
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 422 || authCalls != 2 || apiCalls != 0 {
		t.Fatal("authorized invalid options reached API", response.Code, authCalls, apiCalls)
	}
	req = optionRequest(http.MethodPost, "manager")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 200 || authenticationCalls != 4 || authCalls != 3 || apiCalls != 1 {
		t.Fatal("valid options did not reach existing chain", response.Code, authCalls, apiCalls)
	}
}

func TestOptionsErrorNegotiationPreserved(t *testing.T) {
	scope := optionScope()
	codecs := scope.Serializer.(JSONCodecFactory).CodecFactory
	for _, accept := range []string{"application/json", "application/yaml", "application/vnd.kubernetes.protobuf,application/json"} {
		nextCalls := 0
		handler := withBoundedFieldManager(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }), codecs)
		req := optionRequest(http.MethodPost, strings.Repeat("\x00", 256))
		req.Header.Set("Accept", accept)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		obj, _, err := codecs.UniversalDeserializer().Decode(response.Body.Bytes(), nil, nil)
		if err != nil {
			t.Fatal("cannot decode negotiated status", accept, err)
		}
		status, ok := obj.(*metav1.Status)
		if !ok || response.Code != 422 || status.Reason != metav1.StatusReasonInvalid || status.Details == nil || len(status.Details.Causes) != 1 || response.Body.Len() > 2048 || nextCalls != 0 {
			t.Fatalf("negotiation failed: %s, %T, %d status/%d bytes", accept, obj, response.Code, response.Body.Len())
		}
	}
}

func TestOptionsScopeAndFirstValueSemanticsPreserved(t *testing.T) {
	scope := optionScope()
	calls := 0
	handler := withBoundedFieldManager(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(204) }), scope.Serializer)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, optionRequest(method, strings.Repeat("a", 129)))
		if response.Code != 204 {
			t.Fatal("non-mutating/options-free method altered", method)
		}
	}
	req := optionRequest(http.MethodPost, strings.Repeat("a", 129))
	req = req.WithContext(request.WithRequestInfo(req.Context(), &request.RequestInfo{IsResourceRequest: true, APIGroup: "other.example.invalid"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 204 {
		t.Fatal("another group altered")
	}
	req = optionRequest(http.MethodPost, "manager")
	req.URL.RawQuery += "&fieldManager=" + url.QueryEscape(strings.Repeat("\x00", 256))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 204 || calls != 4 {
		t.Fatal("first-value semantics changed", response.Code, calls)
	}
}
