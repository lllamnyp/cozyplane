package apiserver

import (
	"net/http"
	"unicode"

	"github.com/lllamnyp/cozyplane/api/sdn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	request "k8s.io/apiserver/pkg/endpoints/request"
	genericapiserver "k8s.io/apiserver/pkg/server"
)

func installRequestOptionValidation(config *genericapiserver.RecommendedConfig) {
	build := config.BuildHandlerChainFunc
	if build == nil {
		build = genericapiserver.DefaultBuildHandlerChain
	}
	config.BuildHandlerChainFunc = func(apiHandler http.Handler, c *genericapiserver.Config) http.Handler {
		// Leave all existing authentication, authorization, audit and accounting
		// outside the guard. Only the resource handler receives validated input.
		return build(withBoundedFieldManager(apiHandler, c.Serializer), c)
	}
}

func withBoundedFieldManager(next http.Handler, serializer runtime.NegotiatedSerializer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := ""
		switch r.Method {
		case http.MethodPost:
			kind = "CreateOptions"
		case http.MethodPut:
			kind = "UpdateOptions"
		case http.MethodPatch:
			kind = "PatchOptions"
		}
		info, ok := request.RequestInfoFrom(r.Context())
		if kind == "" || !ok || !info.IsResourceRequest || info.APIGroup != sdn.GroupName {
			next.ServeHTTP(w, r)
			return
		}
		// Query.Get matches ParameterCodec's first-value semantics; do not read
		// the body or silently normalize an invalid manager into another identity.
		manager := r.URL.Query().Get("fieldManager")
		invalid := len(manager) > validation.FieldManagerMaxLength
		if !invalid {
			for _, char := range manager {
				if !unicode.IsPrint(char) {
					invalid = true
					break
				}
			}
		}
		if invalid {
			err := apierrors.NewInvalid(schema.GroupKind{Group: metav1.GroupName, Kind: kind}, "", field.ErrorList{field.Invalid(field.NewPath("fieldManager"), nil, "must contain at most 128 bytes of printable characters")})
			responsewriters.ErrorNegotiated(err, serializer, metav1.SchemeGroupVersion, w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
