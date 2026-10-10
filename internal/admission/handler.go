/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package admission applies the aggregated API's strategies to tenant CRDs.
package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	"github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
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
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

const MaxReviewBytes = 8 << 20 // Two bounded Kubernetes objects plus review metadata.
type strategy interface {
	Validate(context.Context, runtime.Object) field.ErrorList
	ValidateUpdate(context.Context, runtime.Object, runtime.Object) field.ErrorList
	PrepareForUpdate(context.Context, runtime.Object, runtime.Object)
	NamespaceScoped() bool
}
type entry struct {
	kind         string
	main, status strategy
}
type TwinExists func(context.Context, string, string) (bool, error)
type Handler struct {
	scheme  *runtime.Scheme
	decoder runtime.Decoder
	entries map[string]entry
	auth    authorizer.Authorizer
	twin    TwinExists
	slots   chan struct{}
}

func NewHandler(auth authorizer.Authorizer, twin TwinExists) (*Handler, error) {
	if auth == nil {
		return nil, errors.New("admission requires a real authorizer")
	}
	s := runtime.NewScheme()
	install.Install(s)
	h := &Handler{scheme: s, decoder: serializer.NewCodecFactory(s).UniversalDeserializer(), entries: map[string]entry{}, auth: auth, twin: twin, slots: make(chan struct{}, 2)}
	v := vpc.NewStrategy(s, auth)
	h.entries["vpcs"] = entry{"VPC", v, vpc.NewStatusStrategy(v)}
	b := vpcbinding.NewStrategy(s, auth)
	h.entries["vpcbindings"] = entry{"VPCBinding", b, nil}
	p := vpcpeering.NewStrategy(s, auth)
	h.entries["vpcpeerings"] = entry{"VPCPeering", p, vpcpeering.NewStatusStrategy(p)}
	g := vpcgateway.NewStrategy(s, auth)
	h.entries["vpcgateways"] = entry{"VPCGateway", g, vpcgateway.NewStatusStrategy(g)}
	sg := securitygroup.NewStrategy(s, auth)
	h.entries["securitygroups"] = entry{"SecurityGroup", sg, securitygroup.NewStatusStrategy(sg)}
	f := floatingip.NewStrategy(s)
	h.entries["floatingips"] = entry{"FloatingIP", f, floatingip.NewStatusStrategy(f)}
	po := port.NewStrategy(s)
	h.entries["ports"] = entry{"Port", po, port.NewStatusStrategy(po)}
	sv := servicevip.NewStrategy(s)
	h.entries["servicevips"] = entry{"ServiceVIP", sv, servicevip.NewStatusStrategy(sv)}
	hf := hostfirewall.NewStrategy(s)
	h.entries["hostfirewalls"] = entry{"HostFirewall", hf, hostfirewall.NewStatusStrategy(hf)}
	vg := vpngateway.NewStrategy(s)
	h.entries["vpngateways"] = entry{"VPNGateway", vg, vpngateway.NewStatusStrategy(vg)}
	vc := vpnconnection.NewStrategy(s)
	h.entries["vpnconnections"] = entry{"VPNConnection", vc, vpnconnection.NewStatusStrategy(vc)}
	return h, nil
}

func denied(uid string, err error) *admissionv1.AdmissionResponse {
	s := apierrors.NewInternalError(err).ErrStatus
	if a, ok := err.(apierrors.APIStatus); ok {
		s = a.Status()
	}
	if len(s.Message) > 4096 {
		s.Message = s.Message[:4096]
	}
	if s.Details != nil {
		if len(s.Details.Causes) > 16 {
			s.Details.Causes = s.Details.Causes[:16]
		}
		for i := range s.Details.Causes {
			if len(s.Details.Causes[i].Message) > 512 {
				s.Details.Causes[i].Message = s.Details.Causes[i].Message[:512]
			}
		}
	}
	return &admissionv1.AdmissionResponse{UID: types.UID(uid), Allowed: false, Result: &s}
}

func (h *Handler) decode(raw runtime.RawExtension, kind string) (runtime.Object, error) {
	o, gvk, e := h.decoder.Decode(raw.Raw, nil, nil)
	if e != nil {
		return nil, apierrors.NewBadRequest("cannot decode tenant object")
	}
	if gvk.Group != sdn.GroupName || gvk.Version != v1alpha1.SchemeGroupVersion.Version || gvk.Kind != kind {
		return nil, apierrors.NewBadRequest("object does not match admission kind")
	}
	return h.scheme.ConvertToVersion(o, sdn.SchemeGroupVersion)
}

func (h *Handler) Validate(ctx context.Context, r *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if r == nil {
		return denied("", apierrors.NewBadRequest("missing request"))
	}
	fail := func(e error) *admissionv1.AdmissionResponse { return denied(string(r.UID), e) }
	if ctx.Err() != nil {
		return fail(apierrors.NewTimeoutError("admission request cancelled", 0))
	}
	e, ok := h.entries[r.Resource.Resource]
	if !ok || r.Resource.Group != sdn.GroupName || r.Resource.Version != "v1alpha1" || r.Kind.Group != sdn.GroupName || r.Kind.Version != "v1alpha1" || r.Kind.Kind != e.kind {
		return fail(apierrors.NewBadRequest("unsupported tenant resource"))
	}
	s := e.main
	if r.SubResource != "" {
		if r.SubResource != "status" || e.status == nil || r.Operation != admissionv1.Update {
			return fail(apierrors.NewBadRequest("unsupported subresource"))
		}
		s = e.status
	}
	extra := map[string][]string{}
	for k, v := range r.UserInfo.Extra {
		extra[k] = append([]string(nil), v...)
	}
	ctx = request.WithUser(ctx, &user.DefaultInfo{Name: r.UserInfo.Username, UID: r.UserInfo.UID, Groups: append([]string(nil), r.UserInfo.Groups...), Extra: extra})
	ctx = request.WithNamespace(ctx, r.Namespace)
	var old runtime.Object
	var err error
	if r.Operation == admissionv1.Update || r.Operation == admissionv1.Delete {
		old, err = h.decode(r.OldObject, e.kind)
		if err != nil {
			return fail(err)
		}
		if err = checkIdentity(r, s, old); err != nil {
			return fail(err)
		}
	}
	if r.Operation == admissionv1.Delete {
		if err = h.validateDelete(ctx, r, old); err != nil {
			return fail(err)
		}
		if ctx.Err() != nil {
			return fail(apierrors.NewTimeoutError("admission request cancelled", 0))
		}
		return &admissionv1.AdmissionResponse{UID: r.UID, Allowed: true}
	}
	obj, err := h.decode(r.Object, e.kind)
	if err != nil {
		return fail(err)
	}
	m, err := meta.Accessor(obj)
	if err != nil {
		return fail(err)
	}
	if err = checkIdentity(r, s, obj); err != nil {
		return fail(err)
	}
	var errs field.ErrorList
	switch r.Operation {
	case admissionv1.Create:
		errs = s.Validate(ctx, obj)
	case admissionv1.Update:
		if r.SubResource == "status" {
			// Native CRDs preserve spec; protect the reserved ownership marker as well.
			om, _ := meta.Accessor(old)
			key := vpcpeering.PortalManagedByLabel
			if m.GetLabels()[key] != om.GetLabels()[key] {
				errs = append(errs, field.Forbidden(field.NewPath("metadata", "labels").Key(key), "status cannot change ownership"))
			}
		}
		s.PrepareForUpdate(ctx, obj, old)
		errs = append(errs, s.ValidateUpdate(ctx, obj, old)...)
	default:
		return fail(apierrors.NewBadRequest("unsupported operation"))
	}
	if len(errs) > 0 {
		if len(errs) > 16 {
			errs = errs[:16]
		}
		return fail(apierrors.NewInvalid(sdn.Kind(e.kind), m.GetName(), errs))
	}
	if r.Operation == admissionv1.Create && (r.Resource.Resource == "ports" || r.Resource.Resource == "servicevips") {
		if h.twin == nil {
			return fail(apierrors.NewInternalError(errors.New("claim reader unavailable")))
		}
		var resource, name string
		switch o := obj.(type) {
		case *sdn.Port:
			vni, _, _ := sdn.ParseClaim(sdn.ClaimPrefixPort, o.Name)
			resource = "servicevips"
			name = sdn.ServiceVIPName(vni, o.Spec.IP)
		case *sdn.ServiceVIP:
			vni, _, _ := sdn.ParseClaim(sdn.ClaimPrefixServiceVIP, o.Name)
			resource = "ports"
			name = sdn.PortName(vni, o.Spec.IP)
		}
		taken, err := h.twin(ctx, resource, name)
		if err != nil {
			return fail(err)
		}
		if taken {
			return fail(apierrors.NewConflict(sdn.Resource(r.Resource.Resource), m.GetName(), fmt.Errorf("address already held by %s %s", resource, name)))
		}
	}
	if ctx.Err() != nil {
		return fail(apierrors.NewTimeoutError("admission request cancelled", 0))
	}
	return &admissionv1.AdmissionResponse{UID: r.UID, Allowed: true}
}

func checkIdentity(r *admissionv1.AdmissionRequest, s strategy, obj runtime.Object) error {
	m, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	collectionDelete := r.Operation == admissionv1.Delete && r.Name == "" && m.GetName() != ""
	if (!collectionDelete && m.GetName() != r.Name) || m.GetName() == "" || (s.NamespaceScoped() && m.GetNamespace() != r.Namespace) || (!s.NamespaceScoped() && (r.Namespace != "" || m.GetNamespace() != "")) {
		return apierrors.NewBadRequest("object identity does not match request")
	}
	return nil
}

func (h *Handler) validateDelete(ctx context.Context, r *admissionv1.AdmissionRequest, obj runtime.Object) error {
	m, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	managed := false
	switch obj.(type) {
	case *sdn.VPCPeering, *sdn.SecurityGroup, *sdn.VPCGateway:
		managed = m.GetLabels()[vpcpeering.PortalManagedByLabel] == vpcpeering.PortalManagedBy
	}
	if v, ok := obj.(*sdn.VPC); ok {
		managed = v.Spec.Boundary != nil
	}
	if managed {
		if e := authz.CheckResourceVerb(ctx, h.auth, "manage-boundary", r.Resource.Resource, r.Kind.Kind, r.Namespace, m.GetName(), field.NewPath("metadata")); e != nil {
			return apierrors.NewForbidden(sdn.Resource(r.Resource.Resource), m.GetName(), e)
		}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Connection", "close")
		http.Error(w, "admission busy", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, MaxReviewBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil || checkJSONBudget(ctx, body) != nil {
		w.Header().Set("Connection", "close")
		http.Error(w, "admission body exceeds budget or is invalid", http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	reader := bytes.NewReader(body)
	d := json.NewDecoder(reader)
	if err := d.Decode(&review); err != nil || review.Request == nil || review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" {
		http.Error(w, "invalid admission review", http.StatusBadRequest)
		return
	}
	if !whitespaceOnly(io.MultiReader(d.Buffered(), reader)) {
		http.Error(w, "invalid admission review suffix", http.StatusBadRequest)
		return
	}
	response := admissionv1.AdmissionReview{TypeMeta: review.TypeMeta, Response: h.Validate(ctx, review.Request)}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	} // Client disconnect; no state was changed.
}

// Do not decode a second JSON value into interface{}: a tiny repeated value
// can expand into a much larger tree. Read suffix whitespace with fixed storage.
func whitespaceOnly(reader io.Reader) bool {
	var buffer [256]byte
	for {
		n, err := reader.Read(buffer[:])
		for _, b := range buffer[:n] {
			if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
				return false
			}
		}
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
	}
}
