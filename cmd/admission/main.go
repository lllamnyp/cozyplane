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

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"time"

	"context"
	"github.com/lllamnyp/cozyplane/internal/admission"
	"golang.org/x/net/netutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	address := flag.String("listen", ":9443", "TLS admission listener")
	cert := flag.String("tls-cert", "/tls/tls.crt", "operator-mounted certificate")
	key := flag.String("tls-key", "/tls/tls.key", "operator-mounted private key")
	flag.Parse()
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal("in-cluster configuration unavailable")
	}
	cfg.Timeout = 4 * time.Second
	k, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal("authorization client unavailable")
	}
	d, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatal("claim client unavailable")
	}
	h, err := admission.NewHandler(admission.SARAuthorizer{Client: k.AuthorizationV1().SubjectAccessReviews()}, func(ctx context.Context, resource, name string) (bool, error) {
		_, err := d.Resource(schema.GroupVersionResource{Group: "sdn.cozystack.io", Version: "v1alpha1", Resource: resource}).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	})
	if err != nil {
		log.Fatal("admission handler unavailable")
	}
	mux := http.NewServeMux()
	mux.Handle("/validate", h)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	tlsLoader, err := admission.NewCertificateLoader(*cert, *key)
	if err != nil {
		log.Fatal("admission serving certificate unavailable")
	}
	s := &http.Server{Addr: *address, Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: tlsLoader.GetCertificate}}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal("admission listener unavailable")
	}
	defer listener.Close()
	if err := s.ServeTLS(netutil.LimitListener(listener, 32), "", ""); err != nil {
		log.Fatal("admission TLS server stopped")
	}
}
