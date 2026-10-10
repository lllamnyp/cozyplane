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

package admission

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// All key material in this test is generated, disposable and never printed.
func testServingCertificate(t *testing.T, dir string, serial int64) *x509.Certificate {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("synthetic key generation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test-admission.invalid"}, DNSNames: []string{"test-admission.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal("synthetic certificate generation failed")
	}
	encoded, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal("synthetic key encoding failed")
	}
	if e := os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); e != nil {
		t.Fatal(e)
	}
	stamp := time.Unix(serial, 0)
	for _, name := range []string{"tls.crt", "tls.key"} {
		if e := os.Chtimes(filepath.Join(dir, name), stamp, stamp); e != nil {
			t.Fatal(e)
		}
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal("synthetic certificate parsing failed")
	}
	return cert
}

func TestServingCertificateRotatesAndRecovers(t *testing.T) {
	dir := t.TempDir()
	first := testServingCertificate(t, dir, 1)
	l, e := NewCertificateLoader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if e != nil {
		t.Fatal("initial TLS load failed")
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: l.GetCertificate}, ReadHeaderTimeout: time.Second}
	defer s.Close()
	go func() { _ = s.ServeTLS(ln, "", "") }()
	roots := x509.NewCertPool()
	roots.AddCert(first)
	handshake := func(want int64) {
		t.Helper()
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "test-admission.invalid"})
		if e != nil {
			t.Fatal("validated TLS handshake failed")
		}
		defer conn.Close()
		if conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != want {
			t.Fatal("stale serving certificate")
		}
	}
	refresh := func() { l.mu.Lock(); l.nextCheck = time.Time{}; l.mu.Unlock() }
	handshake(1)
	roots.AddCert(testServingCertificate(t, dir, 2))
	refresh()
	handshake(2)
	if e := os.WriteFile(filepath.Join(dir, "tls.key"), []byte("invalid synthetic key"), 0600); e != nil {
		t.Fatal(e)
	}
	refresh()
	if _, e := l.GetCertificate(nil); e == nil {
		t.Fatal("malformed rotation did not fail closed")
	}
	// A repaired Secret is retried on the next bounded metadata check.
	roots.AddCert(testServingCertificate(t, dir, 3))
	refresh()
	handshake(3)
}
