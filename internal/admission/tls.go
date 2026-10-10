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
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// CertificateLoader follows Kubernetes Secret volume rotation without a
// background goroutine or reading keys on every TLS handshake.
type CertificateLoader struct {
	mu                sync.Mutex
	certPath, keyPath string
	nextCheck         time.Time
	certTime, keyTime time.Time
	certificate       *tls.Certificate
	lastError         error
}

func NewCertificateLoader(certPath, keyPath string) (*CertificateLoader, error) {
	l := &CertificateLoader{certPath: certPath, keyPath: keyPath}
	_, err := l.GetCertificate(nil)
	return l, err
}
func (l *CertificateLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Now().Before(l.nextCheck) {
		return l.certificate, l.lastError
	}
	l.nextCheck = time.Now().Add(time.Minute)
	certInfo, err := os.Stat(l.certPath)
	if err != nil {
		l.lastError = err
		return nil, err
	}
	keyInfo, err := os.Stat(l.keyPath)
	if err != nil {
		l.lastError = err
		return nil, err
	}
	if l.lastError == nil && l.certificate != nil && certInfo.ModTime().Equal(l.certTime) && keyInfo.ModTime().Equal(l.keyTime) {
		return l.certificate, nil
	}
	cert, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		l.lastError = err
		return nil, err
	}
	l.certificate = &cert
	l.certTime = certInfo.ModTime()
	l.keyTime = keyInfo.ModTime()
	l.lastError = nil
	return l.certificate, nil
}
