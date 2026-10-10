package sdn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestIPsecAcknowledgementRequiresCurrentOwnedReadyReplica(t *testing.T) {
	checksum := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name                                     string
		annotation, reported, backend            string
		ready, terminating, unowned, unavailable bool
		want                                     bool
	}{
		{name: "current", annotation: checksum, reported: checksum, backend: backendIPsec, ready: true, want: true},
		{name: "old template", annotation: "old", reported: checksum, backend: backendIPsec, ready: true},
		{name: "old runtime", annotation: checksum, reported: "old", backend: backendIPsec, ready: true},
		{name: "missing runtime hash", annotation: checksum, backend: backendIPsec, ready: true},
		{name: "not ready", annotation: checksum, reported: checksum, backend: backendIPsec},
		{name: "terminating", annotation: checksum, reported: checksum, backend: backendIPsec, ready: true, terminating: true},
		{name: "label spoof", annotation: checksum, reported: checksum, backend: backendIPsec, ready: true, unowned: true},
		{name: "unavailable status", annotation: checksum, reported: checksum, backend: backendIPsec, ready: true, unavailable: true},
		{name: "wrong backend", annotation: checksum, reported: checksum, backend: backendWireGuard, ready: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, gw, _, c := vpnApplianceIndexFixture(t, 0, tc.ready)
			gw.Spec.IPsec = &sdn.VPNGatewayIPsec{}
			pod := &corev1.Pod{}
			if err := c.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: "appliance"}, pod); err != nil {
				t.Fatal(err)
			}
			pod.Annotations = map[string]string{vpnConfigChecksumAnnotation: tc.annotation}
			if tc.unowned {
				pod.OwnerReferences = nil
			}
			if err := c.Update(t.Context(), pod); err != nil {
				t.Fatal(err)
			}
			if tc.terminating {
				pod.Finalizers = []string{"example.invalid/drain"}
				if err := c.Update(t.Context(), pod); err != nil {
					t.Fatal(err)
				}
				if err := c.Delete(t.Context(), pod); err != nil {
					t.Fatal(err)
				}
			}
			r.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if tc.unavailable {
					return nil, errors.New("status unavailable")
				}
				body, _ := json.Marshal(map[string]any{"backend": tc.backend, "observedAt": time.Now().UTC(), "configChecksum": tc.reported, "connections": map[string]any{"site": map[string]any{"up": true}}})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
			})}
			got, err := r.ipsecConfigApplied(t.Context(), gw, checksum)
			if got != tc.want || got && err != nil {
				t.Fatalf("configuration applied=%v error=%v, want %v", got, err, tc.want)
			}
		})
	}
}

func TestIPsecWarmStandbyAcknowledgesBothOwnedReplicas(t *testing.T) {
	checksum := strings.Repeat("a", 64)
	r, gw, _, c := vpnApplianceIndexFixture(t, 0, true)
	gw.Spec.IPsec = &sdn.VPNGatewayIPsec{}
	gw.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeWarmStandby}
	pod := &corev1.Pod{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: "appliance"}, pod); err != nil {
		t.Fatal(err)
	}
	pod.Annotations = map[string]string{vpnConfigChecksumAnnotation: checksum}
	if err := c.Update(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	standby := pod.DeepCopy()
	standby.Name, standby.UID, standby.ResourceVersion = "standby", types.UID("standby-current"), ""
	standby.Status.PodIP = "192.0.2.11"
	if err := c.Create(t.Context(), standby); err != nil {
		t.Fatal(err)
	}
	standbyChecksum := checksum
	r.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		reported := checksum
		if req.URL.Hostname() == standby.Status.PodIP {
			reported = standbyChecksum
		}
		body, _ := json.Marshal(map[string]any{"backend": backendIPsec, "observedAt": time.Now().UTC(), "configChecksum": reported, "connections": map[string]any{}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})}
	if got, err := r.ipsecConfigApplied(t.Context(), gw, checksum); err != nil || !got {
		t.Fatal("current standby replicas were not acknowledged", got, err)
	}
	standbyChecksum = "old"
	if got, _ := r.ipsecConfigApplied(t.Context(), gw, checksum); got {
		t.Fatal("current active replica hid a stale standby peer set")
	}
	standbyChecksum = checksum
	if err := c.Delete(t.Context(), standby); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.ipsecConfigApplied(t.Context(), gw, checksum); got {
		t.Fatal("missing standby replica incorrectly acknowledged")
	}
}

type ipsecAckPartialReader struct{ client.Reader }

func (r ipsecAckPartialReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := r.Reader.List(ctx, list, opts...); err != nil {
		return err
	}
	if pods, ok := list.(*corev1.PodList); ok {
		pods.Continue = "remaining"
	}
	return nil
}

func TestIPsecAcknowledgementRejectsPartialLivePodScan(t *testing.T) {
	r, gw, _, c := vpnApplianceIndexFixture(t, 0, true)
	gw.Spec.IPsec = &sdn.VPNGatewayIPsec{}
	r.Reader = ipsecAckPartialReader{Reader: c}
	if got, err := r.ipsecConfigApplied(t.Context(), gw, strings.Repeat("a", 64)); got || err == nil {
		t.Fatal("partial pod scan did not fail closed", got, err)
	}
}
