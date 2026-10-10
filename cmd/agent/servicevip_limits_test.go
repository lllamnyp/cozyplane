package main

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func serviceVIPWorkload(ports, backends int) (*sdnv1alpha1.ServiceVIP, *sdnv1alpha1.VPC) {
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net", UID: "vpc-uid"}, Status: sdnv1alpha1.VPCStatus{VNI: 100}}
	vip := &sdnv1alpha1.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(100, "10.0.255.254"), Annotations: map[string]string{sdnv1alpha1.AnnotationServiceUID: "service-uid", sdnv1alpha1.AnnotationVPCUID: "vpc-uid"}}, Spec: sdnv1alpha1.ServiceVIPSpec{IP: "10.0.255.254", VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}}}
	for i := 0; i < ports; i++ {
		vip.Spec.Ports = append(vip.Spec.Ports, sdnv1alpha1.VIPPort{Protocol: "TCP", Port: int32(i + 1)})
	}
	for i := 0; i < backends; i++ {
		b := sdnv1alpha1.VIPBackend{IP: fmt.Sprintf("10.0.%d.%d", i/254, i%254+1)}
		for j := 0; j < ports; j++ {
			b.Ports = append(b.Ports, sdnv1alpha1.VIPBackendPort{Protocol: "TCP", Port: int32(j + 1), TargetPort: int32(j + 1000)})
		}
		vip.Status.Backends = append(vip.Status.Backends, b)
	}
	return vip, vpc
}

func TestServiceVIPBoundsRetainedBackends(t *testing.T) {
	vip, vpc := serviceVIPWorkload(2, datapath.SvcMaxBackends+1)
	entries, err := compileServiceVIPs([]*sdnv1alpha1.ServiceVIP{vip}, func(sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error) { return vpc, nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal(entries)
	}
	for _, e := range entries {
		if len(e.Backends) != datapath.SvcMaxBackends || cap(e.Backends) > datapath.SvcMaxBackends {
			t.Fatalf("retained %d backends with capacity %d; limit %d", len(e.Backends), cap(e.Backends), datapath.SvcMaxBackends)
		}
	}
}

func TestServiceVIPRejectsOversizeAndRecovers(t *testing.T) {
	vip, vpc := serviceVIPWorkload(1, 1)
	lookup := func(sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error) { return vpc, nil }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, mode := range []string{"ports", "backends", "duplicate work", "entries", "invalid ports"} {
		t.Run(mode, func(t *testing.T) {
			claim := vip.DeepCopy()
			all := []*sdnv1alpha1.ServiceVIP{claim}
			switch mode {
			case "ports":
				claim.Spec.Ports = make([]sdnv1alpha1.VIPPort, 4097)
			case "backends":
				claim.Status.Backends = make([]sdnv1alpha1.VIPBackend, 4097)
			case "duplicate work":
				claim.Status.Backends[0].Ports = make([]sdnv1alpha1.VIPBackendPort, (1<<20)+1)
			case "entries":
				claim.Spec.Ports = make([]sdnv1alpha1.VIPPort, 4096)
				all = []*sdnv1alpha1.ServiceVIP{claim, claim, claim, claim, claim}
			case "invalid ports":
				claim.Spec.Ports = []sdnv1alpha1.VIPPort{{Protocol: "TCP", Port: 65537}, {Protocol: "UDP", Port: -1}}
			}
			entries, err := compileServiceVIPs(all, lookup, logger)
			if mode == "invalid ports" {
				if err != nil || len(entries) != 0 {
					t.Fatal(entries, err)
				}
			} else if err == nil || entries != nil {
				t.Fatal("oversized view retained", len(entries), err)
			}
			entries, err = compileServiceVIPs([]*sdnv1alpha1.ServiceVIP{vip}, lookup, logger)
			if err != nil || len(entries) != 1 || len(entries[0].Backends) != 1 {
				t.Fatal("recovery", entries, err)
			}
		})
	}
}

func BenchmarkServiceVIPCompilation(b *testing.B) {
	vip, vpc := serviceVIPWorkload(32, 512)
	lookup := func(sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error) { return vpc, nil }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compileServiceVIPs([]*sdnv1alpha1.ServiceVIP{vip}, lookup, logger)
	}
}
