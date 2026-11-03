package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceVIPCompileGeneration(t *testing.T) {
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net", UID: "current-vpc"}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}
	vip := &sdnv1alpha1.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(101, "10.0.0.254"), Annotations: map[string]string{sdnv1alpha1.AnnotationServiceUID: "current-service", sdnv1alpha1.AnnotationVPCUID: "current-vpc"}}, Spec: sdnv1alpha1.ServiceVIPSpec{IP: "10.0.0.254", VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}, Ports: []sdnv1alpha1.VIPPort{{Protocol: "TCP", Port: 80}}}, Status: sdnv1alpha1.ServiceVIPStatus{Backends: []sdnv1alpha1.VIPBackend{{IP: "10.0.0.2", Ports: []sdnv1alpha1.VIPBackendPort{{Protocol: "TCP", Port: 80, TargetPort: 8080}}}}}}
	lookup := func(sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error) { return vpc, nil }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, mode := range []string{"current", "old UID", "old VNI", "legacy", "terminating VPC", "terminating VIP"} {
		t.Run(mode, func(t *testing.T) {
			claim := vip.DeepCopy()
			current := vpc.DeepCopy()
			switch mode {
			case "old UID":
				claim.Annotations[sdnv1alpha1.AnnotationVPCUID] = "previous-vpc"
			case "old VNI":
				claim.Name = sdn.ServiceVIPName(100, claim.Spec.IP)
			case "legacy":
				claim.Annotations = nil
			case "terminating VPC":
				now := metav1.Now()
				current.DeletionTimestamp = &now
			case "terminating VIP":
				now := metav1.Now()
				claim.DeletionTimestamp = &now
			}
			lookup = func(sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error) { return current, nil }
			entries, err := compileServiceVIPs([]*sdnv1alpha1.ServiceVIP{claim}, lookup, logger)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "current" {
				if len(entries) != 1 || entries[0].Net != 101 || len(entries[0].Backends) != 1 || entries[0].Backends[0].Port != 8080 {
					t.Fatal(entries)
				}
			} else if len(entries) != 0 {
				t.Fatal("stale VIP programmed", entries)
			}
		})
	}
}
