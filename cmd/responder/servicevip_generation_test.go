package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestServiceVIPDNSGeneration(t *testing.T) {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "service", UID: "current-service"}}
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net", UID: "current-vpc"}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}, Status: sdnv1alpha1.VPCStatus{VNI: 100, Phase: sdnv1alpha1.VPCPhaseReady}}
	ref := sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}
	vip := &sdnv1alpha1.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(100, "10.0.0.254"), Annotations: map[string]string{sdnv1alpha1.AnnotationServiceUID: "current-service", sdnv1alpha1.AnnotationVPCUID: "current-vpc"}}, Spec: sdnv1alpha1.ServiceVIPSpec{IP: "10.0.0.254", VPCRef: ref, ServiceRef: sdnv1alpha1.ServiceRef{Namespace: "tenant", Name: "service"}}}
	s := &informerState{svcs: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil), vpcs: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil), svips: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{svcIndex: func(any) ([]string, error) { return []string{"tenant/service"}, nil }})}
	for _, mode := range []string{"current", "old Service", "old VPC", "wrong VNI", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			claim := vip.DeepCopy()
			switch mode {
			case "old Service":
				claim.Annotations[sdnv1alpha1.AnnotationServiceUID] = "previous-service"
			case "old VPC":
				claim.Annotations[sdnv1alpha1.AnnotationVPCUID] = "previous-vpc"
			case "wrong VNI":
				claim.Name = sdn.ServiceVIPName(101, claim.Spec.IP)
			case "legacy":
				claim.Annotations = nil
			}
			_ = s.svcs.Replace([]any{svc}, "")
			_ = s.vpcs.Replace([]any{vpc}, "")
			_ = s.svips.Replace([]any{claim}, "")
			address := s.ServiceVIPFor("tenant", "service", ref)
			if mode == "current" {
				if address.String() != vip.Spec.IP {
					t.Fatal(address)
				}
			} else if address != nil {
				t.Fatal("stale VIP returned", address)
			}
		})
	}
}
