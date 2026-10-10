package sdn

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	v1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVIPOccupancyIgnoresPredecessorVNI(t *testing.T) {
	for _, kind := range []string{"Port", "ServiceVIP"} {
		t.Run(kind, func(t *testing.T) {
			vpc := readyVPC("tenant", "net", "10.0.0.0/30", 101)
			ref := v1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}
			var old client.Object = &v1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, "10.0.0.2")}, Spec: v1.PortSpec{IP: "10.0.0.2", VPCRef: ref}}
			if kind == "ServiceVIP" {
				old = &v1.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: sdn.ServiceVIPName(100, "10.0.0.2")}, Spec: v1.ServiceVIPSpec{IP: "10.0.0.2", VPCRef: ref}}
			}
			c := svcClient(t, vpc, old)
			r := &ServiceVIPReconciler{Client: c, Reader: c}
			address, err := r.allocateVIP(t.Context(), vpc)
			if err != nil || address != "10.0.0.2" {
				t.Fatal("predecessor VNI exhausted current pool", address, err)
			}
			held, err := r.ipHeldByPort(t.Context(), vpc, "10.0.0.2")
			if err != nil || held {
				t.Fatal("predecessor Port forced current VIP to yield", held, err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(old), old); err != nil {
				t.Fatal("predecessor claim was removed", err)
			}
		})
	}
}

func TestVIPOccupancyKeepsTerminatingCurrentClaims(t *testing.T) {
	vpc := readyVPC("tenant", "net", "10.0.0.0/24", 101)
	port := &v1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(101, "10.0.0.254"), DeletionTimestamp: new(metav1.Now()), Finalizers: []string{"example.invalid/cleanup"}}, Spec: v1.PortSpec{IP: "10.0.0.254", VPCRef: v1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}}}
	c := svcClient(t, vpc, port)
	r := &ServiceVIPReconciler{Client: c, Reader: c}
	held, err := r.ipHeldByPort(t.Context(), vpc, port.Spec.IP)
	if err != nil || !held {
		t.Fatal("terminating current Port lost its reservation", held, err)
	}
	address, err := r.allocateVIP(t.Context(), vpc)
	if err != nil || address != "10.0.0.253" {
		t.Fatal("terminating current Port was reallocated", address, err)
	}
}
