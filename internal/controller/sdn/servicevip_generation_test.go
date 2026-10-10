package sdn

import (
	"context"
	ctrl "sigs.k8s.io/controller-runtime"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestServiceVIPDoesNotAdoptPreviousGeneration(t *testing.T) {
	for _, mode := range []string{"Service recreated", "VPC recreated", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			svc := clusterIPService("tenant", "service", "net")
			svc.UID = "current-service"
			vpc := readyVPC("tenant", "net", "10.0.0.0/24", 100)
			vpc.UID = "current-vpc"
			vip := &sdnv1alpha1.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: "sv100.10-0-0-254", UID: "old-vip", Labels: map[string]string{sdnv1alpha1.LabelServiceNamespace: "tenant", sdnv1alpha1.LabelServiceName: "service"}, Annotations: map[string]string{"sdn.cozystack.io/service-uid": string(svc.UID), "sdn.cozystack.io/vpc-uid": string(vpc.UID)}}, Spec: sdnv1alpha1.ServiceVIPSpec{IP: "10.0.0.254", VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}, ServiceRef: sdnv1alpha1.ServiceRef{Namespace: "tenant", Name: "service"}}, Status: sdnv1alpha1.ServiceVIPStatus{Backends: []sdnv1alpha1.VIPBackend{{IP: "10.0.0.2"}}}}
			switch mode {
			case "Service recreated":
				vip.Annotations["sdn.cozystack.io/service-uid"] = "old-service"
			case "VPC recreated":
				vip.Annotations["sdn.cozystack.io/vpc-uid"] = "old-vpc"
			case "legacy":
				vip.Annotations = nil
			}
			c := svcClient(t, svc, vpc, vip)
			r := &ServiceVIPReconciler{Client: c, Reader: c}
			result, err := r.ensureVIP(t.Context(), svc, vpc)
			if err != nil || result != nil {
				t.Fatalf("previous generation reused: vip=%v err=%v", result, err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(vip), &sdnv1alpha1.ServiceVIP{}); !apierrors.IsNotFound(err) {
				t.Fatal("previous claim was not removed", err)
			}
			result, err = r.ensureVIP(t.Context(), svc, vpc)
			if err != nil || result == nil || len(result.Status.Backends) != 0 {
				t.Fatal("fresh generation did not recover", result, err)
			}
		})
	}
}

func TestServiceVIPUsesLiveGenerationDespiteStaleCache(t *testing.T) {
	svc := clusterIPService("tenant", "service", "net")
	vpc := readyVPC("tenant", "net", "10.0.0.0/24", 100)
	live := svcClient(t, svc, vpc, binding("tenant", "tenant", "net"))
	r := &ServiceVIPReconciler{Client: live, Reader: live}
	vip, err := r.ensureVIP(t.Context(), svc, vpc)
	if err != nil || vip == nil {
		t.Fatal(vip, err)
	}
	oldSvc, oldVPC := svc.DeepCopy(), vpc.DeepCopy()
	oldSvc.UID, oldVPC.UID = "previous-service", "previous-vpc"
	r.Client = cachedServiceVIPClient{Client: live, Reader: svcClient(t, oldSvc, oldVPC)}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(svc)}); err != nil {
		t.Fatal(err)
	}
	current := &sdnv1alpha1.ServiceVIP{}
	if err := live.Get(t.Context(), client.ObjectKeyFromObject(vip), current); err != nil {
		t.Fatal("cached predecessor deleted current VIP", err)
	}
	if current.Annotations[sdnv1alpha1.AnnotationServiceUID] != string(svc.UID) {
		t.Fatal(current.Annotations)
	}
}

type cachedServiceVIPClient struct {
	client.Client
	Reader client.Reader
}

func (c cachedServiceVIPClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	return c.Reader.Get(ctx, key, object, opts...)
}

func TestServiceVIPReaperDoesNotTrustForeignLabels(t *testing.T) {
	foreign := &sdnv1alpha1.ServiceVIP{ObjectMeta: metav1.ObjectMeta{Name: "sv100.10-0-0-254", Labels: map[string]string{sdnv1alpha1.LabelServiceNamespace: "tenant", sdnv1alpha1.LabelServiceName: "service"}}, Spec: sdnv1alpha1.ServiceVIPSpec{ServiceRef: sdnv1alpha1.ServiceRef{Namespace: "other", Name: "service"}}}
	c := svcClient(t, foreign)
	r := &ServiceVIPReconciler{Client: c}
	if err := r.reapVIPs(t.Context(), "tenant", "service", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(foreign), &sdnv1alpha1.ServiceVIP{}); err != nil {
		t.Fatal("deleted foreign spec owner", err)
	}
}
