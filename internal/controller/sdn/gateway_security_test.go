package sdn

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestGatewayForeignDeploymentPreserved(t *testing.T) {
	for _, uid := range []string{"", "previous-vpc-uid"} {
		t.Run(uid, func(t *testing.T) {
			vpc := egressVPC("consumer", "network", 142, true)
			dep := gatewayReconciler(nil).deployment(vpc)
			dep.Annotations[gatewayVPCUIDAnnotation] = uid
			dep.Spec.Template.Spec.Containers[0].Image = "foreign:image"
			c := gatewayClientBuilder(gatewayScheme(t)).WithObjects(vpc, dep, natGateway("consumer", "door", "network")).Build()
			r := gatewayReconciler(c)
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpc)}); err == nil {
				t.Fatal("foreign deployment adopted")
			}
			if err := r.deleteGateways(context.Background(), vpc.Namespace, vpc.Name, vpc.UID); err != nil {
				t.Fatal(err)
			}
			got := &appsv1.Deployment{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(dep), got); err != nil {
				t.Fatal(err)
			}
			if got.Spec.Template.Spec.Containers[0].Image != "foreign:image" {
				t.Fatal("foreign deployment overwritten")
			}
		})
	}
}

func TestGatewayLabelOnlyPodSurvivesHealing(t *testing.T) {
	vpc := egressVPC("consumer", "network", 142, true)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "cozy-cozyplane", UID: "foreign-pod", Labels: map[string]string{sdnv1alpha1.LabelVPC: vpc.Name, sdnv1alpha1.LabelVPCNamespace: vpc.Namespace}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	c := gatewayClientBuilder(gatewayScheme(t)).WithObjects(vpc, pod).Build()
	if err := gatewayReconciler(c).healSeveredGateway(context.Background(), vpc); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
		t.Fatal("foreign pod deleted", err)
	}
}
