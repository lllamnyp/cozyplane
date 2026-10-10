package sdn

import (
	"context"
	"errors"
	"testing"
	"time"

	local "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPortGCReapsObsoleteSandboxWithSamePodUID(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*corev1.Pod, *sdn.Port, *local.FabricIP)
		reap bool
	}{
		{"obsolete", func(*corev1.Pod, *sdn.Port, *local.FabricIP) {}, true},
		{"current", func(_ *corev1.Pod, p *sdn.Port, _ *local.FabricIP) {
			p.Annotations[sdn.AnnotationContainerID] = "current"
		}, false},
		{"young", func(_ *corev1.Pod, p *sdn.Port, _ *local.FabricIP) { p.CreationTimestamp = metav1.Now() }, false},
		{"legacy port", func(_ *corev1.Pod, p *sdn.Port, _ *local.FabricIP) { delete(p.Annotations, sdn.AnnotationContainerID) }, false},
		{"legacy claim", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.ContainerID = "" }, false},
		{"foreign UID", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.PodUID = "other" }, false},
		{"foreign namespace", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.PodNamespace = "other" }, false},
		{"foreign name", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.PodName = "other" }, false},
		{"foreign node", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.Node = "other" }, false},
		{"wrong address", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.Address = "10.244.0.9" }, false},
		{"wrong interface", func(_ *corev1.Pod, _ *sdn.Port, f *local.FabricIP) { f.Spec.IfName = "net1" }, false},
		{"delegate", func(_ *corev1.Pod, p *sdn.Port, _ *local.FabricIP) { p.Annotations[sdn.AnnotationCNIIfName] = "net1" }, false},
		{"VM pins", func(_ *corev1.Pod, p *sdn.Port, _ *local.FabricIP) { p.Labels[sdn.LabelVMName] = "vm" }, false},
		{"pending", func(p *corev1.Pod, _ *sdn.Port, _ *local.FabricIP) { p.Status.Phase = corev1.PodPending }, false},
		{"no status addresses", func(p *corev1.Pod, _ *sdn.Port, _ *local.FabricIP) { p.Status.PodIPs = nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.2", PodIPs: []corev1.PodIP{{IP: "10.244.0.2"}}}}
			port := claimedPort("v100.10-10-0-2", pod.Namespace, pod.Name, string(pod.UID), false)
			port.CreationTimestamp = metav1.NewTime(time.Now().Add(-10 * time.Minute))
			port.Annotations = map[string]string{sdn.AnnotationContainerID: "old", sdn.AnnotationCNIIfName: "eth0"}
			fip := &local.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: local.FabricIPName(pod.Status.PodIP)}, Spec: local.FabricIPSpec{Address: pod.Status.PodIP, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID), Node: pod.Spec.NodeName, ContainerID: "current", IfName: "eth0"}}
			tc.edit(pod, port, fip)
			scheme := gatewayScheme(t)
			if err := local.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, port, fip).Build()
			r := &PortGCReconciler{Client: c}
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)})
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "young" && (result.RequeueAfter <= 0 || result.RequeueAfter > 5*time.Minute) {
				t.Fatal("grace does not schedule a bounded revisit", result)
			}
			got := &sdn.Port{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil {
				t.Fatal("sever barrier lost", err)
			}
			if !got.DeletionTimestamp.IsZero() != tc.reap {
				t.Fatalf("terminating=%v want=%v", !got.DeletionTimestamp.IsZero(), tc.reap)
			}
		})
	}
}

type sandboxReadError struct{ client.Reader }

func (r sandboxReadError) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("live reader unavailable")
}

func TestPortGCSandboxWitnessLiveAndDualStack(t *testing.T) {
	for _, mode := range []string{"agrees", "mixed", "missing", "legacy", "terminating", "live claim differs", "live pod pending", "live pod UID differs", "live read fails", "rebound before delete"} {
		t.Run(mode, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: "10.244.0.2"}, {IP: "2001:db8::2"}}}}
			port := claimedPort("v100.10-10-0-2", pod.Namespace, pod.Name, string(pod.UID), false)
			port.UID = "port-uid"
			port.CreationTimestamp = metav1.NewTime(time.Now().Add(-10 * time.Minute))
			port.Annotations = map[string]string{sdn.AnnotationContainerID: "old", sdn.AnnotationCNIIfName: "eth0"}
			claims := []*local.FabricIP{}
			for _, ip := range pod.Status.PodIPs {
				claims = append(claims, &local.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: local.FabricIPName(ip.IP)}, Spec: local.FabricIPSpec{Address: ip.IP, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID), Node: pod.Spec.NodeName, ContainerID: "current", IfName: "eth0"}})
			}
			scheme := gatewayScheme(t)
			if err := local.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, port, claims[0], claims[1]).Build()
			livePod := pod.DeepCopy()
			liveClaims := []*local.FabricIP{claims[0].DeepCopy(), claims[1].DeepCopy()}
			switch mode {
			case "mixed":
				liveClaims[1].Spec.ContainerID = "other"
			case "missing":
				liveClaims = liveClaims[:1]
			case "legacy":
				liveClaims[1].Spec.ContainerID = ""
			case "terminating":
				liveClaims[1].Finalizers = []string{"test-hold"}
				stamp := metav1.Now()
				liveClaims[1].DeletionTimestamp = &stamp
			case "live claim differs":
				for _, claim := range liveClaims {
					claim.Spec.ContainerID = "old"
				}
			case "live pod pending":
				livePod.Status.Phase = corev1.PodPending
			case "live pod UID differs":
				livePod.UID = "other"
			}
			objects := []client.Object{livePod}
			for _, claim := range liveClaims {
				objects = append(objects, claim)
			}
			var live client.Reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			var writer client.Client = cached
			if mode == "live read fails" {
				live = sandboxReadError{Reader: live}
			}
			if mode == "rebound before delete" {
				writer = &reboundPortDeleteClient{Client: cached}
			}
			r := &PortGCReconciler{Client: writer, Reader: live}
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)})
			if mode == "live read fails" {
				if err == nil {
					t.Fatal("live reader failure ignored")
				}
			} else if err != nil && !(mode == "rebound before delete" && apierrors.IsConflict(err)) {
				t.Fatal(err)
			}
			got := &sdn.Port{}
			if err := cached.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil {
				t.Fatal("sever barrier lost", err)
			}
			if !got.DeletionTimestamp.IsZero() != (mode == "agrees") {
				t.Fatal("GC ignored the live sandbox witness", got.DeletionTimestamp)
			}
		})
	}
}
