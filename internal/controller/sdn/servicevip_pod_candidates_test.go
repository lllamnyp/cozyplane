package sdn

import (
	"context"
	"errors"
	"strings"
	"testing"

	local "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type serviceCandidateReader struct {
	client.Client
	reverse             bool
	failFabric          bool
	podGets, fabricGets int
}

func (c *serviceCandidateReader) List(ctx context.Context, out client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, out, opts...); err != nil {
		return err
	}
	if ports, ok := out.(*sdnv1alpha1.PortList); ok && c.reverse {
		for i, j := 0, len(ports.Items)-1; i < j; i, j = i+1, j-1 {
			ports.Items[i], ports.Items[j] = ports.Items[j], ports.Items[i]
		}
	}
	return nil
}

func (c *serviceCandidateReader) Get(ctx context.Context, key client.ObjectKey, out client.Object, opts ...client.GetOption) error {
	switch out.(type) {
	case *corev1.Pod:
		c.podGets++
	case *local.FabricIP:
		c.fabricGets++
		if c.failFabric {
			return errors.New("proof read unavailable")
		}
	}
	return c.Client.Get(ctx, key, out, opts...)
}

func TestServiceVIPCurrentPodClaimCannotBeMaskedByPredecessor(t *testing.T) {
	svc := clusterIPService("tenant-a", "service", "net")
	vpc := readyVPC("tenant-a", "net", "10.0.0.0/24", 100)
	current := livePort("tenant-a", "net", "10.0.0.2", "node-a")
	current.Spec.PodNamespace, current.Spec.PodName = "tenant-a", "backend"
	current.Labels = map[string]string{sdnv1alpha1.LabelVPC: "net", sdnv1alpha1.LabelVPCNamespace: "tenant-a", sdnv1alpha1.LabelPodUID: "current-pod"}
	old := current.DeepCopy()
	old.Name, old.Spec.IP = "v100.10-0-0-3", "10.0.0.3"
	old.Labels[sdnv1alpha1.LabelPodUID] = "old-pod"
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "slice", Namespace: svc.Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: new(true)}}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "tenant-a", Name: "backend", UID: "current-pod"}}}}
	c := svcClient(t, svc, vpc, current, old, slice)
	for _, reverse := range []bool{false, true} {
		r := &ServiceVIPReconciler{Client: &serviceCandidateReader{Client: c, reverse: reverse}}
		backends, err := r.resolveBackends(t.Context(), svc, vpc)
		if err != nil || len(backends) != 1 || backends[0].IP != current.Spec.IP {
			t.Fatalf("current Pod backend masked by predecessor: reverse=%v backends=%v err=%v", reverse, backends, err)
		}
	}
}

func TestServiceVIPCurrentSandboxWinsBeforeOldPortGC(t *testing.T) {
	svc := clusterIPService("tenant-a", "service", "net")
	vpc := readyVPC("tenant-a", "net", "10.0.0.0/24", 100)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: svc.Namespace, Name: "backend", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: "198.51.100.5"}}}}
	current := livePort(svc.Namespace, vpc.Name, "10.0.0.2", pod.Spec.NodeName)
	current.Spec.PodNamespace, current.Spec.PodName = pod.Namespace, pod.Name
	current.Labels = map[string]string{sdnv1alpha1.LabelVPC: vpc.Name, sdnv1alpha1.LabelVPCNamespace: vpc.Namespace, sdnv1alpha1.LabelPodUID: string(pod.UID)}
	current.Annotations = map[string]string{sdnv1alpha1.AnnotationContainerID: strings.Repeat("a", 64), sdnv1alpha1.AnnotationCNIIfName: "eth0"}
	old := current.DeepCopy()
	old.Name, old.Spec.IP = "v100.10-0-0-3", "10.0.0.3"
	old.Annotations[sdnv1alpha1.AnnotationContainerID] = strings.Repeat("b", 64)
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "slice", Namespace: svc.Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: new(true)}}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}}}}
	c := svcClient(t, svc, vpc, current, old, pod, slice)
	if err := local.AddToScheme(c.Scheme()); err != nil {
		t.Fatal(err)
	}
	claim := &local.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: local.FabricIPName(pod.Status.PodIPs[0].IP)}, Spec: local.FabricIPSpec{Address: pod.Status.PodIPs[0].IP, Node: pod.Spec.NodeName, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID), ContainerID: current.Annotations[sdnv1alpha1.AnnotationContainerID], IfName: "eth0"}}
	if err := c.Create(t.Context(), claim); err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		counter := &serviceCandidateReader{Client: c, reverse: reverse}
		r := &ServiceVIPReconciler{Client: counter}
		backends, err := r.resolveBackends(t.Context(), svc, vpc)
		if err != nil || len(backends) != 1 || backends[0].IP != current.Spec.IP {
			t.Fatalf("current sandbox loses to old claim: reverse=%v backends=%v err=%v", reverse, backends, err)
		}
		if counter.podGets != 1 || counter.fabricGets != 1 {
			t.Fatal("unexpected proof read count", counter.podGets, counter.fabricGets)
		}
		counter.failFabric = true
		backends, err = r.resolveBackends(t.Context(), svc, vpc)
		if err == nil || len(backends) != 0 {
			t.Fatal("failed proof admitted partial backend set", backends, err)
		}
	}
	// Even an obsolete singleton is rejected by a positive current witness.
	if err := c.Delete(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	r := &ServiceVIPReconciler{Client: c}
	if backends, err := r.resolveBackends(t.Context(), svc, vpc); err != nil || len(backends) != 0 {
		t.Fatal("obsolete singleton admitted", backends, err)
	}
	current.ResourceVersion = ""
	if err := c.Create(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	// Multiple EndpointSlices for one endpoint reuse the proof during this pass.
	copySlice := slice.DeepCopy()
	copySlice.Name = "second-slice"
	copySlice.ResourceVersion = ""
	if err := c.Create(t.Context(), copySlice); err != nil {
		t.Fatal(err)
	}
	counter := &serviceCandidateReader{Client: c}
	r.Client = counter
	if backends, err := r.resolveBackends(t.Context(), svc, vpc); err != nil || len(backends) != 1 {
		t.Fatal(backends, err)
	}
	if counter.podGets != 1 || counter.fabricGets != 1 {
		t.Fatal("duplicate endpoints repeated proof", counter.podGets, counter.fabricGets)
	}
}
