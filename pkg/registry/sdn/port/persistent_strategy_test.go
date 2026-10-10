package port

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func persistentTestPort() *sdn.Port {
	return &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(101, "10.0.0.2"), Labels: map[string]string{sdnv1.LabelVMName: "vm", sdnv1.LabelVMNIC: "0"}}, Spec: sdn.PortSpec{IP: "10.0.0.2", MAC: "02:00:00:00:00:01", PodNamespace: "consumer", VPCRef: sdn.VPCRef{Namespace: "owner", Name: "net"}}}
}

func TestPersistentNICIdentityImmutable(t *testing.T) {
	s := NewStrategy(runtime.NewScheme())
	mutations := map[string]func(*sdn.Port){
		"VM name":   func(p *sdn.Port) { p.Labels[sdnv1.LabelVMName] = "other" },
		"remove VM": func(p *sdn.Port) { delete(p.Labels, sdnv1.LabelVMName) },
		"NIC":       func(p *sdn.Port) { p.Labels[sdnv1.LabelVMNIC] = "1" },
		"namespace": func(p *sdn.Port) { p.Spec.PodNamespace = "other" },
		"MAC":       func(p *sdn.Port) { p.Spec.MAC = "02:00:00:00:00:02" },
		"VPC owner": func(p *sdn.Port) { p.Spec.VPCRef.Namespace = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			old := persistentTestPort()
			next := old.DeepCopy()
			mutate(next)
			if len(s.ValidateUpdate(t.Context(), next, old)) == 0 {
				t.Fatal("identity change admitted")
			}
		})
	}
	status := NewStatusStrategy(s)
	for _, key := range []string{sdnv1.LabelVMName, sdnv1.LabelVMNIC} {
		old, next := persistentTestPort(), persistentTestPort()
		next.Labels[key] = "other"
		status.PrepareForUpdate(t.Context(), next, old)
		if len(status.ValidateUpdate(t.Context(), next, old)) == 0 {
			t.Fatal("status bypass changed identity", key)
		}
	}
	old, next := persistentTestPort(), persistentTestPort()
	delete(old.Labels, sdnv1.LabelVMName)
	if len(s.ValidateUpdate(t.Context(), next, old)) == 0 {
		t.Fatal("ordinary Port converted without allocation guard")
	}
	old = persistentTestPort()
	next = old.DeepCopy()
	next.Spec.Node, next.Spec.PodName = "target-node", "target-launcher"
	next.Labels[sdnv1.LabelPodUID] = "target-pod"
	next.Annotations = map[string]string{sdnv1.AnnotationPodLabels: `{"app":"target"}`}
	next.Finalizers = nil
	if errors := s.ValidateUpdate(t.Context(), next, old); len(errors) != 0 {
		t.Fatal("migration binding rejected", errors)
	}
	// Invalid legacy pins still allow metadata/finalizer cleanup.
	old.Spec.MAC = "legacy-invalid"
	next = old.DeepCopy()
	next.Finalizers = nil
	if errors := s.ValidateUpdate(t.Context(), next, old); len(errors) != 0 {
		t.Fatal("legacy cleanup rejected", errors)
	}
}

func TestPersistentNICCreateRequiresCompletePins(t *testing.T) {
	s := NewStrategy(runtime.NewScheme())
	valid := persistentTestPort()
	if errors := s.Validate(t.Context(), valid); len(errors) != 0 {
		t.Fatal(errors)
	}
	for _, mutate := range []func(*sdn.Port){
		func(p *sdn.Port) { p.Spec.PodNamespace = "" },
		func(p *sdn.Port) { p.Spec.VPCRef.Namespace = "" },
		func(p *sdn.Port) { p.Spec.VPCRef.Name = "" },
		func(p *sdn.Port) { delete(p.Labels, sdnv1.LabelVMNIC) },
		func(p *sdn.Port) { p.Spec.MAC = "01:00:00:00:00:01" },
		func(p *sdn.Port) { p.Spec.MAC = "02:00:00:00:00:01:02:03" },
		func(p *sdn.Port) { p.Spec.MAC = "" },
	} {
		p := valid.DeepCopy()
		mutate(p)
		if len(s.Validate(t.Context(), p)) == 0 {
			t.Fatal("incomplete persistent identity admitted", p)
		}
	}
}
