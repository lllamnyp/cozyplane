package sdn

import (
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/floatingvalidation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const floatingTargetIndex = "cozyplane.floating-target"

func floatingContenderEvents() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		old, oldOK := e.ObjectOld.(*sdnv1alpha1.FloatingIP)
		current, currentOK := e.ObjectNew.(*sdnv1alpha1.FloatingIP)
		if !oldOK || !currentOK {
			return false
		}
		return old.UID != current.UID || !old.CreationTimestamp.Equal(&current.CreationTimestamp) || old.DeletionTimestamp.IsZero() != current.DeletionTimestamp.IsZero() || floatingTargetKey(old) != floatingTargetKey(current)
	}}
}

func floatingTargetKey(f *sdnv1alpha1.FloatingIP) string {
	ip := floatingvalidation.Target(f.Spec.VPCRef.Name, f.Spec.Target)
	if ip == "" {
		return ""
	}
	return f.Spec.VPCRef.Name + "|" + ip
}

func floatingTargetIndexKeys(obj client.Object) []string {
	f, ok := obj.(*sdnv1alpha1.FloatingIP)
	if !ok {
		return nil
	}
	key := floatingTargetKey(f)
	if key == "" {
		return nil
	}
	return []string{key}
}
