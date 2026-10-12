package sdn

import (
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const vpnConnectionGatewayIndex = "cozyplane.vpn-connection-gateway"

const vpnAppliancePodIndex = "cozyplane.vpn-appliance-pod"

func vpnAppliancePodKeys(obj client.Object) []string {
	p, ok := obj.(*sdnv1alpha1.Port)
	if !ok || p.Spec.PodNamespace == "" || p.Spec.PodName == "" || len(p.Spec.PodNamespace) > 63 || len(p.Spec.PodName) > 253 {
		return nil
	}
	return []string{p.Spec.PodNamespace + "/" + p.Spec.PodName}
}

const vpnCredentialIndex = "cozyplane.vpn-credential"

func vpnCredentialKeys(obj client.Object) []string {
	var refs []string
	switch obj := obj.(type) {
	case *sdnv1alpha1.VPNGateway:
		if auth := obj.Spec.IPsec; auth != nil {
			refs = append(refs, auth.CredentialSecretRef, auth.TrustedCASecretRef)
		}
	case *sdnv1alpha1.VPNConnection:
		if wg := obj.Spec.WireGuard; wg != nil {
			refs = append(refs, wg.PresharedKeySecretRef)
		}
		if auth := obj.Spec.IPsec; auth != nil {
			refs = append(refs, auth.Auth.PSKSecretRef)
			if auth.Auth.EAP != nil {
				refs = append(refs, auth.Auth.EAP.SecretRef)
			}
		}
	}
	var out []string
	for _, ref := range refs {
		if !vpnlimits.ObjectName(ref) {
			continue
		}
		duplicate := false
		for _, existing := range out {
			duplicate = duplicate || existing == ref
		}
		if !duplicate {
			out = append(out, ref)
		}
	}
	return out
}

func vpnConnectionEvents() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		old, oldOK := e.ObjectOld.(*sdnv1alpha1.VPNConnection)
		current, currentOK := e.ObjectNew.(*sdnv1alpha1.VPNConnection)
		if !oldOK || !currentOK {
			return false
		}
		return old.UID != current.UID || old.DeletionTimestamp.IsZero() != current.DeletionTimestamp.IsZero() || !equality.Semantic.DeepEqual(old.Spec, current.Spec)
	}}
}

func vpnConnectionGatewayKeys(obj client.Object) []string {
	c, ok := obj.(*sdnv1alpha1.VPNConnection)
	if !ok || !vpnlimits.ObjectName(c.Spec.GatewayRef.Name) || !c.DeletionTimestamp.IsZero() {
		return nil
	}
	return []string{c.Spec.GatewayRef.Name}
}
