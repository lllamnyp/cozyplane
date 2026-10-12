package sdn

import (
	"context"
	"fmt"
	"slices"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Gateway failure revokes published success regardless of the current backend:
// both the gateway and its peers may have changed since their last ready status.
func (r *VPNGatewayReconciler) invalidateGatewayConnectionStatuses(ctx context.Context, gw *sdn.VPNGateway, reason, message string) error {
	return r.invalidateVPNConnectionStatuses(ctx, gw, reason, message, func(*sdn.VPNConnection) bool { return true }, false)
}

// invalidateWGClientStatuses clears previously published setup parameters after
// realization has failed. Read live rather than through the active-peer cache:
// deleting connections and legacy invalid specifications still need revocation.
func (r *VPNGatewayReconciler) invalidateWGClientStatuses(ctx context.Context, gw *sdn.VPNGateway, reason, message string) error {
	return r.invalidateVPNConnectionStatuses(ctx, gw, reason, message, func(connection *sdn.VPNConnection) bool {
		return connection.Spec.WireGuard != nil && connection.Spec.WireGuard.Client != nil ||
			connection.Status.ClientConfig != nil || hasWGClientCondition(connection.Status.Conditions)
	}, true)
}

func (r *VPNGatewayReconciler) invalidateVPNConnectionStatuses(ctx context.Context, gw *sdn.VPNGateway, reason, message string,
	matches func(*sdn.VPNConnection) bool, clientConfig bool) error {
	var list sdn.VPNConnectionList
	if err := r.quotaReader().List(ctx, &list, client.InNamespace(gw.Namespace), client.Limit(wgClientStateRecords+1)); err != nil {
		return err
	}
	if list.Continue != "" || len(list.Items) > wgClientStateRecords {
		return fmt.Errorf("VPN connection status revocation scan exceeds budget")
	}
	for i := range list.Items {
		connection := &list.Items[i]
		if connection.Spec.GatewayRef.Name != gw.Name {
			continue
		}
		if !matches(connection) {
			continue
		}
		previous := connection.Status
		previous.Conditions = slices.Clone(previous.Conditions)
		if clientConfig || connection.Spec.WireGuard != nil && connection.Spec.WireGuard.Client != nil ||
			connection.Status.ClientConfig != nil || hasWGClientCondition(connection.Status.Conditions) {
			connection.Status.ClientConfig = nil
			setConnCondition(&connection.Status, sdn.VPNConnectionConditionClientConfigured, false, reason, message)
		}
		connection.Status.Phase = sdn.VPNConnectionPhasePending
		for _, condition := range []string{
			sdn.VPNConnectionConditionRoutesProgrammed,
			sdn.VPNConnectionConditionEstablished,
		} {
			setConnCondition(&connection.Status, condition, false, reason, message)
		}
		for j := range connection.Status.Conditions {
			connection.Status.Conditions[j].ObservedGeneration = connection.Generation
		}
		if connStatusEqual(previous, connection.Status) {
			continue
		}
		if err := r.Status().Update(ctx, connection); err != nil {
			return fmt.Errorf("invalidate VPN connection status: %w", err)
		}
	}
	return nil
}

func hasWGClientCondition(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type == sdn.VPNConnectionConditionClientConfigured {
			return true
		}
	}
	return false
}
