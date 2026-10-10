package sdn

import (
	"context"
	"fmt"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const wgClientPortWitnesses = 640

// Keep the exact Port UID across a lost/force-deleted Pod object. Port deletion
// completes only after the node's existing sever acknowledgement, so API Pod
// disappearance must not allow an address to be reassigned to another client.
func (r *VPNGatewayReconciler) rememberWGClientPorts(ctx context.Context, gw *sdn.VPNGateway, record *wgClientGatewayReservation, pods *corev1.PodList) error {
	if len(record.PortUIDs) > wgClientPortWitnesses || len(record.PodUIDs) > 64 || pods == nil || len(pods.Items) > wgClientStateRecords {
		return fmt.Errorf("WireGuard port witness scan exceeds budget")
	}
	witnesses := make(map[string]string, len(record.PortUIDs))
	for name, uid := range record.PortUIDs {
		witnesses[name] = uid
	}
	work := 0
	remember := func(port *sdn.Port) error {
		if port.Spec.PodNamespace != gw.Namespace {
			return nil
		}
		if port.UID == "" {
			return fmt.Errorf("WireGuard appliance Port has no UID")
		}
		// A replacement UID proves the previous Port completed deletion.
		witnesses[port.Name] = string(port.UID)
		if len(witnesses) > wgClientPortWitnesses {
			return fmt.Errorf("WireGuard port witnesses exceed budget")
		}
		return nil
	}
	// A Pod or one of its VPC legs may disappear from the informer cache first.
	// Query every protected Pod UID live so partially delivered secondary legs
	// cannot escape the witness. This still works after Pod API force-deletion;
	// complete zero permits bootstrap and cleanup after Ports were severed.
	for _, uid := range record.PodUIDs {
		if uid == "" || len(uid) > 253 {
			return fmt.Errorf("invalid WireGuard Pod witness")
		}
		ports := &sdn.PortList{}
		if err := r.quotaReader().List(ctx, ports, client.MatchingLabels{sdn.LabelPodUID: uid}, client.Limit(wgClientPortWitnesses-work+1)); err != nil {
			return err
		}
		work += len(ports.Items)
		if ports.Continue != "" || work > wgClientPortWitnesses {
			return fmt.Errorf("WireGuard live port witness scan exceeds budget")
		}
		for i := range ports.Items {
			if ports.Items[i].Labels[sdn.LabelPodUID] != uid {
				return fmt.Errorf("WireGuard live Port query returned an unrelated UID")
			}
			if err := remember(&ports.Items[i]); err != nil {
				return err
			}
		}
	}
	record.PortUIDs = witnesses
	return nil
}

func (r *VPNGatewayReconciler) activeWGClientPodUIDs(ctx context.Context, gw *sdn.VPNGateway, pods *corev1.PodList) (map[string]bool, error) {
	if pods == nil || len(pods.Items) > wgClientStateRecords {
		return nil, fmt.Errorf("WireGuard current pod scan exceeds budget")
	}
	uids := map[string]bool{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Namespace == gw.Namespace && pod.UID != "" && pod.DeletionTimestamp.IsZero() && pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed && r.appliancePodOwned(ctx, gw, pod) {
			uids[string(pod.UID)] = true
		}
	}
	if len(uids) > 64 {
		return nil, fmt.Errorf("WireGuard current pod witnesses exceed budget")
	}
	return uids, nil
}

// currentWGClientPorts returns only current Port witnesses after the caller has
// independently confirmed the exact applied configuration of every current pod.
func (r *VPNGatewayReconciler) currentWGClientPorts(ctx context.Context, gw *sdn.VPNGateway, record wgClientGatewayReservation, currentPods *corev1.PodList) (map[string]string, error) {
	active, err := r.activeWGClientPodUIDs(ctx, gw, currentPods)
	if err != nil {
		return nil, err
	}
	if len(record.PortUIDs) > wgClientPortWitnesses {
		return nil, fmt.Errorf("WireGuard port witnesses exceed budget")
	}
	current := map[string]string{}
	for name, uid := range record.PortUIDs {
		port := &sdn.Port{}
		err := r.quotaReader().Get(ctx, client.ObjectKey{Name: name}, port)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if string(port.UID) == uid && port.DeletionTimestamp.IsZero() && port.Spec.PodNamespace == gw.Namespace && active[port.Labels[sdn.LabelPodUID]] {
			current[name] = uid
		}
	}
	return current, nil
}

func (r *VPNGatewayReconciler) wgClientPortsRevoked(ctx context.Context, gw *sdn.VPNGateway, record wgClientGatewayReservation, currentPods *corev1.PodList) (bool, error) {
	active, err := r.activeWGClientPodUIDs(ctx, gw, currentPods)
	if err != nil {
		return false, err
	}
	if len(record.PortUIDs) > wgClientPortWitnesses {
		return false, fmt.Errorf("WireGuard port witnesses exceed budget")
	}
	for name, uid := range record.PortUIDs {
		if name == "" || uid == "" {
			return false, fmt.Errorf("invalid WireGuard Port witness")
		}
		port := &sdn.Port{}
		err := r.quotaReader().Get(ctx, client.ObjectKey{Name: name}, port)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if string(port.UID) != uid {
			continue
		}
		if !port.DeletionTimestamp.IsZero() || port.Spec.PodNamespace != gw.Namespace || !active[port.Labels[sdn.LabelPodUID]] {
			return false, nil
		}
	}
	return true, nil
}
