package sdn

import (
	"context"
	"errors"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fenceWGClientStateFailure revokes authorization even when allocation state
// cannot be read or saved. Preserve workloads and their pod witnesses so a
// later successful read can still prove teardown before any lease is released.
func (r *VPNGatewayReconciler) fenceWGClientStateFailure(ctx context.Context, gw *sdn.VPNGateway, cause error) error {
	primary := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace}}
	primaryErr := r.deleteVPNOwned(ctx, gw, primary)
	bindingsErr := r.pruneVPCBindings(ctx, gw, nil)
	statusErr := r.invalidateWGClientStatuses(ctx, gw, "AllocationStateUnavailable", "client authorization revoked while allocation state is unavailable")
	return wgClientStateFenceError{cause: errors.Join(cause, primaryErr, bindingsErr, statusErr)}
}

// Do not put API response payloads or state/credential contents in controller
// logs. The original causes remain available for errors.Is/As and retries.
type wgClientStateFenceError struct{ cause error }

func (wgClientStateFenceError) Error() string {
	return "WireGuard allocation state unavailable; authorization fencing attempted and leases retained"
}

func (e wgClientStateFenceError) Unwrap() error { return e.cause }
