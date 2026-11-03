package sdn

import (
	"context"
	"errors"
	"fmt"
	"slices"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	ctrl "sigs.k8s.io/controller-runtime"
)

// The caller has completely enumerated, budgeted and filtered these peers.
// Compare only their prefix intent so successful reconciliations do not cycle
// Ready -> Pending -> Ready or erase a healthy leg on every informer event.
func (r *VPNGatewayReconciler) protectRouteIntent(ctx context.Context, gw *sdn.VPNGateway, conns []sdn.VPNConnection) error {
	if len(gw.Spec.AdditionalVPCRefs) > 9 || len(conns) > vpnlimits.RoutePrefixes {
		return fmt.Errorf("VPN route intent exceeds bounded input limits")
	}
	refs := append([]sdn.LocalVPCRef{gw.Spec.VPCRef}, gw.Spec.AdditionalVPCRefs...)
	prefixes, perVPC := 0, vpnlimits.RoutePrefixes/len(refs)
	for i := range conns {
		if len(conns[i].Spec.RemoteCIDRs) > perVPC-prefixes {
			return fmt.Errorf("hub route prefix candidates exceed %d", vpnlimits.RoutePrefixes)
		}
		prefixes += len(conns[i].Spec.RemoteCIDRs)
	}
	var desired []sdn.VPCGatewayRouteStatus
	for _, ref := range refs {
		for i := range conns {
			if !clientAllowsVPC(&conns[i], ref.Name) {
				continue
			}
			if cidrs := conns[i].Spec.RemoteCIDRs; len(cidrs) != 0 {
				desired = append(desired, sdn.VPCGatewayRouteStatus{VPCRef: ref, CIDRs: cidrs})
			}
		}
	}

	unchanged := len(gw.Status.Routes) == len(desired)
	if unchanged {
		for i := range desired {
			ref := gw.Status.Routes[i].VPCRef
			if ref.Name == "" {
				ref = gw.Spec.VPCRef
			}
			if ref != desired[i].VPCRef || !slices.Equal(gw.Status.Routes[i].CIDRs, desired[i].CIDRs) {
				unchanged = false
				break
			}
		}
	}
	if unchanged {
		return nil
	}
	routes, err := blackholeVPNRoutes(desired)
	if err != nil {
		return err
	}
	status := sdn.VPNGatewayStatus{Phase: sdn.VPNGatewayPhasePending, Routes: routes}
	for _, condition := range []string{sdn.VPNGatewayConditionApplianceReady, sdn.VPNGatewayConditionAddressAssigned, sdn.VPNGatewayConditionRoutesProgrammed} {
		setVPNGWCondition(&status, condition, false, "ConfigurationPending", "accepted prefixes are blocked until appliance configuration succeeds")
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = gw.Generation
	}
	gw.Status = status
	// Unlike an ordinary best-effort status refresh, a conflict here must
	// stop realization: the protected prefix publication has not succeeded.
	return r.Status().Update(ctx, gw)
}

func (r *VPNGatewayReconciler) configurationFailure(ctx context.Context, gw *sdn.VPNGateway, cause error) (ctrl.Result, error) {
	_, err := r.reportUnready(ctx, gw, "ConfigurationFailed", "appliance configuration failed; accepted prefixes remain blocked")
	return ctrl.Result{}, errors.Join(cause, err)
}
