package sdn

import (
	"context"
	"fmt"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const vpnQuotaScanTimeout = 30 * time.Second

// gatewayQuota computes a rank without retaining or sorting gateway payloads.
// Live pagination is a consistent snapshot; incomplete scans never admit.
func (r *VPNGatewayReconciler) gatewayQuota(ctx context.Context, gw *sdnv1alpha1.VPNGateway) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, vpnQuotaScanTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	total, older := 0, 0
	found := false
	var identityErr error
	visit := func(g *sdnv1alpha1.VPNGateway) {
		if g.Namespace != gw.Namespace {
			identityErr = fmt.Errorf("VPN gateway quota result escaped namespace")
			return
		}
		if !g.DeletionTimestamp.IsZero() {
			return
		}
		total++
		if g.Name == gw.Name {
			if g.UID != gw.UID || !g.CreationTimestamp.Equal(&gw.CreationTimestamp) {
				identityErr = fmt.Errorf("VPN gateway changed identity during quota lookup")
				return
			}
			found = true
		}
		if g.CreationTimestamp.Before(&gw.CreationTimestamp) || g.CreationTimestamp.Equal(&gw.CreationTimestamp) && g.Name < gw.Name {
			older++
		}
	}
	listPage := func(limit int64, token string) ([]sdnv1alpha1.VPNGateway, string, error) {
		if identityErr != nil {
			return nil, "", identityErr
		}
		var list sdnv1alpha1.VPNGatewayList
		if err := r.quotaReader().List(ctx, &list, client.InNamespace(gw.Namespace), client.Limit(limit), client.Continue(token)); err != nil {
			return nil, "", fmt.Errorf("list VPNGateways for quota: %w", err)
		}
		return list.Items, list.Continue, nil
	}
	if r.Reader != nil {
		if err := ipam.WalkClaims(ctx, listPage, visit); err != nil {
			return "", err
		}
	} else {
		// The cache cannot page. Below the requested limit the result is complete;
		// at saturation there is no proof that this gateway is among the oldest.
		items, token, err := listPage(ipam.ClaimPageSize, "")
		if err != nil {
			return "", err
		}
		if len(items) >= ipam.ClaimPageSize || token != "" && token != "continue-not-supported" {
			return "", fmt.Errorf("VPN gateway quota needs a live reader for a complete bounded snapshot")
		}
		for i := range items {
			visit(&items[i])
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if identityErr != nil {
		return "", identityErr
	}
	if !found {
		return "", fmt.Errorf("active VPN gateway missing from quota snapshot")
	}
	maxGW := r.maxGatewaysPerNamespace()
	if older >= maxGW {
		return fmt.Sprintf("namespace has %d VPN gateways, over the limit of %d (this one is #%d oldest)", total, maxGW, older+1), nil
	}
	return "", nil
}
