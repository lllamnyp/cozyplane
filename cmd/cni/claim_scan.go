package main

import (
	"context"
	"fmt"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Visitors build temporary state only; callers may act after a complete scan.
func walkPortClaims(ctx context.Context, client sdnclientset.Interface, selector string, visit func(*sdnv1.Port)) error {
	return ipam.WalkClaims(ctx, func(limit int64, token string) ([]sdnv1.Port, string, error) {
		list, err := client.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: limit, Continue: token})
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}, visit)
}

func findUniquePort(ctx context.Context, client sdnclientset.Interface, selector string, matches func(*sdnv1.Port) bool) (*sdnv1.Port, error) {
	var found *sdnv1.Port
	ambiguous := false
	err := walkPortClaims(ctx, client, selector, func(port *sdnv1.Port) {
		if matches != nil && !matches(port) {
			return
		}
		if found != nil {
			ambiguous = true
			return
		}
		copy := *port // do not retain the page's backing array
		found = &copy
	})
	if err != nil {
		return nil, err
	}
	if ambiguous {
		return nil, fmt.Errorf("multiple Ports claim the same attachment identity")
	}
	return found, nil
}

func lookupEffectiveGateway(ctx context.Context, client sdnclientset.Interface, namespace, vpcName string) (*sdnv1.VPCGateway, error) {
	var best *sdnv1.VPCGateway
	err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]sdnv1.VPCGateway, string, error) {
		list, err := client.SdnV1alpha1().VPCGateways(namespace).List(ctx, metav1.ListOptions{Limit: limit, Continue: token})
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}, func(gateway *sdnv1.VPCGateway) {
		if gateway.Namespace != namespace || gateway.Spec.VPCRef.Name != vpcName || !gateway.DeletionTimestamp.IsZero() {
			return
		}
		if best != nil {
			pair := [2]sdnv1.VPCGateway{*best, *gateway}
			if sdnv1.EffectiveGateway(pair[:], vpcName) != &pair[1] {
				return
			}
		}
		copy := *gateway
		best = &copy
	})
	if err != nil {
		return nil, err
	}
	return best, nil
}
