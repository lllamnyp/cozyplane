package main

import (
	"context"
	"fmt"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func lookupAttachmentVPC(ctx context.Context, client sdnclientset.Interface, namespace, name string) (*sdnv1alpha1.VPC, error) {
	vpc, err := client.SdnV1alpha1().VPCs(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get vpc %s/%s: %w", namespace, name, err)
	}
	if err := validateAttachmentVPC(vpc); err != nil {
		return nil, err
	}
	return vpc, nil
}

func validateAttachmentVPC(vpc *sdnv1alpha1.VPC) error {
	if vpc == nil {
		return fmt.Errorf("attachment has no resolved VPC")
	}
	if !vpc.DeletionTimestamp.IsZero() {
		return fmt.Errorf("vpc %s/%s is terminating", vpc.Namespace, vpc.Name)
	}
	if vpc.Status.VNI <= 0 {
		return fmt.Errorf("vpc %s/%s is not ready (no positive VNI assigned)", vpc.Namespace, vpc.Name)
	}
	if err := sdnv1alpha1.ValidateVPCCIDRs(vpc.Spec.CIDRs); err != nil {
		return err
	}
	return nil
}
