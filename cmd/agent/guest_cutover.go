package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lllamnyp/cozyplane/datapath"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	"k8s.io/client-go/kubernetes"
	"net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/podlabels"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

type guestSandboxBinding struct{ namespace, name, uid, containerID, ifName, podLabels string }

func guestBindingForVeth(ctx context.Context, core kubernetes.Interface, factory localinformers.SharedInformerFactory, port *sdnv1alpha1.Port, v datapath.LocalPortVeth, self string) (guestSandboxBinding, error) {
	var empty guestSandboxBinding
	veths, err := datapath.ListLocalPortVeths()
	if err != nil {
		return empty, err
	}
	live := false
	for _, current := range veths {
		if current.Ifindex != v.Ifindex || current.RawNet == datapath.QuarantineNet || current.PortUID != string(port.UID) || current.ContainerID != v.ContainerID || current.IfName != v.IfName || current.Net != v.Net {
			continue
		}
		for _, ip := range current.IPs {
			live = live || ip.Equal(net.ParseIP(port.Spec.IP))
		}
	}
	if !live {
		return empty, fmt.Errorf("guest endpoint ownership changed")
	}
	claims, err := fabricClaimsForNodeSandbox(factory.Local().V1alpha1().FabricIPs().Informer().GetIndexer(), self, port.Spec.PodNamespace, v.ContainerID)
	if err != nil {
		return empty, err
	}
	for _, claim := range claims {
		if claim.Spec.ContainerID != v.ContainerID || claim.Spec.Node != self {
			continue
		}
		pod, err := launcherClaimPod(ctx, core, claim, port, v, self)
		if err != nil {
			return empty, err
		}
		if pod == nil {
			continue
		}
		currentAddress := pod.Status.PodIP == claim.Spec.Address
		for _, ip := range pod.Status.PodIPs {
			currentAddress = currentAddress || ip.IP == claim.Spec.Address
		}
		if !currentAddress {
			continue
		}
		encoded, err := podlabels.Encode(pod.Labels)
		if err != nil {
			return empty, err
		}
		return guestSandboxBinding{namespace: pod.Namespace, name: pod.Name, uid: string(pod.UID), containerID: v.ContainerID, ifName: v.IfName, podLabels: encoded}, nil
	}
	return empty, fmt.Errorf("guest sandbox has no current launcher FabricIP claim")
}

func claimPortOnGuestAnnouncement(ctx context.Context, client sdnclientset.Interface, expected *sdnv1alpha1.Port, node, nodeIP string, bindings ...guestSandboxBinding) (bool, error) {
	current, err := client.SdnV1alpha1().Ports().Get(ctx, expected.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if current.UID != expected.UID || current.ResourceVersion != expected.ResourceVersion || current.DeletionTimestamp != nil || current.Labels[sdnv1alpha1.LabelVMName] == "" || current.Spec != expected.Spec || current.Spec.Node == node {
		return false, nil
	}
	metadata := map[string]any{"uid": current.UID, "resourceVersion": current.ResourceVersion}
	spec := map[string]string{"node": node, "nodeIP": nodeIP}
	if len(bindings) > 0 {
		b := bindings[0]
		if b.namespace == "" || b.name == "" || b.uid == "" || b.containerID == "" || b.ifName == "" {
			return false, fmt.Errorf("incomplete guest sandbox binding")
		}
		metadata["labels"] = map[string]string{sdnv1alpha1.LabelPodNamespace: b.namespace, sdnv1alpha1.LabelPodName: b.name, sdnv1alpha1.LabelPodUID: b.uid}
		metadata["annotations"] = map[string]string{sdnv1alpha1.AnnotationContainerID: b.containerID, sdnv1alpha1.AnnotationCNIIfName: b.ifName, sdnv1alpha1.AnnotationPodLabels: b.podLabels}
		spec["podNamespace"] = b.namespace
		spec["podName"] = b.name
	}
	patch, err := json.Marshal(map[string]any{"metadata": metadata, "spec": spec})
	if err != nil {
		return false, err
	}
	_, err = client.SdnV1alpha1().Ports().Patch(ctx, current.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err == nil, err
}
