package main

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
)

func verifiedVMName(ctx context.Context, pod *corev1.Pod, client dynamic.Interface) (string, error) {
	name := pod.Labels[sdnv1alpha1.KubeVirtLabelVMName]
	if name == "" {
		return "", nil
	}
	owner := vmidentity.LauncherOwner(pod, name)
	if owner == nil {
		return "", fmt.Errorf("VM label requires a protected VMI controller reference")
	}
	vmi, err := client.Resource(schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}).
		Namespace(pod.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("verify VMI ownership: %w", err)
	}
	if vmi.GetUID() != owner.UID || vmi.GetDeletionTimestamp() != nil {
		return "", fmt.Errorf("VMI identity changed or is terminating")
	}
	pod.Labels[vmidentity.CreatedByLabel] = string(owner.UID)
	return name, nil
}

func dynamicClient() (dynamic.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", datapath.PluginKubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.Timeout = apiRequestTimeout
	return dynamic.NewForConfig(cfg)
}
