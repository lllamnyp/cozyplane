package main

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"net"
	"time"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const legacyOwnershipReadTimeout = 5 * time.Second

// A VPC address identifies a route, not its current owner. Legacy migration
// targets require a sandbox claim and a protected VMI owner before adoption.
func legacyVethOwnsPort(ctx context.Context, core kubernetes.Interface, claims []*localv1.FabricIP, port *sdnv1alpha1.Port, v datapath.LocalPortVeth, self string) (bool, error) {
	if v.ContainerID == "" || v.IfName == "" {
		return false, nil
	}
	if port.Spec.Node == self && v.ContainerID == port.Annotations[sdnv1alpha1.AnnotationContainerID] && v.IfName == port.Annotations[sdnv1alpha1.AnnotationCNIIfName] {
		return true, nil
	}
	for _, claim := range claims {
		pod, err := launcherClaimPod(ctx, core, claim, port, v, self)
		if err != nil {
			return false, err
		}
		if pod != nil {
			return true, nil
		}
	}
	return false, nil
}

func launcherClaimPod(ctx context.Context, core kubernetes.Interface, claim *localv1.FabricIP, port *sdnv1alpha1.Port, v datapath.LocalPortVeth, self string) (*corev1.Pod, error) {
	uid := types.UID(port.Labels[vmidentity.InstanceUIDLabel])
	if uid == "" {
		uid = vmidentity.SnapshotUID(port.Annotations[sdnv1alpha1.AnnotationPodLabels])
	}
	if uid == "" || v.ContainerID == "" || v.IfName == "" || claim.Spec.Node != self || claim.Spec.PodNamespace != port.Spec.PodNamespace || claim.Spec.ContainerID != v.ContainerID || claim.DeletionTimestamp != nil {
		return nil, nil
	}
	if iface := port.Annotations[sdnv1alpha1.AnnotationCNIIfName]; port.Annotations[sdnv1alpha1.AnnotationCNIPrimary] == "true" || iface == "" {
		if claim.Spec.IfName != v.IfName {
			return nil, nil
		}
	} else if iface != v.IfName {
		return nil, nil
	}
	// Reconciliation also calls this join with the long-lived agent context,
	// before any guest worker can supply its own cutover deadline.
	readCtx, cancel := context.WithTimeout(ctx, legacyOwnershipReadTimeout)
	defer cancel()
	pod, err := core.CoreV1().Pods(claim.Spec.PodNamespace).Get(readCtx, claim.Spec.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if string(pod.UID) != claim.Spec.PodUID || pod.Spec.NodeName != self || pod.DeletionTimestamp != nil {
		return nil, nil
	}
	owner := vmidentity.LauncherOwner(pod, port.Labels[sdnv1alpha1.LabelVMName])
	if owner == nil || owner.UID != uid {
		return nil, nil
	}
	return pod, nil
}

func ownedPortVeths(ctx context.Context, core kubernetes.Interface, localFactory localinformers.SharedInformerFactory, port *sdnv1alpha1.Port, self string, inventory ...[]datapath.LocalPortVeth) ([]datapath.LocalPortVeth, error) {
	vni, ok := vniFromPortName(port.Name)
	if !ok {
		return nil, fmt.Errorf("invalid Port VNI")
	}
	var veths []datapath.LocalPortVeth
	var err error
	if len(inventory) > 0 {
		veths = inventory[0]
	} else {
		veths, err = datapath.ListLocalPortVeths()
		if err != nil {
			return nil, err
		}
	}
	var out []datapath.LocalPortVeth
	for _, v := range veths {
		if v.RawNet == datapath.QuarantineNet && v.PortUID == string(port.UID) && v.PortUID != "" {
			out = append(out, v)
			continue
		}
		if v.Net != vni || v.RawNet == datapath.QuarantineNet || v.RawNet&datapath.PortGatewayFlag != 0 {
			continue
		}
		matches := false
		for _, ip := range v.IPs {
			matches = matches || ip.Equal(net.ParseIP(port.Spec.IP))
		}
		if !matches {
			continue
		}
		if v.PortUID != "" {
			if v.PortUID == string(port.UID) {
				out = append(out, v)
			}
			continue
		}
		if !localFactory.Local().V1alpha1().FabricIPs().Informer().HasSynced() {
			return nil, fmt.Errorf("FabricIP ownership cache not ready")
		}
		claims, err := fabricClaimsForNodeSandbox(localFactory.Local().V1alpha1().FabricIPs().Informer().GetIndexer(), self, port.Spec.PodNamespace, v.ContainerID)
		if err != nil {
			return nil, err
		}
		owned, err := legacyVethOwnsPort(ctx, core, claims, port, v, self)
		if err != nil {
			return nil, err
		}
		if !owned {
			return nil, fmt.Errorf("cannot prove ownership of legacy endpoint %d", v.Ifindex)
		}
		v.Alias, err = datapath.AdoptVethPortIdentity(v.Ifindex, v.Alias, datapath.PortVethIdentity{UID: string(port.UID), Staged: port.Spec.Node != self})
		if err != nil {
			return nil, err
		}
		v.PortUID = string(port.UID)
		out = append(out, v)
	}
	return out, nil
}
