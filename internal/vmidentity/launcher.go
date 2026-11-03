// Package vmidentity verifies the identity behind a persistent VM network port.
package vmidentity

import (
	"encoding/json"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	InstanceUIDLabel = "sdn.cozystack.io/vmi-uid"
	CreatedByLabel   = sdnv1alpha1.KubeVirtLabelVMIUID
)

// LauncherOwner requires the real controller reference, including the deletion
// blocking flag protected by OwnerReferencesPermissionEnforcement. Labels alone
// never confer the right to bind another workload's persistent address.
func LauncherOwner(pod *corev1.Pod, vmName string) *metav1.OwnerReference {
	ref := metav1.GetControllerOf(pod)
	if vmName == "" || ref == nil || ref.APIVersion != "kubevirt.io/v1" ||
		ref.Kind != "VirtualMachineInstance" || ref.Name != vmName || ref.UID == "" ||
		ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		return nil
	}
	return ref
}

// SnapshotUID also supports Ports created before the dedicated VMI UID label.
// Their CNI-authored label snapshot already carries KubeVirt's instance UID.
func SnapshotUID(raw string) types.UID {
	var labels map[string]string
	if json.Unmarshal([]byte(raw), &labels) != nil {
		return ""
	}
	return types.UID(labels[CreatedByLabel])
}
