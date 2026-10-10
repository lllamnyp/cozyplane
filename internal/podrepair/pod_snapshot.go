package podrepair

import (
	"context"
	"fmt"
	"net"

	"github.com/lllamnyp/cozyplane/internal/ipam"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

// LocalPodAddress retains only the identity needed for a missing-claim repair.
// Pod specifications, annotations and unrelated addresses are not retained.
type LocalPodAddress struct {
	Address, Namespace, Name, UID string
}

// ListLocalRunningPodAddresses selects candidate addresses from a complete,
// bounded Pod snapshot. No repair is authorized by a partial or ambiguous list.
func ListLocalRunningPodAddresses(ctx context.Context, core kubernetes.Interface, node string, candidates map[string]struct{}) ([]LocalPodAddress, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	selected := make(map[string]LocalPodAddress)
	ambiguous := make(map[string]bool)
	selector := fields.AndSelectors(fields.OneTermEqualSelector("spec.nodeName", node), fields.OneTermEqualSelector("status.phase", string(corev1.PodRunning))).String()
	err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]corev1.Pod, string, error) {
		list, err := core.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: selector, Limit: limit, Continue: token})
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}, func(pod *corev1.Pod) {
		if pod.Spec.NodeName != node || pod.Spec.HostNetwork || !pod.DeletionTimestamp.IsZero() || pod.UID == "" || pod.Status.Phase != corev1.PodRunning {
			return
		}
		selectAddress := func(raw string) {
			ip := net.ParseIP(raw)
			if ip == nil {
				return
			}
			address := ip.String()
			if _, ok := candidates[address]; !ok || ambiguous[address] {
				return
			}
			owner := LocalPodAddress{Address: address, Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)}
			if previous, ok := selected[address]; ok && previous != owner {
				delete(selected, address)
				ambiguous[address] = true
				return
			}
			selected[address] = owner
		}
		if len(pod.Status.PodIPs) == 0 {
			selectAddress(pod.Status.PodIP)
		} else {
			for _, address := range pod.Status.PodIPs {
				selectAddress(address.IP)
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("list local pods for fabric repair: %w", err)
	}
	result := make([]LocalPodAddress, 0, len(selected))
	for _, owner := range selected {
		result = append(result, owner)
	}
	return result, nil
}
