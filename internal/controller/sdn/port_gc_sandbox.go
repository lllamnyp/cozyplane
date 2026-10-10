package sdn

import (
	"context"
	"fmt"
	"net"
	"time"

	local "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const portSandboxGracePeriod = 5 * time.Minute

// One reconciliation reuses a proof only for the same immutable pod version.
// The map is discarded on return; it does not retain historical pod versions.
type podSandboxSnapshot map[string]string

func (s podSandboxSnapshot) forPod(ctx context.Context, reader client.Reader, pod *corev1.Pod) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := string(pod.UID) + "/" + pod.ResourceVersion
	if sandbox, ok := s[key]; ok {
		return sandbox, nil
	}
	sandbox, err := currentPodSandbox(ctx, reader, pod, "eth0")
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s[key] = sandbox
	return sandbox, nil
}

func (r *PortGCReconciler) reapObsoleteSandbox(ctx context.Context, port *sdn.Port, pod *corev1.Pod) (ctrl.Result, error) {
	containerID := port.Annotations[sdn.AnnotationContainerID]
	ifName := port.Annotations[sdn.AnnotationCNIIfName]
	if containerID == "" || ifName != "eth0" || port.CreationTimestamp.IsZero() ||
		port.Labels[sdn.LabelPodUID] == "" || string(pod.UID) != port.Labels[sdn.LabelPodUID] || pod.Status.Phase != corev1.PodRunning {
		return ctrl.Result{}, nil
	}
	if remaining := portSandboxGracePeriod - time.Since(port.CreationTimestamp.Time); remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, nil
	}
	current, err := currentPodSandbox(ctx, r.Client, pod, ifName)
	if err != nil || current == "" || current == containerID {
		return ctrl.Result{}, err
	}
	// Only stale candidates incur live reads. Cache absence/legacy state never
	// authorizes deletion; FabricIP/Pod events revisit this indexed claimant.
	livePod := &corev1.Pod{}
	if err := r.reader().Get(ctx, client.ObjectKeyFromObject(pod), livePod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if livePod.UID != pod.UID || livePod.Status.Phase != corev1.PodRunning {
		return ctrl.Result{}, nil
	}
	current, err = currentPodSandbox(ctx, r.reader(), livePod, ifName)
	if err != nil || current == "" || current == containerID {
		return ctrl.Result{}, err
	}
	if err := r.Delete(ctx, port, client.Preconditions{UID: &port.UID, ResourceVersion: &port.ResourceVersion}); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("gc obsolete sandbox Port: %w", err)
	}
	log.FromContext(ctx).Info("GC'd obsolete sandbox Port", "port", port.Name, "pod", client.ObjectKeyFromObject(pod))
	return ctrl.Result{}, nil
}

// currentPodSandbox returns a witness only when every current status address
// agrees. Dual-stack transitions, missing/legacy claims and malformed status
// cannot identify a sandbox safely. At most two individual claims are read.
func currentPodSandbox(ctx context.Context, reader client.Reader, pod *corev1.Pod, ifName string) (string, error) {
	if len(pod.Status.PodIPs) == 0 || len(pod.Status.PodIPs) > 2 || pod.Spec.NodeName == "" {
		return "", nil
	}
	containerID := ""
	for _, address := range pod.Status.PodIPs {
		ip := net.ParseIP(address.IP)
		if ip == nil {
			return "", nil
		}
		claim := &local.FabricIP{}
		if err := reader.Get(ctx, client.ObjectKey{Name: local.FabricIPName(ip.String())}, claim); err != nil {
			return "", client.IgnoreNotFound(err)
		}
		if !claim.DeletionTimestamp.IsZero() || claim.Spec.ContainerID == "" || claim.Spec.IfName != ifName ||
			claim.Spec.PodUID != string(pod.UID) || claim.Spec.PodNamespace != pod.Namespace || claim.Spec.PodName != pod.Name ||
			claim.Spec.Node != pod.Spec.NodeName || !ip.Equal(net.ParseIP(claim.Spec.Address)) {
			return "", nil
		}
		if containerID != "" && containerID != claim.Spec.ContainerID {
			return "", nil
		}
		containerID = claim.Spec.ContainerID
	}
	return containerID, nil
}
