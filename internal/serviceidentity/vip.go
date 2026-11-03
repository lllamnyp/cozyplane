package serviceidentity

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func MatchesService(vip *sdnv1alpha1.ServiceVIP, service *corev1.Service) bool {
	return vip != nil && service != nil && service.UID != "" &&
		vip.DeletionTimestamp.IsZero() && service.DeletionTimestamp.IsZero() &&
		vip.Spec.ServiceRef.Namespace == service.Namespace && vip.Spec.ServiceRef.Name == service.Name &&
		vip.Annotations[sdnv1alpha1.AnnotationServiceUID] == string(service.UID)
}

func MatchesVPC(vip *sdnv1alpha1.ServiceVIP, vpc *sdnv1alpha1.VPC) bool {
	return vip != nil && vpc != nil && vpc.UID != "" && vpc.Status.VNI > 0 && vpc.Status.VNI < 1<<22 &&
		vip.DeletionTimestamp.IsZero() && vpc.DeletionTimestamp.IsZero() &&
		vip.Spec.VPCRef.Namespace == vpc.Namespace && vip.Spec.VPCRef.Name == vpc.Name &&
		vip.Annotations[sdnv1alpha1.AnnotationVPCUID] == string(vpc.UID) &&
		vip.Name == sdn.ServiceVIPName(vpc.Status.VNI, vip.Spec.IP)
}
