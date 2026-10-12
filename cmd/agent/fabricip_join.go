package main

import (
	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

// fabricClaimsForNodeSandbox finds the launcher claims for a local target.
// The Pod UID is learned from these claims and verified against the live Pod.
func fabricClaimsForNodeSandbox(store cache.Indexer, node, namespace, containerID string) ([]*localv1.FabricIP, error) {
	if node == "" || namespace == "" || containerID == "" {
		return nil, nil
	}
	claims, err := store.ByIndex(fabricNodeSandboxIndex, fabricTupleKey(node, namespace, containerID))
	if err != nil {
		return nil, err
	}
	out := make([]*localv1.FabricIP, 0, len(claims))
	for _, obj := range claims {
		claim, ok := obj.(*localv1.FabricIP)
		if !ok || claim == nil {
			continue
		}
		if claim.Spec.Node == node && claim.Spec.PodNamespace == namespace && claim.Spec.ContainerID == containerID {
			out = append(out, claim)
		}
	}
	return out, nil
}
