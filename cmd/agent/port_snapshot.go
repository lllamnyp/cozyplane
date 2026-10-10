package main

import (
	"fmt"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

// currentPortSnapshot treats notifications as cache keys, never as authority to
// overwrite or remove the route of a newer Port generation.
func currentPortSnapshot(store cache.Store, event *sdnv1alpha1.Port) (*sdnv1alpha1.Port, bool, error) {
	key, err := cache.MetaNamespaceKeyFunc(event)
	if err != nil {
		return nil, false, err
	}
	obj, found, err := store.GetByKey(key)
	if err != nil || !found {
		return nil, found, err
	}
	port, ok := obj.(*sdnv1alpha1.Port)
	if !ok {
		return nil, false, fmt.Errorf("unexpected Port cache object %T", obj)
	}
	return port, true, nil
}
