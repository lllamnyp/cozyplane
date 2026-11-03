package main

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

type fabricRemoteWriter interface {
	SetRemote(uint32, string, net.IP) error
	DelRemote(uint32, string) error
	PruneFabricRemotes([]string) error
}

type fabricRemoteReconciler struct {
	mu       sync.Mutex
	store    cache.Store
	writer   fabricRemoteWriter
	nodeIPOf func(string) net.IP
	self     string
	log      *slog.Logger
}

// reconcileLocked rereads cache truth instead of trusting an event's old object.
func (r *fabricRemoteReconciler) reconcileLocked(key, previous string) error {
	obj, found, err := r.store.GetByKey(key)
	if err != nil {
		return err
	}
	fip, valid := obj.(*localv1alpha1.FabricIP)
	current := ""
	if found && valid && fip.DeletionTimestamp == nil && net.ParseIP(fip.Spec.Address) != nil {
		current = fip.Spec.Address
	}
	if previous != "" && net.ParseIP(previous) != nil && previous != current {
		if err := r.writer.DelRemote(0, hostCIDR(previous)); err != nil {
			return err
		}
	}
	if current == "" {
		return nil
	}
	node := r.nodeIPOf(fip.Spec.Node)
	if fip.Spec.Node == "" || fip.Spec.Node == r.self || node == nil || node.To4() == nil {
		return r.writer.DelRemote(0, hostCIDR(current))
	}
	return r.writer.SetRemote(0, hostCIDR(current), node)
}

func (r *fabricRemoteReconciler) apply(obj any) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	fip, ok := obj.(*localv1alpha1.FabricIP)
	if !ok {
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(fip)
	if err != nil {
		r.log.Error("fabric route cache key", "err", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reconcileLocked(key, fip.Spec.Address); err != nil {
		r.log.Error("reconcile fabric route", "claim", key, "err", err)
	}
}

func (r *fabricRemoteReconciler) resync() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.resyncLocked(); err != nil {
		r.log.Error("resync fabric routes", "err", err)
	}
}

func (r *fabricRemoteReconciler) resyncLocked() error {
	for _, obj := range r.store.List() {
		fip, ok := obj.(*localv1alpha1.FabricIP)
		if !ok {
			continue
		}
		key, err := cache.MetaNamespaceKeyFunc(fip)
		if err != nil {
			return err
		}
		if err := r.reconcileLocked(key, fip.Spec.Address); err != nil {
			return err
		}
	}
	return nil
}

func (r *fabricRemoteReconciler) syncInitial() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var cidrs []string
	for _, obj := range r.store.List() {
		if fip, ok := obj.(*localv1alpha1.FabricIP); ok && fip.DeletionTimestamp == nil && net.ParseIP(fip.Spec.Address) != nil {
			cidrs = append(cidrs, hostCIDR(fip.Spec.Address))
		}
	}
	if err := r.writer.PruneFabricRemotes(cidrs); err != nil {
		return fmt.Errorf("prune fabric routes: %w", err)
	}
	return r.resyncLocked()
}
