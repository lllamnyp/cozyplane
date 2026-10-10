package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

// A VPC endpoint wired by a CNI release that predates sandbox witnesses has no
// container ID in its veth alias, its FabricIP claim or its Port, so the current
// release can never prove who owns it: its SecurityGroup membership stays
// pending and every flow is refused until the pod is recreated. The container
// runtime's libcni result cache still names the sandbox. Recover it only when
// the CNI's deterministic veth name, the cached pod UID and the live pod all
// agree, then record it where the current release reads it. Anything unproven
// stays fail-closed.
const cniResultCacheDir = "/var/lib/cni/results"

// cniCacheEntry is the part of a libcni cniCacheV1 record the recovery trusts.
type cniCacheEntry struct {
	ContainerID, IfName, PodNamespace, PodName, PodUID string
}

const maxCNICacheRecord = 1 << 20 // a cache record carries a CNI result, not data

func readCNIResultCache(dir string) ([]cniCacheEntry, error) {
	files, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[cniCacheEntry]bool{}
	var out []cniCacheEntry
	for _, f := range files {
		if !f.Type().IsRegular() {
			continue
		}
		raw, err := readBounded(filepath.Join(dir, f.Name()), maxCNICacheRecord)
		if err != nil {
			continue // a record being rewritten or removed is simply not evidence
		}
		var rec struct {
			Kind        string     `json:"kind"`
			ContainerID string     `json:"containerId"`
			IfName      string     `json:"ifName"`
			CNIArgs     [][]string `json:"cniArgs"`
		}
		// The runtime also caches the sandbox's loopback attachment, with the same
		// container ID and pod identity; it never owns a cozyplane veth.
		if json.Unmarshal(raw, &rec) != nil || rec.Kind != "cniCacheV1" || rec.ContainerID == "" || rec.IfName == "" || rec.IfName == "lo" {
			continue
		}
		e := cniCacheEntry{ContainerID: rec.ContainerID, IfName: rec.IfName}
		for _, kv := range rec.CNIArgs {
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "K8S_POD_NAMESPACE":
				e.PodNamespace = kv[1]
			case "K8S_POD_NAME":
				e.PodName = kv[1]
			case "K8S_POD_UID":
				e.PodUID = kv[1]
			}
		}
		if e.PodNamespace == "" || e.PodName == "" || e.PodUID == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("cache record too large")
	}
	return raw, nil
}

// legacySandboxFor returns the one cached sandbox whose CNI-derived primary veth
// name is this endpoint's. Zero or several candidates prove nothing.
func legacySandboxFor(v datapath.LocalPortVeth, entries []cniCacheEntry) (cniCacheEntry, bool) {
	var found []cniCacheEntry
	for _, e := range entries {
		if datapath.PodVethName(e.ContainerID) == v.Name {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		return cniCacheEntry{}, false
	}
	return found[0], true
}

// isLegacyVPCEndpoint selects the endpoints this recovery may touch: an active
// VPC leg whose alias records no sandbox at all.
func isLegacyVPCEndpoint(v datapath.LocalPortVeth) bool {
	return v.Net != 0 && v.RawNet != datapath.QuarantineNet && v.RawNet&datapath.PortGatewayFlag == 0 &&
		v.ContainerID == "" && v.IfName == ""
}

// recoverLegacySandboxes runs a pass now and then every interval.
func recoverLegacySandboxes(ctx context.Context, core kubernetes.Interface, local localclientset.Interface, sdn sdnclientset.Interface, node string, interval time.Duration, log *slog.Logger) {
	for {
		if err := recoverLegacySandboxesOnce(ctx, core, local, sdn, node, log); err != nil {
			log.Warn("legacy sandbox recovery pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func recoverLegacySandboxesOnce(ctx context.Context, core kubernetes.Interface, local localclientset.Interface, sdn sdnclientset.Interface, node string, log *slog.Logger) error {
	veths, err := datapath.ListLocalPortVeths()
	if err != nil {
		return err
	}
	var legacy []datapath.LocalPortVeth
	for _, v := range veths {
		if isLegacyVPCEndpoint(v) {
			legacy = append(legacy, v)
		}
	}
	if len(legacy) == 0 {
		return nil
	}
	entries, err := readCNIResultCache(cniResultCacheDir)
	if err != nil {
		return err
	}
	for _, v := range legacy {
		e, ok := legacySandboxFor(v, entries)
		if !ok {
			log.Warn("legacy VPC endpoint has no provable sandbox; restart its pod to re-wire it", "veth", v.Name)
			continue
		}
		if err := recoverLegacySandbox(ctx, core, local, sdn, node, v, e); err != nil {
			log.Warn("legacy sandbox recovery refused", "veth", v.Name, "pod", e.PodNamespace+"/"+e.PodName, "err", err)
			continue
		}
		log.Info("recovered legacy sandbox witness", "veth", v.Name, "pod", e.PodNamespace+"/"+e.PodName, "container", e.ContainerID, "ifname", e.IfName)
	}
	return nil
}

// recoverLegacySandbox records e on the pod's claims, then its Ports, then the
// veth. Each write fills only an absent witness under a UID/RV precondition, so
// an interrupted pass resumes; a different recorded sandbox is a conflict.
func recoverLegacySandbox(ctx context.Context, core kubernetes.Interface, local localclientset.Interface, sdn sdnclientset.Interface, node string, v datapath.LocalPortVeth, e cniCacheEntry) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pod, err := core.CoreV1().Pods(e.PodNamespace).Get(ctx, e.PodName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(pod.UID) != e.PodUID || pod.Spec.NodeName != node || pod.DeletionTimestamp != nil {
		return fmt.Errorf("cached sandbox does not belong to the live pod on this node")
	}
	for _, address := range podFabricAddrs(pod) {
		claim, err := local.LocalV1alpha1().FabricIPs().Get(ctx, localv1alpha1.FabricIPName(address), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue // the heal pass recreates it with the witness the veth now records
		}
		if err != nil {
			return err
		}
		if claim.Spec.PodUID != e.PodUID || claim.Spec.Node != node || claim.DeletionTimestamp != nil {
			return fmt.Errorf("claim %s belongs to another pod", claim.Name)
		}
		switch {
		case claim.Spec.ContainerID == e.ContainerID && claim.Spec.IfName == e.IfName:
			continue
		case claim.Spec.ContainerID != "" || claim.Spec.IfName != "":
			return fmt.Errorf("claim %s records another sandbox", claim.Name)
		}
		claim.Spec.ContainerID, claim.Spec.IfName = e.ContainerID, e.IfName
		if _, err := local.LocalV1alpha1().FabricIPs().Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("record sandbox on claim %s: %w", claim.Name, err)
		}
	}
	ports, err := sdn.SdnV1alpha1().Ports().List(ctx, metav1.ListOptions{LabelSelector: sdnv1alpha1.LabelPodUID + "=" + e.PodUID})
	if err != nil {
		return err
	}
	for i := range ports.Items {
		port := &ports.Items[i]
		if port.Spec.Node != node || port.DeletionTimestamp != nil || !vethCarries(v, port.Spec.IP) {
			continue
		}
		cid, iface := port.Annotations[sdnv1alpha1.AnnotationContainerID], port.Annotations[sdnv1alpha1.AnnotationCNIIfName]
		switch {
		case cid == e.ContainerID && iface == e.IfName:
			continue
		case cid != "" || iface != "":
			return fmt.Errorf("Port %s records another sandbox", port.Name)
		}
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"uid": port.UID, "resourceVersion": port.ResourceVersion,
			"annotations": map[string]string{sdnv1alpha1.AnnotationContainerID: e.ContainerID, sdnv1alpha1.AnnotationCNIIfName: e.IfName,
				sdnv1alpha1.AnnotationCNIPrimary: strconv.FormatBool(port.Spec.Primary)}}})
		if err != nil {
			return err
		}
		if _, err := sdn.SdnV1alpha1().Ports().Patch(ctx, port.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("record sandbox on Port %s: %w", port.Name, err)
		}
	}
	return datapath.RecordLegacyVethSandbox(v.Ifindex, v.Alias, e.ContainerID, e.IfName)
}

func vethCarries(v datapath.LocalPortVeth, address string) bool {
	ip := net.ParseIP(address)
	for _, a := range v.IPs {
		if ip != nil && a.Equal(ip) {
			return true
		}
	}
	return false
}
