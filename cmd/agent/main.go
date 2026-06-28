/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command cozyplane-agent is the per-node datapath manager. It loads the eBPF
// overlay, manages the Geneve device, watches Node objects to learn remote pod
// CIDRs, publishes node state for the CNI plugin, and writes the CNI conf.
//
// It depends only on the core Kubernetes API (Nodes) — never on the aggregated
// sdn.cozystack.io API — so it can bring up the default network during cluster
// bootstrap before anything else is reachable.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

const (
	cniConfDir  = "/etc/cni/net.d"
	cniConfFile = "10-cozyplane.conflist"
	cniConfBody = `{
  "cniVersion": "1.0.0",
  "name": "cozyplane",
  "plugins": [
    { "type": "cozyplane", "mtu": %d }
  ]
}
`
)

func main() {
	var (
		nodeName = os.Getenv("NODE_NAME")
		mtu      int
		vni      uint
	)
	flag.IntVar(&mtu, "mtu", 1450, "pod MTU (underlay MTU minus Geneve overhead)")
	flag.UintVar(&vni, "vni", uint(datapath.DefaultVNI), "VNI for the default network")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if nodeName == "" {
		log.Error("NODE_NAME must be set (downward API)")
		os.Exit(1)
	}

	if err := run(nodeName, mtu, uint32(vni), log); err != nil {
		log.Error("agent failed", "err", err)
		os.Exit(1)
	}
}

func run(nodeName string, mtu int, vni uint32, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Permit forwarding and accept asymmetric/encapsulated return traffic.
	for path, val := range map[string]string{
		"net/ipv4/ip_forward":             "1",
		"net/ipv4/conf/all/rp_filter":     "0",
		"net/ipv4/conf/default/rp_filter": "0",
	} {
		if err := datapath.WriteProcSys(path, val); err != nil {
			log.Warn("set sysctl", "path", path, "err", err)
		}
	}

	if err := datapath.EnsureBPFFS(); err != nil {
		return fmt.Errorf("ensure bpffs: %w", err)
	}

	mgr := datapath.New()
	if err := mgr.Load(vni); err != nil {
		return fmt.Errorf("load datapath: %w", err)
	}
	defer mgr.Close()
	if err := mgr.EnsureGeneve(); err != nil {
		return fmt.Errorf("ensure geneve: %w", err)
	}
	if err := datapath.EnsureForwardRules(); err != nil {
		return fmt.Errorf("ensure forward rules: %w", err)
	}
	uplink, err := mgr.AttachUplink()
	if err != nil {
		return fmt.Errorf("attach uplink: %w", err)
	}
	log.Info("datapath loaded", "vni", vni, "geneve", datapath.GeneveDevice, "uplink", uplink)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kube client: %w", err)
	}

	self, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get self node %q: %w", nodeName, err)
	}
	podCIDR := self.Spec.PodCIDR
	if podCIDR == "" {
		return fmt.Errorf("node %q has no spec.podCIDR (is --allocate-node-cidrs enabled?)", nodeName)
	}
	state := &datapath.AgentState{NodeName: nodeName, PodCIDR: podCIDR, MTU: mtu}
	if err := state.Save(); err != nil {
		return fmt.Errorf("publish agent state: %w", err)
	}
	log.Info("published node state", "podCIDR", podCIDR, "mtu", mtu)

	if err := watchNodes(ctx, client, mgr, nodeName, log); err != nil {
		return err
	}

	// VPC watching is best-effort: the default network must work even before the
	// sdn.cozystack.io API exists, so we don't block readiness on it.
	if sdnClient, err := sdnclientset.NewForConfig(cfg); err != nil {
		log.Warn("sdn client init failed; VPC networks won't be programmed", "err", err)
	} else {
		watchVPCs(ctx, sdnClient, mgr, log)
	}

	// Datapath is up and remotes are syncing; expose the CNI to kubelet.
	if err := writeCNIConf(mtu); err != nil {
		return fmt.Errorf("write CNI conf: %w", err)
	}
	log.Info("CNI configuration installed; agent ready")

	<-ctx.Done()
	log.Info("shutting down")
	return nil
}

// watchNodes starts a Node informer that mirrors every other node's pod CIDR
// into the remotes map. It blocks until the cache is synced.
func watchNodes(ctx context.Context, client kubernetes.Interface, mgr *datapath.Manager, selfName string, log *slog.Logger) error {
	factory := informers.NewSharedInformerFactory(client, 0)
	nodeInformer := factory.Core().V1().Nodes().Informer()

	apply := func(obj any) {
		node, ok := obj.(*corev1.Node)
		if !ok || node.Name == selfName || node.Spec.PodCIDR == "" {
			return
		}
		ip := internalIP(node)
		if ip == "" {
			log.Warn("node has no InternalIP", "node", node.Name)
			return
		}
		if err := mgr.SetRemote(node.Spec.PodCIDR, net.ParseIP(ip)); err != nil {
			log.Error("set remote", "node", node.Name, "err", err)
			return
		}
		log.Info("remote set", "node", node.Name, "podCIDR", node.Spec.PodCIDR, "nodeIP", ip)
	}

	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			node, ok := obj.(*corev1.Node)
			if !ok || node.Name == selfName || node.Spec.PodCIDR == "" {
				return
			}
			if err := mgr.DelRemote(node.Spec.PodCIDR); err != nil {
				log.Error("del remote", "node", node.Name, "err", err)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("add node handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), nodeInformer.HasSynced) {
		return fmt.Errorf("node cache failed to sync")
	}
	return nil
}

// watchVPCs mirrors VPC CIDR -> network id into the networks map. Best-effort:
// it starts the informer without blocking on cache sync, so a missing sdn API
// (during bootstrap) doesn't stall the agent.
func watchVPCs(ctx context.Context, client sdnclientset.Interface, mgr *datapath.Manager, log *slog.Logger) {
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	informer := factory.Sdn().V1alpha1().VPCs().Informer()

	apply := func(obj any) {
		vpc, ok := obj.(*sdnv1alpha1.VPC)
		if !ok || vpc.Status.VNI == 0 || len(vpc.Spec.CIDRs) == 0 {
			return
		}
		if err := mgr.SetNetwork(vpc.Spec.CIDRs[0], uint32(vpc.Status.VNI)); err != nil {
			log.Error("set network", "vpc", vpc.Name, "err", err)
			return
		}
		log.Info("network set", "vpc", vpc.Name, "cidr", vpc.Spec.CIDRs[0], "vni", vpc.Status.VNI)
	}

	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    apply,
		UpdateFunc: func(_, newObj any) { apply(newObj) },
		DeleteFunc: func(obj any) {
			vpc, ok := obj.(*sdnv1alpha1.VPC)
			if !ok || len(vpc.Spec.CIDRs) == 0 {
				return
			}
			if err := mgr.DelNetwork(vpc.Spec.CIDRs[0]); err != nil {
				log.Error("del network", "vpc", vpc.Name, "err", err)
			}
		},
	})

	factory.Start(ctx.Done())
}

func writeCNIConf(mtu int) error {
	if err := os.MkdirAll(cniConfDir, 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf(cniConfBody, mtu)
	tmp := filepath.Join(cniConfDir, "."+cniConfFile+".tmp")
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(cniConfDir, cniConfFile))
}

func internalIP(node *corev1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}
