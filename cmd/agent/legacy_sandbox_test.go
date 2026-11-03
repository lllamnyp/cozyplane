package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lllamnyp/cozyplane/datapath"
)

func TestLegacySandboxRecoveryEvidence(t *testing.T) {
	dir := t.TempDir()
	const cid = "1a856329d30141a1150f6d66db71a1e20db0b70f39b3d36061d18b18a5c55e82"
	record := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := `"cniArgs":[["K8S_POD_NAMESPACE","tenant"],["K8S_POD_NAME","virt-launcher-vm-a"],["K8S_POD_UID","pod-uid"],["K8S_POD_INFRA_CONTAINER_ID","` + cid + `"]]`
	record("multus-cni-network-"+cid+"-eth0", `{"kind":"cniCacheV1","containerId":"`+cid+`","ifName":"eth0","networkName":"multus-cni-network",`+args+`}`)
	record("cilium-"+cid+"-eth0", `{"kind":"cniCacheV1","containerId":"`+cid+`","ifName":"eth0","networkName":"cilium",`+args+`}`)         // same sandbox, other network
	record("cni-loopback-"+cid+"-lo", `{"kind":"cniCacheV1","containerId":"`+cid+`","ifName":"lo","networkName":"cni-loopback",`+args+`}`) // as containerd writes it
	record("unnamed-y-eth0", `{"kind":"cniCacheV1","containerId":"y","ifName":"eth0"}`)                                                    // no pod identity
	record("foreign", `{"kind":"other","containerId":"`+cid+`","ifName":"eth0",`+args+`}`)
	record("broken", `{`)
	entries, err := readCNIResultCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != (cniCacheEntry{ContainerID: cid, IfName: "eth0", PodNamespace: "tenant", PodName: "virt-launcher-vm-a", PodUID: "pod-uid"}) {
		t.Fatalf("entries = %+v", entries)
	}
	if missing, err := readCNIResultCache(filepath.Join(dir, "absent")); err != nil || missing != nil {
		t.Fatal("an absent cache must be no evidence, not an error", missing, err)
	}

	legacy := datapath.LocalPortVeth{Name: "cph1a856329d30", Net: 100, RawNet: 100}
	if !isLegacyVPCEndpoint(legacy) {
		t.Fatal("legacy VPC endpoint not selected")
	}
	for _, v := range []datapath.LocalPortVeth{
		{Name: "cph1a856329d30", Net: 0, RawNet: 0},
		{Name: "cph1a856329d30", Net: 100, RawNet: 100, ContainerID: cid, IfName: "eth0"},
		{Name: "cph1a856329d30", Net: 100, RawNet: datapath.QuarantineNet},
		{Name: "cpg1a856329d30", Net: 100, RawNet: 100 | datapath.PortGatewayFlag},
	} {
		if isLegacyVPCEndpoint(v) {
			t.Fatalf("selected %+v", v)
		}
	}
	if e, ok := legacySandboxFor(legacy, entries); !ok || e.ContainerID != cid {
		t.Fatal("sandbox not proven by its CNI veth name", e, ok)
	}
	if _, ok := legacySandboxFor(datapath.LocalPortVeth{Name: "cph1a856329d31"}, entries); ok {
		t.Fatal("a foreign veth name proved a sandbox")
	}
	twin := append(entries, cniCacheEntry{ContainerID: cid[:11] + "ffff", IfName: "eth0", PodNamespace: "tenant", PodName: "other", PodUID: "other-uid"})
	if _, ok := legacySandboxFor(legacy, twin); ok {
		t.Fatal("two sandboxes sharing a veth name must prove nothing")
	}
}
