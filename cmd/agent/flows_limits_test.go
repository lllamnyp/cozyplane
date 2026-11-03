package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/lllamnyp/cozyplane/datapath"
	locallisters "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/listers/localsdn/v1alpha1"
	sdnlisters "github.com/lllamnyp/cozyplane/pkg/generated/sdn/listers/sdn/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

func TestFlowLifetimeSeriesBoundDuringTenantChurn(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	fp := newFlowPipeline(nil, sdnlisters.NewVPCLister(index), sdnlisters.NewPortLister(index), locallisters.NewFabricIPLister(index), "node", slog.New(slog.NewTextHandler(io.Discard, nil)))
	const count = 18000
	for i := 1; i <= count; i++ {
		for _, proto := range []uint8{6, 58} {
			e := datapath.FlowEvent{Src: net.ParseIP("2001:db8::1"), Dst: net.ParseIP("2001:db8::2"), SrcNet: uint32(i), DstNet: uint32(i), Proto: proto, Dport: 443, TCPFlags: 2, ICMPType: 128}
			fp.ingest(&e)
		}
	}
	for name, size := range map[string]int{"flow": len(fp.metrics), "ports": len(fp.portDist), "tcp": len(fp.tcpFlags), "icmp": len(fp.icmp)} {
		if size > 16385 {
			t.Errorf("%s retained %d historical series", name, size)
		}
	}
	if len(fp.groupN) > 4096 {
		t.Errorf("retained %d distribution groups", len(fp.groupN))
	}
	var total uint64
	for _, n := range fp.metrics {
		total += n
	}
	if total != 2*count {
		t.Fatal(fmt.Sprintf("overflow lost flow counts: %d", total))
	}
}
