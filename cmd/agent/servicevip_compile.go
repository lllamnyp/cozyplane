package main

import (
	"fmt"
	"log/slog"
	"net"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/serviceidentity"
	"golang.org/x/sys/unix"
)

type servicePortKey struct {
	protocol string
	port     int32
}

func compileServiceVIPs(all []*sdnv1alpha1.ServiceVIP, lookup func(sdnv1alpha1.VPCRef) (*sdnv1alpha1.VPC, error), log *slog.Logger) ([]datapath.SvcEntry, error) {
	// Count input before constructing expanded backend or entry arrays.
	work, ports := len(all), 0
	if work > serviceidentity.MaxWork {
		return nil, fmt.Errorf("ServiceVIP object budget exceeded")
	}
	for _, sv := range all {
		if len(sv.Spec.Ports) > serviceidentity.MaxPorts || len(sv.Status.Backends) > serviceidentity.MaxBackends {
			return nil, fmt.Errorf("ServiceVIP %s exceeds port/backend budget", sv.Name)
		}
		work += len(sv.Spec.Ports) + len(sv.Status.Backends)
		ports += len(sv.Spec.Ports)
		for _, b := range sv.Status.Backends {
			work += len(b.Ports)
			if work > serviceidentity.MaxSnapshotWork {
				return nil, fmt.Errorf("ServiceVIP input work budget exceeded")
			}
		}
		if work > serviceidentity.MaxSnapshotWork || ports > serviceidentity.MaxEntries {
			return nil, fmt.Errorf("ServiceVIP snapshot budget exceeded")
		}
	}
	var entries []datapath.SvcEntry
	for _, sv := range all {
		vpc, err := lookup(sv.Spec.VPCRef)
		if err != nil || !serviceidentity.MatchesVPC(sv, vpc) || sv.Annotations[sdnv1alpha1.AnnotationServiceUID] == "" {
			continue
		}
		vip := net.ParseIP(sv.Spec.IP)
		if vip == nil {
			continue
		}
		// Index declared ports once, capping each bucket before appending.
		byPort := map[servicePortKey][]datapath.SvcBackend{}
		truncated := false
		for _, p := range sv.Spec.Ports {
			if (p.Protocol == "TCP" || p.Protocol == "UDP") && p.Port > 0 && p.Port <= 65535 {
				byPort[servicePortKey{p.Protocol, p.Port}] = nil
			}
		}
		for _, b := range sv.Status.Backends {
			ip := net.ParseIP(b.IP)
			if ip == nil {
				continue
			}
			for _, bp := range b.Ports {
				key := servicePortKey{bp.Protocol, bp.Port}
				bucket, found := byPort[key]
				if !found || bp.TargetPort <= 0 || bp.TargetPort > 65535 {
					continue
				}
				if len(bucket) == datapath.SvcMaxBackends {
					truncated = true
					continue
				}
				if bucket == nil {
					bucket = make([]datapath.SvcBackend, 0, datapath.SvcMaxBackends)
				}
				byPort[key] = append(bucket, datapath.SvcBackend{IP: ip, Port: uint16(bp.TargetPort)})
			}
		}
		if truncated {
			log.Warn("service VIP backends truncated", "vip", sv.Name, "max", datapath.SvcMaxBackends)
		}
		for _, p := range sv.Spec.Ports {
			backends, found := byPort[servicePortKey{p.Protocol, p.Port}]
			if !found {
				continue
			}
			proto := uint8(unix.IPPROTO_TCP)
			if p.Protocol == "UDP" {
				proto = unix.IPPROTO_UDP
			}
			entries = append(entries, datapath.SvcEntry{Net: uint32(vpc.Status.VNI), VIP: vip, Proto: proto, Port: uint16(p.Port), Backends: backends, Affinity: sv.Spec.SessionAffinity == "ClientIP"})
		}
	}
	return entries, nil
}
