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

package datapath

import (
	"fmt"
	"net"
)

// ServiceVIP load balancing (docs/services-in-vpc.md increment 2): the agent
// projects every ServiceVIP into the svc_vips map — {net, vip, proto, svc
// port} -> the backend set (VPC IPs + target ports). The per-flow ct
// (svc_fwd/svc_rev) is written by the datapath itself, never from here.

// SvcMaxBackends mirrors SVC_MAX_BACKENDS in bpf/overlay.c: a service with
// more ready backends than this has the excess silently truncated (v1 limit —
// logged by the agent).
const SvcMaxBackends = 16

// SvcBackend is one backend of a service port: a VPC IP and the target port.
type SvcBackend struct {
	IP   net.IP
	Port uint16
}

// svcFAffinity mirrors SVC_F_AFFINITY in bpf/overlay.c (ClientIP affinity).
const svcFAffinity = 1

// SvcEntry is one datapath service entry: a (net, vip, proto, port) key and
// its backends.
type SvcEntry struct {
	Net      uint32
	VIP      net.IP
	Proto    uint8 // unix.IPPROTO_TCP / IPPROTO_UDP
	Port     uint16
	Backends []SvcBackend
	Affinity bool // ClientIP session affinity
}

// SyncServiceVIPs makes the svc_vips map exactly `entries` (full-state diff,
// like SyncMasqSources): stale keys are pruned so a deleted ServiceVIP stops
// resolving at map speed. Established flows keep their svc_fwd/svc_rev pins
// (LRU; they age out).
func (m *Manager) SyncServiceVIPs(entries []SvcEntry) error {
	want := map[overlaySvcKey]overlaySvcVal{}
	for _, e := range entries {
		vip, err := addr128(e.VIP)
		if err != nil {
			return fmt.Errorf("service VIP: %w", err)
		}
		key := overlaySvcKey{Net: e.Net, Vip: vip, Proto: e.Proto, Port: htons(e.Port)}
		var val overlaySvcVal
		n := 0
		for _, b := range e.Backends {
			if n >= SvcMaxBackends {
				break
			}
			ip, err := addr128(b.IP)
			if err != nil {
				return fmt.Errorf("service backend: %w", err)
			}
			val.Be[n].Ip = ip
			val.Be[n].Port = htons(b.Port)
			n++
		}
		val.N = uint32(n)
		if e.Affinity {
			val.Flags = svcFAffinity
		}
		want[key] = val
	}

	var key overlaySvcKey
	var val overlaySvcVal
	var stale []overlaySvcKey
	it := m.objs.SvcVips.Iterate()
	for it.Next(&key, &val) {
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate svc_vips: %w", err)
	}
	for _, k := range stale {
		if err := m.objs.SvcVips.Delete(&k); err != nil && !isNotExist(err) {
			return err
		}
	}
	for k, v := range want {
		if err := m.objs.SvcVips.Put(&k, &v); err != nil {
			return fmt.Errorf("set service VIP: %w", err)
		}
	}
	return nil
}

// htons converts a port to network byte order in a uint16.
func htons(p uint16) uint16 { return p<<8 | p>>8 }
