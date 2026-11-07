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

import "fmt"

// RouteKind is a vpc_routes entry kind (RT_* in bpf/overlay.c).
type RouteKind uint8

const (
	RouteLocal      RouteKind = 1
	RoutePeer       RouteKind = 2
	RouteNAT        RouteKind = 3
	RouteInternet   RouteKind = 4
	RouteBlackhole  RouteKind = 5
	RouteUnresolved RouteKind = 6
)

// Route is one vpc_routes entry: within route table Table, CIDR goes to Kind
// (and, for RouteNAT, NAT gateway NATGateway).
type Route struct {
	Table      uint32
	CIDR       string
	Kind       RouteKind
	NATGateway uint16
}

// SyncRoutes makes vpc_routes exactly `want` (docs/vpc-egress.md §5.1). Two
// entries for one {table, CIDR} are an error: the agent resolves precedence
// before it calls this.
func (m *Manager) SyncRoutes(want []Route) error {
	w := map[overlayLpmKey]overlayRtVal{}
	for _, r := range want {
		key, err := lpmKey(r.Table, r.CIDR)
		if err != nil {
			return err
		}
		if _, dup := w[key]; dup {
			return fmt.Errorf("route table %d: two entries for %s", r.Table, r.CIDR)
		}
		w[key] = overlayRtVal{Kind: uint8(r.Kind), Natgw: r.NATGateway}
	}
	return syncMap(m.objs.VpcRoutes, w)
}

// PortTable assigns a local Port {net, VPC IP} its route table.
type PortTable struct {
	Net uint32
	IP  string
}

// SyncPortTables makes port_rt exactly `want`.
func (m *Manager) SyncPortTables(want map[PortTable]uint32) error {
	w := map[overlayLocalKey]uint32{}
	for p, table := range want {
		ip, err := addr128Str(p.IP)
		if err != nil {
			return err
		}
		w[overlayLocalKey{Net: p.Net, Ip: ip}] = table
	}
	return syncMap(m.objs.PortRt, w)
}

// route_drops reasons (RTD_* in bpf/overlay.c), named as in
// docs/vpc-egress.md §4.6.
var routeDropNames = map[uint32]string{
	0: "blackhole",
	1: "unresolved",
	2: "no_floating_ip",
	3: "no_route",
}

// RouteDrops returns route_drops as {net: {reason: count}}.
func (m *Manager) RouteDrops() (map[uint32]map[string]uint64, error) {
	out := map[uint32]map[string]uint64{}
	var k overlayRouteDropKey
	var v uint64
	it := m.objs.RouteDrops.Iterate()
	for it.Next(&k, &v) {
		name, ok := routeDropNames[k.Reason]
		if !ok {
			continue
		}
		if out[k.Net] == nil {
			out[k.Net] = map[string]uint64{}
		}
		out[k.Net][name] = v
	}
	return out, it.Err()
}
