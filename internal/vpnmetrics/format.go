// Package vpnmetrics formats the shared tunnel monitoring contract.
package vpnmetrics

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
)

type metricField struct {
	name, help, kind string
	value            func(vpnstatus.Connection) any
}

func Format(backend string, connections map[string]vpnstatus.Connection, packets bool) string {
	names := make([]string, 0, len(connections))
	for name := range connections {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# HELP cozyplane_vpn_gateway_connections Configured connections on this appliance.\n# TYPE cozyplane_vpn_gateway_connections gauge\n")
	fmt.Fprintf(&b, "cozyplane_vpn_gateway_connections{backend=%q} %d\n", backend, len(names))
	fields := []metricField{
		{"rx_bytes_total", "Bytes received from the peer over the tunnel.", "counter", func(c vpnstatus.Connection) any { return c.RXBytes }},
		{"tx_bytes_total", "Bytes sent to the peer over the tunnel.", "counter", func(c vpnstatus.Connection) any { return c.TXBytes }},
		{"up", "Whether the peer has a fresh WireGuard handshake or an installed IPsec CHILD SA.", "gauge", func(c vpnstatus.Connection) any {
			if c.Up {
				return 1
			}
			return 0
		}},
		{"last_handshake_timestamp_seconds", "Unix time of the latest handshake or IKE establishment (0 if none).", "gauge", func(c vpnstatus.Connection) any { return c.LastHandshakeUnix }},
	}
	if packets {
		fields = append(fields,
			metricField{"rx_packets_total", "Packets received from the peer over the tunnel.", "counter", func(c vpnstatus.Connection) any { return c.RXPackets }},
			metricField{"tx_packets_total", "Packets sent to the peer over the tunnel.", "counter", func(c vpnstatus.Connection) any { return c.TXPackets }},
		)
	}
	for _, field := range fields {
		metric := "cozyplane_vpn_connection_" + field.name
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", metric, field.help, metric, field.kind)
		for _, name := range names {
			fmt.Fprintf(&b, "%s{connection=%q,backend=%q} %v\n", metric, name, backend, field.value(connections[name]))
		}
	}
	return b.String()
}
