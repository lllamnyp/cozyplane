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

// Package vpnstatus defines the secret-free live-state contract exposed by a
// managed VPN appliance and consumed by the controller. It deliberately carries
// only operational facts that are already exported as aggregate metrics.
package vpnstatus

import "time"

// Snapshot is one point-in-time view of every configured connection.
type Snapshot struct {
	Backend     string                `json:"backend"`
	ObservedAt  time.Time             `json:"observedAt"`
	Connections map[string]Connection `json:"connections"`
}

// Connection is the live state of one VPNConnection.
type Connection struct {
	Up                bool     `json:"up"`
	LastHandshakeUnix int64    `json:"lastHandshakeUnix,omitempty"`
	RXBytes           uint64   `json:"rxBytes,omitempty"`
	TXBytes           uint64   `json:"txBytes,omitempty"`
	RXPackets         uint64   `json:"rxPackets,omitempty"`
	TXPackets         uint64   `json:"txPackets,omitempty"`
	AssignedAddresses []string `json:"assignedAddresses,omitempty"`
}
