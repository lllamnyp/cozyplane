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

package main

import (
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/pkg/netid"
	"slices"
)

type vpcNetworkWriter interface {
	SetNetwork(uint32, string, uint32) error
	DelNetwork(uint32, string) error
	EnsureVPCCounter(uint32) error
}

type vpcNetworkKey struct {
	scope uint32
	cidr  string
}

// applied is the last complete projection; dirty journals individual successful
// operations after a partial failure. Neither retains acknowledgements/status.
type vpcNetworkState struct {
	applied map[string]*sdn.VPC
	dirty   map[string]map[vpcNetworkKey]bool
}

func (s *vpcNetworkState) sync(writer vpcNetworkWriter, key string, next *sdn.VPC) error {
	old := s.applied[key]
	realized, partial := s.dirty[key]
	if !partial && old != nil && next != nil && old.Status.VNI == next.Status.VNI && slices.Equal(old.Spec.CIDRs, next.Spec.CIDRs) {
		return nil
	}
	if !partial {
		realized = projectedVPCNetworks(old)
	}
	if err := syncRealizedVPCNetworks(writer, realized, old, next); err != nil {
		if s.dirty == nil {
			s.dirty = map[string]map[vpcNetworkKey]bool{}
		}
		s.dirty[key] = realized
		return err
	}
	delete(s.dirty, key)
	if next == nil {
		delete(s.applied, key)
		return nil
	}
	if s.applied == nil {
		s.applied = map[string]*sdn.VPC{}
	}
	s.applied[key] = &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: append([]string(nil), next.Spec.CIDRs...)}, Status: sdn.VPCStatus{VNI: next.Status.VNI}}
	return nil
}
func projectedVPCNetworks(vpc *sdn.VPC) map[vpcNetworkKey]bool {
	out := map[vpcNetworkKey]bool{}
	if vpc == nil || !netid.ValidVNI(vpc.Status.VNI) {
		return out
	}
	for _, cidr := range vpc.Spec.CIDRs {
		out[vpcNetworkKey{netid.VNI(vpc.Status.VNI), cidr}] = true
	}
	return out
}

// Remove obsolete scopes before realizing the new one. Status-only ACKs do not
// rewrite LPM entries or metering counters on every informer update.
func syncVPCNetworks(writer vpcNetworkWriter, old, next *sdn.VPC) error {
	return syncRealizedVPCNetworks(writer, projectedVPCNetworks(old), old, next)
}

func syncRealizedVPCNetworks(writer vpcNetworkWriter, before map[vpcNetworkKey]bool, old, next *sdn.VPC) error {
	after := projectedVPCNetworks(next)
	for key := range before {
		if !after[key] {
			if err := writer.DelNetwork(key.scope, key.cidr); err != nil {
				return err
			}
			delete(before, key)
		}
	}
	for key := range after {
		if !before[key] {
			if err := writer.SetNetwork(key.scope, key.cidr, key.scope); err != nil {
				return err
			}
			before[key] = true
		}
	}
	if next != nil && len(after) > 0 && (old == nil || old.Status.VNI != next.Status.VNI) {
		return writer.EnsureVPCCounter(netid.VNI(next.Status.VNI))
	}
	return nil
}
