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
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// MasqLink is a link other than the default uplink and the addresses the masquerade sources from on it.
type MasqLink struct {
	Ifindex int
	Name    string
	V4, V6  net.IP
}

// MasqLinks returns every link other than the default uplink that the cluster-egress masquerade covers.
func (m *Manager) MasqLinks() ([]MasqLink, error) {
	links, err := linkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var out []MasqLink
	for _, l := range links {
		a := l.Attrs()
		if a.Index == m.uplinkIfindex || a.Name == GeneveDevice || !masqEligible(linkInfoOf(l)) {
			continue
		}
		v4s, err := addrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("list addrs on %s: %w", a.Name, err)
		}
		v6s, err := addrList(l, netlink.FAMILY_V6)
		if err != nil {
			return nil, fmt.Errorf("list addrs on %s: %w", a.Name, err)
		}
		ml := MasqLink{Ifindex: a.Index, Name: a.Name, V4: masqAddr(v4s), V6: masqAddr(v6s)}
		if ml.V4 != nil || ml.V6 != nil {
			out = append(out, ml)
		}
	}
	return out, nil
}

// masqEligible reports whether a link can carry masqueraded pod traffic to the wire.
func masqEligible(l linkInfo) bool {
	if !carriesWire(l) {
		return false
	}
	switch l.Type {
	case "geneve", "vxlan", "gretap", "ip6gretap", "erspan", "ip6erspan":
		return false
	}
	return true
}

// masqAddr returns a link's own address of one family: the first global, primary address that is not a host prefix.
func masqAddr(addrs []netlink.Addr) net.IP {
	for _, a := range addrs {
		if a.IPNet == nil || !a.IP.IsGlobalUnicast() || a.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		if a.Flags&(unix.IFA_F_SECONDARY|unix.IFA_F_DEPRECATED) != 0 {
			continue
		}
		if ones, bits := a.Mask.Size(); ones == bits {
			continue
		}
		return a.IP
	}
	return nil
}

// SyncMasqLinks attaches the masquerade to links and makes masq_links and masq_addrs match them and the default uplink's addresses.
func (m *Manager) SyncMasqLinks(links []MasqLink, uplinkV4, uplinkV6 net.IP) error {
	wantLinks := map[uint32]overlayMasqLink{}
	wantAddrs := map[overlayAddr128]uint8{}
	addAddr := func(ip net.IP) error {
		a, err := addr128(ip)
		if err != nil {
			return err
		}
		wantAddrs[a] = 1
		return nil
	}
	for _, ip := range []net.IP{uplinkV4, uplinkV6} {
		if ip != nil {
			if err := addAddr(ip); err != nil {
				return err
			}
		}
	}
	for _, l := range links {
		var v overlayMasqLink
		if l.V4 != nil {
			v.V4 = binary.NativeEndian.Uint32(l.V4.To4())
			if err := addAddr(l.V4); err != nil {
				return err
			}
		}
		if l.V6 != nil {
			a, err := addr128(l.V6)
			if err != nil {
				return err
			}
			v.V6 = a
			wantAddrs[a] = 1
		}
		wantLinks[uint32(l.Ifindex)] = v
	}

	m.floatMu.Lock()
	defer m.floatMu.Unlock()
	for _, l := range links {
		if err := AttachIngress(l.Ifindex, m.objs.CozyplaneFromUplink); err != nil {
			return fmt.Errorf("attach from_uplink on %s: %w", l.Name, err)
		}
	}
	if err := syncMap(m.objs.MasqAddrs, wantAddrs); err != nil {
		return fmt.Errorf("sync masq_addrs: %w", err)
	}
	if err := syncMap(m.objs.MasqLinks, wantLinks); err != nil {
		return fmt.Errorf("sync masq_links: %w", err)
	}
	for _, l := range links {
		if err := AttachEgress(l.Ifindex, m.objs.CozyplaneLinkEgress); err != nil {
			return fmt.Errorf("attach link_egress on %s: %w", l.Name, err)
		}
	}
	return nil
}

// WatchMasqLinks re-syncs the masquerade links on every address change and once a minute, until ctx ends.
func (m *Manager) WatchMasqLinks(ctx context.Context, uplinkV4, uplinkV6 net.IP, log *slog.Logger) {
	updates := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribe(updates, ctx.Done()); err != nil {
		log.Warn("subscribe to address changes; masquerade links re-sync once a minute only", "err", err)
		updates = nil
	}
	sync := func() {
		links, err := m.MasqLinks()
		if err == nil {
			err = m.SyncMasqLinks(links, uplinkV4, uplinkV6)
		}
		if err != nil {
			log.Error("sync masquerade links", "err", err)
		}
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			// Coalesce a burst of address events into one sync.
			for drained := false; !drained; {
				select {
				case _, ok := <-updates:
					if !ok {
						updates, drained = nil, true
					}
				case <-time.After(500 * time.Millisecond):
					drained = true
				}
			}
			sync()
		case <-tick.C:
			sync()
		}
	}
}
