package datapath

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const hfModeInitialized uint32 = 2

// Seed durable modes before reconcilePins can remove legacy params. A mode pin
// is never automatically discarded: it is the witness of host isolation.
func ensureHFModePin(root string) error {
	spec, err := loadOverlay()
	if err != nil {
		return err
	}
	modes, err := ebpf.NewMapWithOptions(spec.Maps["hf_modes"], ebpf.MapOptions{PinPath: root})
	if err != nil {
		return fmt.Errorf("open durable host-firewall modes: %w", err)
	}
	defer modes.Close()
	legacy, err := ebpf.LoadPinnedMap(filepath.Join(root, "params"), nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read legacy firewall modes: %w", err)
	}
	if legacy != nil {
		defer legacy.Close()
	}
	ambiguous := false
	if legacy == nil {
		for _, name := range []string{"hf_allow", "hf_eallow", "hf_self"} {
			_, err := os.Stat(filepath.Join(root, name))
			if err == nil {
				ambiguous = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return seedHFModeMap(modes, legacy, ambiguous)
}

func seedHFModeMap(modes, legacy *ebpf.Map, ambiguous bool) error {
	var initialized uint32
	if err := modes.Lookup(hfModeInitialized, &initialized); err != nil {
		return err
	}
	if initialized == 1 {
		return nil
	}
	if initialized != 0 {
		return fmt.Errorf("invalid host-firewall initialization witness")
	}
	for direction := uint32(0); direction < 2; direction++ {
		mode := uint32(0)
		if legacy != nil {
			if err := legacy.Lookup(cfgHFEnabled+direction, &mode); err != nil && !isNotExist(err) {
				return err
			}
		} else if ambiguous {
			mode = 2
		}
		if mode > 2 {
			return fmt.Errorf("invalid legacy host-firewall mode %d", mode)
		}
		if err := modes.Put(direction, mode); err != nil {
			return err
		}
	}
	return modes.Put(hfModeInitialized, uint32(1))
}

// Mirror params for old classifiers still attached during an upgrade. New
// classifiers use hf_modes, so losing params cannot disable host isolation.
func (m *Manager) setHFMode(index, mode uint32) error {
	if err := m.objs.HfModes.Put(index-cfgHFEnabled, mode); err != nil {
		return err
	}
	return m.objs.Params.Put(index, mode)
}

func (m *Manager) armHFBootstrap(missing map[string]bool) error {
	active := false
	for direction, rules := range []string{"hf_allow", "hf_eallow"} {
		var mode uint32
		if err := m.objs.HfModes.Lookup(uint32(direction), &mode); err != nil {
			return err
		}
		if mode > 2 {
			return fmt.Errorf("invalid durable host-firewall mode %d", mode)
		}
		if mode != 0 && missing[rules] {
			mode = 2
		}
		active = active || mode != 0
		if err := m.setHFMode(cfgHFEnabled+uint32(direction), mode); err != nil {
			return err
		}
	}
	if active && missing["hf_self"] {
		addresses, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		var ips []net.IP
		for _, address := range addresses {
			if address.IP != nil && !address.IP.IsUnspecified() && !address.IP.IsMulticast() {
				ips = append(ips, address.IP)
			}
		}
		if len(ips) == 0 {
			return fmt.Errorf("cannot restore host-firewall identity without host addresses")
		}
		if err := m.SyncHFSelf(ips); err != nil {
			return fmt.Errorf("restore host-firewall identity: %w", err)
		}
	}
	return nil
}
