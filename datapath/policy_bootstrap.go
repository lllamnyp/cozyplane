package datapath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var npPolicyPins = []string{"params", "np_ident", "np_allow", "np_cidr"}
var sgPolicyPins = []string{"params", "sg_members", "sg_rules", "sg_cidr", "sg_egress", "sg_egress_cidr"}

func missingPolicyPins() (map[string]bool, error) {
	missing := map[string]bool{}
	for _, names := range [][]string{npPolicyPins, sgPolicyPins, {"hf_allow", "hf_eallow", "hf_self"}} {
		for _, name := range names {
			_, err := os.Stat(filepath.Join(PinRoot, name))
			if errors.Is(err, os.ErrNotExist) {
				missing[name] = true
			} else if err != nil {
				return nil, fmt.Errorf("stat policy pin %s: %w", name, err)
			}
		}
	}
	return missing, nil
}

func (m *Manager) armPolicyBootstrap(missing map[string]bool) error {
	for _, layer := range []struct {
		initialized, guard uint32
		pins               []string
	}{{cfgNPInitialized, cfgNPUpdating, npPolicyPins}, {cfgSGInitialized, cfgSGUpdating, sgPolicyPins}} {
		var initialized uint32
		if err := m.objs.Params.Lookup(layer.initialized, &initialized); err != nil {
			return err
		}
		needs := initialized != 1
		for _, pin := range layer.pins {
			needs = needs || missing[pin]
		}
		if needs {
			if err := m.objs.Params.Put(layer.guard, uint32(1)); err != nil {
				return err
			}
		}
	}
	return nil
}
