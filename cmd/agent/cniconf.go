package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lllamnyp/cozyplane/internal/atomicfile"
)

func configureCNIConf(dir, name string, mtu int, enabled bool) (string, error) {
	if !enabled {
		return "", nil
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return "", fmt.Errorf("CNI configuration name must be a filename")
	}
	winner, err := cniConfOwner(dir, name)
	if err != nil || winner != "" {
		return winner, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	return "", atomicfile.Write(filepath.Join(dir, name), []byte(fmt.Sprintf(cniConfBody, mtu)))
}

// cniConfOwner returns the foreign configuration that sorts before name.
// A deliberately earlier name still selects cozyplane; opt-out is independent
// of filename order. Inspection errors must not authorize a write.
func cniConfOwner(dir, name string) (string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, entry := range entries { // ReadDir returns names in lexical order.
		other := entry.Name()
		if entry.IsDir() || other == name || other >= name || strings.HasPrefix(other, ".") {
			continue
		}
		switch filepath.Ext(other) {
		case ".conf", ".conflist", ".json":
			return other, nil
		}
	}
	return "", nil
}
