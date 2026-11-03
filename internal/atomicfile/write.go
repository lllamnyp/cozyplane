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

// Package atomicfile publishes private runtime files in an operator-owned
// directory, without predictable temporary names or inherited file modes.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write creates an exclusive 0600 temporary file and atomically replaces path.
// The parent directory must be owned and writable only by the operator.
func Write(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".cozyplane-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write private runtime file: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
