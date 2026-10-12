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

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDoesNotFollowPredictableTemporarySymlink(t *testing.T) {
	dir := t.TempDir()
	dst, victim := filepath.Join(dir, "fixture"), filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, dst+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := Write(dst, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "unchanged" {
		t.Fatalf("symlink victim changed: %q %v", b, err)
	}
	st, err := os.Stat(dst)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("destination mode: %v %v", st, err)
	}
	if err := os.Chmod(dst, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dst, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(dst)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("replacement inherited public mode: %v %v", st, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, ".cozyplane-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary files leaked %v %v", files, err)
	}
}

func TestFailedRenameRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "existing-directory")
	if err := os.Mkdir(dst, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Write(dst, []byte("synthetic")); err == nil {
		t.Fatal("directory replacement unexpectedly succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "existing-directory" {
		t.Fatal("failed publication leaked a temporary file", entries, err)
	}
}
