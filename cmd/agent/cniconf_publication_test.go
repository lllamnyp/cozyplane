package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnabledCNIConfigPreservesEarlierOwner(t *testing.T) {
	dir := t.TempDir()
	owner := filepath.Join(dir, "00-chain.conf")
	if err := os.WriteFile(owner, []byte("synthetic-owner"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := configureCNIConf(dir, "10-cozyplane.conflist", 1450, true)
	if err != nil || got != "00-chain.conf" {
		t.Fatalf("owner = %q, error = %v", got, err)
	}
	if content, err := os.ReadFile(owner); err != nil || string(content) != "synthetic-owner" {
		t.Fatal("earlier owner changed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("writer published a competing configuration")
	}
}

func TestCNIConfigPublicationAvoidsPredictableSymlink(t *testing.T) {
	dir := t.TempDir()
	name := "10-cozyplane.conflist"
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "."+name+".tmp")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := configureCNIConf(dir, name, 1450, true); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("configuration permissions are not private", info, err)
		}
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "unchanged" {
		t.Fatal("publication followed the predictable symlink")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cozyplane-") {
			t.Fatal("publication leaked a temporary file")
		}
	}
}

func TestCNIConfigInspectionErrorPreventsPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configureCNIConf(path, "10-cozyplane.conflist", 1450, true); err == nil {
		t.Fatal("failed directory inspection authorized publication")
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "unchanged" {
		t.Fatal("inspection failure changed the existing path")
	}
}

func TestCNIConfigRejectsTraversalBeforeCreatingDirectory(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape.conflist", "/tmp/escape.conflist"} {
		dir := filepath.Join(t.TempDir(), "absent")
		if _, err := configureCNIConf(dir, name, 1450, true); err == nil {
			t.Fatal("non-filename configuration name admitted")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("invalid name created the configuration directory")
		}
	}
}
