package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedReads(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.yaml")
	if err := os.WriteFile(small, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readFileLimit(small, 5); err != nil || string(raw) != "12345" {
		t.Fatal("exact-limit read failed", err)
	}
	if _, err := readFileLimit(small, 4); err == nil {
		t.Fatal("oversized file accepted")
	}
	sparse := filepath.Join(dir, "sparse.yaml")
	f, err := os.Create(sparse)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxConfigBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	// A mistaken path or oversized configuration must fail fast, not allocate.
	if _, err := readFileLimit(sparse, MaxConfigBytes); err == nil {
		t.Fatal("oversized configuration accepted")
	}
	if _, err := LoadSites(sparse); err == nil {
		t.Fatal("oversized sites file accepted")
	}
	if _, err := LoadSites(dir); err == nil {
		t.Fatal("directory accepted as a sites file")
	}
	missing := filepath.Join(dir, "absent.yaml")
	if _, err := LoadSites(missing); err == nil {
		t.Fatal("missing sites file accepted")
	}
}

func TestReadTargetListBoundsAndParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("# comment\n\nalice\n bob \ncarol@example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTargetList(path)
	if err != nil || strings.Join(got, ",") != "alice,bob,carol@example.test" {
		t.Fatalf("targets: %v %v", got, err)
	}
	sparse := filepath.Join(dir, "large.txt")
	f, err := os.Create(sparse)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxTargetsBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadTargetList(sparse); err == nil {
		t.Fatal("oversized target file accepted")
	}
}
