package passworddb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func mutate(t *testing.T, path string, at int64, value byte) {
	t.Helper()
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte{value}, at); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestActivationLeasesRecoveryAndConcurrentReaders(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a := importFixture(t, root, 42)
	b := importFixture(t, root, 99)
	if e := Activate(ctx, root, a); e != nil {
		t.Fatal(e)
	}
	old, e := Open(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	var key [20]byte
	key[19] = 2
	if e = Activate(ctx, root, b); e != nil {
		t.Fatal(e)
	}
	current, e := Open(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if n, e := current.Lookup(ctx, key); e != nil || n != 99 {
					t.Error("concurrent new lookup failed")
				}
				if n, e := old.Lookup(ctx, key); e != nil || n != 42 {
					t.Error("old snapshot changed")
				}
			}
		}()
	}
	wg.Wait()
	// Explicit rollback creates a new sequence and restores A for new readers.
	if e = Activate(ctx, root, a); e != nil {
		t.Fatal(e)
	}
	rolled, e := Open(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := rolled.Lookup(ctx, key); e != nil || n != 42 {
		t.Fatal("rollback failed")
	}
	rolled.Close()
	if e = Activate(ctx, root, b); e != nil {
		t.Fatal(e)
	}
	if e = Activate(ctx, root, b); e != nil {
		t.Fatal(e)
	} // retire A's redundant slot reference
	removed, e := Prune(ctx, root)
	if e != nil || len(removed) != 0 {
		t.Fatal("pruned leased version")
	}
	old.Close()
	removed, e = Prune(ctx, root)
	if e != nil || len(removed) != 1 || removed[0] != a {
		t.Fatal("unleased retired version not pruned")
	}
	// A torn newest slot recovers the other valid B slot with an explicit indicator.
	sel, e := readSelection(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	mutate(t, filepath.Join(root, []string{"active-a", "active-b"}[sel.best]), 100, 1)
	recovered, e := Open(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	if !recovered.Info().Recovered {
		t.Fatal("recovery not reported")
	}
	recovered.Close()
	if _, e = Prune(ctx, root); e == nil {
		t.Fatal("prune accepted unrepaired control state")
	}
	// A valid selected control record with missing data must not fall back.
	sel, e = readSelection(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	bad := sel.slots[sel.best]
	bad.sequence++
	bad.id = "00112233445566778899aabbccddeeff"
	path := filepath.Join(root, []string{"active-a", "active-b"}[1-sel.best])
	if e = os.WriteFile(path, encodeSlot(bad), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e := Open(ctx, root); e == nil {
		s.Close()
		t.Fatal("invalid selected generation fell back")
	}
}
func TestCorruptionFailsClosed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	id := importFixture(t, root, 42)
	if e := Activate(ctx, root, id); e != nil {
		t.Fatal(e)
	}
	s, e := Open(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var key [20]byte
	key[19] = 2
	path := filepath.Join(root, "versions", id, "hashes.bin")
	mutate(t, path, HeaderSize+RecordSize+19, 3)
	if _, e = s.Lookup(ctx, key); e == nil {
		t.Fatal("corrupt range returned an answer")
	}
	mutate(t, path, HeaderSize+RecordSize+19, 2)
	if e = os.Truncate(path, HeaderSize+RecordSize); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Lookup(ctx, key); e == nil {
		t.Fatal("truncated data returned an answer")
	}
	s.Close()
	// Reuse one independent fixture for metadata corruption checks.
	id = importFixture(t, root, 43)
	dir := filepath.Join(root, "versions", id)
	idxPath := filepath.Join(dir, "prefix.idx")
	mutate(t, idxPath, HeaderSize, 1)
	if v, e := loadVersion(ctx, dir, id, nil); e == nil {
		v.Close()
		t.Fatal("corrupt index accepted")
	}
	mutate(t, idxPath, HeaderSize, 0)
	manifestPath := filepath.Join(dir, "manifest.json")
	raw, e := os.ReadFile(manifestPath)
	if e != nil {
		t.Fatal(e)
	}
	mutate(t, manifestPath, 0, '!')
	if v, e := loadVersion(ctx, dir, id, nil); e == nil {
		v.Close()
		t.Fatal("invalid manifest accepted")
	}
	if e = os.WriteFile(manifestPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	headerBytes, e := os.ReadFile(filepath.Join(dir, "hashes.bin"))
	if e != nil {
		t.Fatal(e)
	}
	mutate(t, filepath.Join(dir, "hashes.bin"), 16, headerBytes[16]^1)
	if v, e := loadVersion(ctx, dir, id, nil); e == nil {
		v.Close()
		t.Fatal("mismatched dataset header accepted")
	}
}
func TestActivationSlotValidation(t *testing.T) {
	a := activation{sequence: 1, id: "00112233445566778899aabbccddeeff", manifest: sha256.Sum256([]byte("public fixture"))}
	raw := encodeSlot(a)
	got, ok, e := decodeSlot(raw)
	if e != nil || !ok || got != a {
		t.Fatal("slot roundtrip failed")
	}
	raw[20] ^= 1
	if _, ok, e = decodeSlot(raw); ok || e != nil {
		t.Fatal("corrupt slot accepted")
	}
	root := t.TempDir()
	ctx := context.Background()
	if _, e = initialize(root); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "active-a"), encodeSlot(a), 0600); e != nil {
		t.Fatal(e)
	}
	a.id = "ffeeddccbbaa99887766554433221100"
	if e = os.WriteFile(filepath.Join(root, "active-b"), encodeSlot(a), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = readSelection(ctx, root); e == nil {
		t.Fatal("equal sequence conflict accepted")
	}
	// Manifest integrity is checked against the activation record, not just JSON.
	id := importFixture(t, root, 1)
	dir := filepath.Join(root, "versions", id)
	raw, e = os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var m Manifest
	if e = json.Unmarshal(raw, &m); e != nil {
		t.Fatal(e)
	}
	bogus, _ := hex.DecodeString(m.DataSHA256)
	var wrong [32]byte
	copy(wrong[:], bogus)
	if v, e := loadVersion(ctx, dir, id, &wrong); e == nil {
		v.Close()
		t.Fatal("wrong manifest binding accepted")
	}
}
