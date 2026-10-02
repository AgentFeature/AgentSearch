package passworddb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func importFixture(t *testing.T, root string, count int) string {
	t.Helper()
	text := fmt.Sprintf("\xef\xbb\xbf0000000000000000000000000000000000000002:%d\r\n0000000000000000000000000000000000000001:1\n\xef\xbb\xbfabcdef0000000000000000000000000000000000:7\n", count)
	f := filepath.Join(t.TempDir(), "artifact.txt")
	if e := os.WriteFile(f, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(text))
	id, e := Import(context.Background(), root, f, ImportOptions{ExpectedSHA256: hex.EncodeToString(sum[:]), Complete: true, AcquiredAt: time.Now()})
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func TestStrictImporter(t *testing.T) {
	for _, s := range []string{
		strings.Repeat("0", 40) + ":0\n", strings.Repeat("0", 40) + ":18446744073709551616\n", strings.Repeat("0", 40) + ":+1\n", strings.Repeat("0", 40) + ":1", strings.Repeat("0", 32) + ":1\n", strings.Repeat("0", 40) + ": 1\n", strings.Repeat("0", 40) + ":1:2\n",
	} {
		if _, _, e := parseLine([]byte(s), -1); e == nil {
			t.Fatal("invalid record accepted")
		}
	}
	good := []byte(strings.Repeat("0", 40) + ":18446744073709551615\r\n")
	if _, _, e := parseLine(good, -1); e != nil {
		t.Fatal("maximum count rejected")
	}
	bom := append([]byte{0xef, 0xbb, 0xbf}, good...)
	if _, _, e := parseLine(bom, 0); e == nil {
		t.Fatal("BOM inside group accepted")
	}
	root := t.TempDir()
	id := importFixture(t, root, 42)
	s, e := loadVersion(context.Background(), filepath.Join(root, "versions", id), id, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var key [20]byte
	key[19] = 2
	if n, e := s.Lookup(context.Background(), key); e != nil || n != 42 {
		t.Fatal("imported lookup failed")
	}
	key[19] = 3
	if n, e := s.Lookup(context.Background(), key); e != nil || n != 0 {
		t.Fatal("absence failed")
	}
}

func TestImporterRejectsDuplicatesAndDescendingGroups(t *testing.T) {
	a := strings.Repeat("0", 40) + ":1\n"
	b := "FFFFF" + strings.Repeat("0", 35) + ":1\n"
	for _, text := range []string{a + a, b + a} {
		input := filepath.Join(t.TempDir(), "artifact.txt")
		if e := os.WriteFile(input, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256([]byte(text))
		if _, e := Import(context.Background(), t.TempDir(), input, ImportOptions{ExpectedSHA256: hex.EncodeToString(sum[:]), Complete: true, AcquiredAt: time.Now()}); e == nil {
			t.Fatal("invalid ordering or duplicate accepted")
		}
	}
}
