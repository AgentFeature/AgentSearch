package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/passworddb"
)

func TestCorpusCommandWorkflow(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "db")
	text := strings.Repeat("0", 40) + ":7\n"
	sum := sha256.Sum256([]byte(text))
	input := filepath.Join(t.TempDir(), "hashes.txt")
	if e := os.WriteFile(input, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	var out, logs bytes.Buffer
	if run(ctx, []string{"import", "-db", root, "-input", input, "-sha256", hex.EncodeToString(sum[:]), "-acquired-at", "2026-09-10T00:00:00Z", "-complete"}, &out, &logs) != 0 {
		t.Fatal("import command failed", logs.String())
	}
	id := strings.TrimSpace(out.String())
	if s, e := passworddb.Open(ctx, root); e == nil {
		s.Close()
		t.Fatal("import activated implicitly")
	}
	for _, op := range []string{"verify", "activate", "rollback"} {
		if run(ctx, []string{op, "-db", root, "-version", id}, &out, &logs) != 0 {
			t.Fatal("maintenance command failed", logs.String())
		}
	}
	s, e := passworddb.Open(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if n, e := s.Lookup(ctx, [20]byte{}); e != nil || n != 7 {
		t.Fatal("activated lookup failed")
	}
	if run(ctx, []string{"prune", "-db", root}, &out, &logs) != 0 {
		t.Fatal("prune failed")
	}
	if run(ctx, []string{"prune", "-db", root, "-input", input}, &out, &logs) == 0 {
		t.Fatal("irrelevant flag accepted")
	}
}
