package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func TestStorePersistenceAtomicFailureAndRecovery(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir)
	subject := target(t, "example.com")
	p, err := project([]models.Result{row("source", "http_service", "A")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseline, _, _ := merge(newSnapshot(subject), p.Good)
	if err = s.Save(subject, baseline); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(dir, "state", Identity(subject)+".tmp")
	if err = os.Symlink(outside, temporary); err != nil {
		t.Fatal(err)
	}
	changed := baseline
	changed.Revision++
	if err = s.Save(subject, changed); err == nil {
		t.Fatal("unsafe temporary followed")
	}
	old, _, err := s.Load(subject)
	if err != nil || !bytes.Equal(marshal(old), marshal(baseline)) {
		t.Fatal("atomic failure damaged baseline")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "untouched" {
		t.Fatal("escaped root")
	}
	s.Close()
	s = openTestStore(t, dir)
	old, _, err = s.Load(subject)
	if err != nil || !bytes.Equal(marshal(old), marshal(baseline)) {
		t.Fatal("recovery lost old baseline")
	}
	if _, err = os.Lstat(temporary); !os.IsNotExist(err) {
		t.Fatal("abandoned temporary not cleaned")
	}
}
func TestCorruptStateRebaselineNoChanges(t *testing.T) {
	for _, bad := range []string{"{", `{"version":100}`, strings.Repeat("x", MaxStateBytes+1)} {
		t.Run(fmt.Sprint(len(bad)), func(t *testing.T) {
			dir := t.TempDir()
			s := openTestStore(t, dir)
			subject := target(t, "example.com")
			if err := os.WriteFile(filepath.Join(dir, "state", Identity(subject)+".json"), []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			e, err := New(searchFunc(func(_ context.Context, _ models.Target, emit sources.Emit) error {
				return emit(row("fixture", "service", "A"))
			}), s, []models.Target{subject}, DefaultOptions(), &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Warnings()) == 0 {
				t.Fatal("corruption not reported")
			}
			cycle(t, e)
			if len(readChanges(t, dir)) != 0 {
				t.Fatal("corrupt state generated changes")
			}
			state, corrupt, err := s.Load(subject)
			if err != nil || corrupt || len(state.Sources) != 1 {
				t.Fatal("did not establish baseline", err)
			}
		})
	}
}
func TestCrashWindowChangeIDs(t *testing.T) {
	dir := t.TempDir()
	subject := target(t, "example.com")
	value := "100"
	f := searchFunc(func(_ context.Context, _ models.Target, emit sources.Emit) error {
		return emit(row("fixture", "balance", value))
	})
	e, _ := newTestEngine(t, dir, []models.Target{subject}, f)
	cycle(t, e)
	value = "150"
	// Force failure after durable log append but before atomic baseline replacement.
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("safe"), 0600)
	if err := os.Symlink(outside, filepath.Join(dir, "state", Identity(subject)+".tmp")); err != nil {
		t.Fatal(err)
	}
	if err := e.cycle(context.Background()); err == nil {
		t.Fatal("expected storage error")
	}
	if len(readChanges(t, dir)) != 1 {
		t.Fatal("change not durable")
	}
	e.store.Close()
	e, _ = newTestEngine(t, dir, []models.Target{subject}, f)
	cycle(t, e)
	if len(readChanges(t, dir)) != 1 {
		t.Fatal("crash replay duplicated durable change")
	}
}
func TestLogAppendRotationAndTailRepair(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir)
	padding := strings.Repeat("x", 1<<20)
	for i := 0; i < 20; i++ {
		raw := marshal(map[string]any{"run_id": fmt.Sprintf("%064x", i), "padding": padding})
		s.mu.Lock()
		err := s.appendLog("observations", [][]byte{raw})
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"observations.jsonl", "observations.1.jsonl"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() > MaxLogBytes {
			t.Fatal("log bound", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "observations.2.jsonl")); !os.IsNotExist(err) {
		t.Fatal("unbounded archive")
	}
	// Redelivery of a retained ID does not append another record.
	before, _ := os.Stat(filepath.Join(dir, "observations.jsonl"))
	s.mu.Lock()
	err := s.appendLog("observations", [][]byte{marshal(map[string]any{"run_id": fmt.Sprintf("%064x", 19), "padding": padding})})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(dir, "observations.jsonl"))
	if after.Size() != before.Size() {
		t.Fatal("duplicate log")
	}
	s.Close()
	file, err := os.OpenFile(filepath.Join(dir, "observations.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(`{"run_id":`)
	file.Close()
	s = openTestStore(t, dir)
	if len(s.Warnings()) == 0 {
		t.Fatal("tail repair not reported")
	}
	after, _ = os.Stat(filepath.Join(dir, "observations.jsonl"))
	if after.Size() != before.Size() {
		t.Fatal("tail not repaired")
	}
}
func TestStorageSafetyAndBounds(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir)
	if other, err := OpenStore(dir); err == nil {
		other.Close()
		t.Fatal("concurrent monitor admitted")
	}
	subject, _ := models.NewTarget(models.TargetUsername, "../../outside/\u540d\u5b57")
	if !validStorageKey(Identity(subject)) || strings.ContainsAny(Identity(subject), "/:") {
		t.Fatal("unsafe identity")
	}
	if err := s.Save(subject, newSnapshot(subject)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", Identity(subject)+".json")); err != nil {
		t.Fatal("hashed storage")
	}
	bad := newSnapshot(subject)
	bad.Sources = []SourceState{{Source: "fake", Type: models.SourceAPI, Evidence: []models.Evidence{{Kind: "secret", Value: strings.Repeat("x", MaxValueBytes+1)}}}}
	if err := s.Save(subject, bad); err == nil {
		t.Fatal("state bounds")
	}
	if err := s.Changes([]Change{{ID: "bad"}}); err == nil {
		t.Fatal("invalid log identity")
	}
	for i := 0; i < MaxTargets; i++ {
		s.files[fmt.Sprintf("%064x.json", i)] = true
	}
	if err := s.ValidateTargets([]models.Target{target(t, "new.example")}); err == nil {
		t.Fatal("on-disk target capacity")
	}
}
func TestSymlinkLogsAndCorruptCompleteLog(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		dir := t.TempDir()
		os.Chmod(dir, 0700)
		path := filepath.Join(dir, "observations.jsonl")
		if symlink {
			outside := filepath.Join(t.TempDir(), "target")
			os.WriteFile(outside, []byte("outside"), 0600)
			os.Symlink(outside, path)
		} else {
			os.WriteFile(path, []byte("bad-json\n"), 0600)
		}
		s, err := OpenStore(dir)
		if err == nil {
			s.Close()
			t.Fatal("unsafe/corrupt log accepted")
		}
	}
}
func TestPersistedStateRejectsSecretsAndWrongIdentity(t *testing.T) {
	subject := target(t, "example.com")
	state := newSnapshot(subject)
	state.Sources = []SourceState{{Source: "fixture", Type: models.SourceAPI, Provenance: []Provenance{{Source: "fixture", SourceType: models.SourceAPI}}, Evidence: []models.Evidence{{Kind: "token", Value: "secret-value"}}}}
	if _, err := parseState(marshal(state), subject); err == nil {
		t.Fatal("unredacted stored secret accepted")
	}
	clean := newSnapshot(subject)
	raw := marshal(clean)
	if _, err := parseState(raw, target(t, "other.example")); err == nil {
		t.Fatal("wrong target baseline")
	}
	if _, err := parseState(append(raw, []byte("{}")...), subject); err == nil {
		t.Fatal("trailing state accepted")
	}
	var check any
	if json.Unmarshal(raw, &check) != nil {
		t.Fatal("bad canonical state")
	}
}

func TestConcurrentStoreAndLogs(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir)
	subject := target(t, "example.com")
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if err := s.Save(subject, newSnapshot(subject)); err != nil {
					t.Error(err)
				}
				if _, _, err := s.Load(subject); err != nil {
					t.Error(err)
				}
				if err := s.Observations(Observation{RunID: fmt.Sprintf("%064x", worker*10+i), Target: subject.Value()}); err != nil {
					t.Error(err)
				}
			}
		}(worker)
	}
	wg.Wait()
	if len(lines(t, dir, "observations")) != 40 {
		t.Fatal("concurrent appends lost")
	}
	s.Close()
	if err := s.Save(subject, newSnapshot(subject)); err == nil {
		t.Fatal("closed store accepted write")
	}
}
