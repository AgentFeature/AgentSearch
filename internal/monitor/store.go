package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
)

var errFileLimit = errors.New("monitor file exceeds size limit")

const MaxLogBytes = 8 << 20
const MaxLogBatchBytes = 4 << 20

type logState struct {
	size int64
	seen map[string]bool
}

// Store owns an exclusive process lock. Its mutex also serializes embedding
// callers. Files use fixed names or SHA-256 keys, never raw target paths.
type Store struct {
	mu          sync.Mutex
	root, state *os.Root
	lock        *os.File
	logs        map[string]*logState
	files       map[string]bool
	warnings    []string
}

func OpenStore(dir string) (s *Store, err error) {
	if dir == "" || len(dir) > 4096 {
		return nil, errors.New("invalid watch state directory")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("watch directory must not be a symlink")
	}
	// An operator-owned private directory prevents other users replacing children.
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("watch directory must have permissions 0700")
	}
	s = &Store{logs: map[string]*logState{}, files: map[string]bool{}}
	defer func() {
		if err != nil {
			s.Close()
			s = nil
		}
	}()
	s.root, err = os.OpenRoot(dir)
	if err != nil {
		return s, err
	}
	s.lock, err = openRegular(s.root, "watch.lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		return s, err
	}
	if err = lockStore(s.lock); err != nil {
		return s, errors.New("watch directory already locked or locking unsupported")
	}
	if err = s.root.Mkdir("state", 0700); err != nil && !os.IsExist(err) {
		return s, err
	}
	info, err = s.root.Lstat("state")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return s, errors.New("invalid state directory")
	}
	s.state, err = s.root.OpenRoot("state")
	if err != nil {
		return s, err
	}
	folder, err := s.state.Open(".")
	if err != nil {
		return s, err
	}
	entries, e := folder.ReadDir(2*MaxTargets + 1)
	folder.Close()
	if e != nil && e != io.EOF {
		return s, e
	}
	if len(entries) > 2*MaxTargets {
		return s, errors.New("too many state files")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".tmp") && validStorageKey(strings.TrimSuffix(name, ".tmp")) {
			if err = s.state.Remove(name); err != nil {
				return s, err
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") || !validStorageKey(strings.TrimSuffix(name, ".json")) || !entry.Type().IsRegular() {
			return s, errors.New("unexpected state file")
		}
		s.files[name] = true
	}
	if len(s.files) > MaxTargets {
		return s, errors.New("stored target limit exceeded")
	}
	for _, name := range []string{"observations", "changes"} {
		if err = s.loadLog(name); err != nil {
			return s, err
		}
		f, e := openRegular(s.root, name+".jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY)
		if e != nil {
			return s, e
		}
		if e = f.Close(); e != nil {
			return s, e
		}
	}
	return s, nil
}
func validStorageKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func openRegular(root *os.Root, name string, flags int) (*os.File, error) {
	f, err := root.OpenFile(name, flags|safeOpenFlags(), 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("monitor file must be regular")
	}
	return f, nil
}
func readBounded(root *os.Root, name string, limit int) ([]byte, error) {
	f, err := openRegular(root, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, errFileLimit
	}
	return raw, nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.state != nil {
		err = errors.Join(err, s.state.Close())
		s.state = nil
	}
	if s.lock != nil {
		err = errors.Join(err, s.lock.Close())
		s.lock = nil
	}
	if s.root != nil {
		err = errors.Join(err, s.root.Close())
		s.root = nil
	}
	return err
}
func (s *Store) Warnings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.warnings
	s.warnings = nil
	return w
}
func (s *Store) Load(t models.Target) (Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return Snapshot{}, false, errors.New("monitor store closed")
	}
	raw, err := readBounded(s.state, Identity(t)+".json", MaxStateBytes)
	if os.IsNotExist(err) {
		return newSnapshot(t), false, nil
	}
	if err != nil && !errors.Is(err, errFileLimit) {
		return Snapshot{}, false, err
	}
	state, err := parseState(raw, t)
	if err != nil {
		s.warnings = append(s.warnings, "corrupt baseline for target "+Identity(t)+"; next complete source observations establish a new baseline")
		return newSnapshot(t), true, nil
	}
	return state, false, nil
}
func (s *Store) ValidateTargets(targets []models.Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return errors.New("monitor store closed")
	}
	n := len(s.files)
	for _, t := range targets {
		if !s.files[Identity(t)+".json"] {
			n++
		}
	}
	if n > MaxTargets {
		return errors.New("state directory target capacity exceeded; use a new directory or remove inactive baselines")
	}
	return nil
}
func atomicFile(root *os.Root, name string, raw []byte) error {
	temp := strings.TrimSuffix(name, ".json") + ".tmp"
	// The fixed temporary name bounds crash leftovers. Existing symlinks fail closed.
	f, err := openRegular(root, temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = renameWithin(root, temp, name); err != nil {
		return err
	}
	return syncRoot(root)
}
func (s *Store) Save(t models.Target, state Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return errors.New("monitor store closed")
	}
	raw := marshal(state)
	if len(raw) > MaxStateBytes {
		return errors.New("monitor state exceeds size limit")
	}
	if _, err := parseState(raw, t); err != nil {
		return err
	}
	name := Identity(t) + ".json"
	if !s.files[name] && len(s.files) >= MaxTargets {
		return errors.New("stored target limit exceeded")
	}
	if err := atomicFile(s.state, name, raw); err != nil {
		return err
	}
	s.files[name] = true
	return nil
}
func syncRoot(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Incomplete trailing writes are removed; invalid complete records fail closed.
func (s *Store) loadLog(name string) error {
	l := &logState{seen: map[string]bool{}}
	for _, file := range []string{name + ".1.jsonl", name + ".jsonl"} {
		raw, err := readBounded(s.root, file, MaxLogBytes)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = raw[:bytes.LastIndexByte(raw, '\n')+1]
			f, e := openRegular(s.root, file, os.O_WRONLY)
			if e != nil {
				return e
			}
			e = f.Truncate(int64(len(raw)))
			if e == nil {
				e = f.Sync()
			}
			e = errors.Join(e, f.Close())
			if e != nil {
				return e
			}
			s.warnings = append(s.warnings, "recovered incomplete trailing "+name+" log record")
		}
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			id, err := eventID(line)
			if err != nil {
				return errors.New("corrupt complete monitor log record")
			}
			l.seen[id] = true
		}
		if file == name+".jsonl" {
			l.size = int64(len(raw))
		}
	}
	s.logs[name] = l
	return nil
}
func eventID(raw []byte) (string, error) {
	if len(raw) > MaxLogBatchBytes {
		return "", errors.New("event too large")
	}
	var e struct {
		ChangeID string `json:"change_id"`
		RunID    string `json:"run_id"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return "", errors.New("invalid log event")
	}
	id := e.ChangeID
	if id == "" {
		id = e.RunID
	}
	if !validStorageKey(id) {
		return "", errors.New("invalid event identity")
	}
	return id, nil
}
func (s *Store) appendLog(name string, events [][]byte) (resultErr error) {
	// Preflight before any writes; one batch must fit within a half-generation.
	total := 0
	for _, raw := range events {
		total += len(raw) + 1
		if total > MaxLogBatchBytes {
			return errors.New("monitor log batch exceeds limit")
		}
		if _, err := eventID(raw); err != nil {
			return err
		}
	}
	l := s.logs[name]
	if l.size+int64(total) > MaxLogBytes {
		if err := renameWithin(s.root, name+".jsonl", name+".1.jsonl"); err != nil {
			return err
		}
		if err := syncRoot(s.root); err != nil {
			return err
		}
		if err := s.loadLog(name); err != nil {
			return err
		}
		l = s.logs[name]
	}
	f, err := openRegular(s.root, name+".jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	for _, raw := range events {
		id, _ := eventID(raw)
		if l.seen[id] {
			continue
		}
		line := append(append([]byte(nil), raw...), '\n')
		n, err := f.Write(line)
		if err != nil {
			return err
		}
		if n != len(line) {
			return io.ErrShortWrite
		}
		l.size += int64(n)
		l.seen[id] = true
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return syncRoot(s.root)
}
func (s *Store) Observations(observation Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return errors.New("monitor store closed")
	}
	return s.appendLog("observations", [][]byte{marshal(observation)})
}
func (s *Store) Changes(events []Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return errors.New("monitor store closed")
	}
	raw := [][]byte{}
	total := 0
	for _, event := range events {
		line := marshal(event)
		total += len(line) + 1
		if total > MaxLogBatchBytes {
			return fmt.Errorf("change batch exceeds %d bytes", MaxLogBatchBytes)
		}
		raw = append(raw, line)
	}
	if len(raw) == 0 {
		return nil
	}
	return s.appendLog("changes", raw)
}
