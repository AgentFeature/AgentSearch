package passworddb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
)

const slotSize = 4096
const slotMagic = "ASPWNACT"

type activation struct {
	sequence uint64
	id       string
	manifest [32]byte
}

func encodeSlot(a activation) []byte {
	b := make([]byte, slotSize)
	copy(b, slotMagic)
	binary.BigEndian.PutUint32(b[8:12], formatVersion)
	binary.BigEndian.PutUint64(b[16:24], a.sequence)
	id, _ := hex.DecodeString(a.id)
	copy(b[24:40], id)
	copy(b[40:72], a.manifest[:])
	sum := sha256.Sum256(b[:slotSize-32])
	copy(b[slotSize-32:], sum[:])
	return b
}
func decodeSlot(b []byte) (activation, bool, error) {
	var a activation
	if len(b) != slotSize {
		return a, false, nil
	}
	sum := sha256.Sum256(b[:slotSize-32])
	if !bytes.Equal(sum[:], b[slotSize-32:]) || string(b[:8]) != slotMagic {
		return a, false, nil
	}
	if binary.BigEndian.Uint32(b[8:12]) != formatVersion {
		return a, false, problem("unsupported_activation")
	}
	a.sequence = binary.BigEndian.Uint64(b[16:24])
	a.id = hex.EncodeToString(b[24:40])
	copy(a.manifest[:], b[40:72])
	if a.sequence == 0 || !bytes.Equal(b, encodeSlot(a)) {
		return activation{}, false, nil
	}
	return a, true, nil
}

type selection struct {
	slots     [2]activation
	valid     [2]bool
	best      int
	recovered bool
}

func readSelection(ctx context.Context, root string) (selection, error) {
	sel := selection{best: -1}
	for i, name := range []string{"active-a", "active-b"} {
		path := filepath.Join(root, name)
		raw, e := readBounded(ctx, path, slotSize)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			if own, ok := e.(*Error); ok && own.kind == "invalid_file_size" {
				sel.recovered = true
				continue
			}
			return sel, e
		}
		a, ok, e := decodeSlot(raw)
		if e != nil {
			return sel, e
		}
		if !ok {
			if len(raw) > 0 {
				sel.recovered = true
			}
			continue
		}
		sel.slots[i] = a
		sel.valid[i] = true
		if sel.best < 0 || a.sequence > sel.slots[sel.best].sequence {
			sel.best = i
		}
	}
	if sel.valid[0] && sel.valid[1] && sel.slots[0].sequence == sel.slots[1].sequence && sel.slots[0] != sel.slots[1] {
		return sel, problem("activation_conflict")
	}
	return sel, nil
}

// Open selects one generation under the control gate, pins its lease, then loads
// metadata outside the gate. Invalid selected data never triggers another selection.
func Open(ctx context.Context, root string) (s *Snapshot, err error) {
	defer sanitize(&err)
	root, err = rootPath(root)
	if err != nil {
		return nil, err
	}
	gate, err := lock(ctx, filepath.Join(root, "control.lock"), false, true)
	if err != nil {
		return nil, err
	}
	sel, err := readSelection(ctx, root)
	if err != nil {
		gate.Close()
		return nil, err
	}
	if sel.best < 0 {
		gate.Close()
		return nil, problem("not_activated")
	}
	a := sel.slots[sel.best]
	dir, err := versionDir(root, a.id)
	if err != nil {
		gate.Close()
		return nil, err
	}
	lease, err := lock(ctx, filepath.Join(dir, "lease.lock"), false, true)
	gate.Close()
	if err != nil {
		return nil, err
	}
	s, err = loadVersion(ctx, dir, a.id, &a.manifest)
	if err != nil {
		lease.Close()
		return nil, err
	}
	s.lease = lease
	s.info.Recovered = sel.recovered
	return s, nil
}

// Verify performs a complete semantic/integrity scrub of a named generation.
func Verify(ctx context.Context, root, id string) (err error) {
	defer sanitize(&err)
	root, err = rootPath(root)
	if err != nil {
		return err
	}

	// Serialize with creation/failed-import cleanup as well as pruning.
	update, err := lock(ctx, filepath.Join(root, "update.lock"), true, false)
	if err != nil {
		return err
	}
	defer update.Close()
	gate, err := lock(ctx, filepath.Join(root, "control.lock"), false, true)
	if err != nil {
		return err
	}
	dir, err := versionDir(root, id)
	if err != nil {
		gate.Close()
		return err
	}
	lease, err := lock(ctx, filepath.Join(dir, "lease.lock"), false, true)
	gate.Close()
	if err != nil {
		return err
	}
	defer lease.Close()
	s, err := loadVersion(ctx, dir, id, nil)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.verifyContents(ctx)
}

// Activate also implements explicit rollback to a retained ID. Every publication
// is fully verified and uses a new sequence. A failed slot write/Sync is uncertain;
// inspect/retry explicitly, never delete the possibly-published generation.
func Activate(ctx context.Context, root, id string) (err error) {
	defer sanitize(&err)
	root, err = rootPath(root)
	if err != nil {
		return err
	}
	update, err := lock(ctx, filepath.Join(root, "update.lock"), true, false)
	if err != nil {
		return err
	}
	defer update.Close()
	dir, err := versionDir(root, id)
	if err != nil {
		return err
	}
	s, err := loadVersion(ctx, dir, id, nil)
	if err != nil {
		return err
	}
	err = s.verifyContents(ctx)
	mh := s.manifestHash
	closeErr := s.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	gate, err := lock(ctx, filepath.Join(root, "control.lock"), true, true)
	if err != nil {
		return err
	}
	defer gate.Close()
	sel, err := readSelection(ctx, root)
	if err != nil {
		return err
	}
	next := uint64(1)
	slot := 0
	if sel.best >= 0 {
		next = sel.slots[sel.best].sequence + 1
		slot = 1 - sel.best
	}
	if next == 0 {
		return problem("sequence_exhausted")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	name := []string{"active-a", "active-b"}[slot]
	path := filepath.Join(root, name)
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return problem("invalid_file")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	b := encodeSlot(activation{sequence: next, id: id, manifest: mh})
	_, err = f.WriteAt(b, 0)
	if err == nil {
		err = f.Truncate(slotSize)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr = f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(root)
	}
	if err != nil {
		return problem("activation_outcome_uncertain")
	}
	return nil
}

// Prune deletes only versions referenced by neither control slot nor a live lease.
// It deliberately retains both slot targets for recovery. Re-activating the current
// version or publishing another version can retire an older slot reference.
func Prune(ctx context.Context, root string) (removed []string, err error) {
	defer sanitize(&err)
	root, err = rootPath(root)
	if err != nil {
		return nil, err
	}
	update, err := lock(ctx, filepath.Join(root, "update.lock"), true, false)
	if err != nil {
		return nil, err
	}
	defer update.Close()
	gate, err := lock(ctx, filepath.Join(root, "control.lock"), true, true)
	if err != nil {
		return nil, err
	}
	defer gate.Close()
	sel, err := readSelection(ctx, root)
	if err != nil {
		return nil, err
	}
	if sel.best < 0 || sel.recovered {
		return nil, problem("recovery_required_before_prune")
	}
	entries, err := os.ReadDir(filepath.Join(root, "versions"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return removed, err
		}
		id := entry.Name()
		if !validID(id) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		keep := false
		for i, a := range sel.slots {
			if sel.valid[i] && a.id == id {
				keep = true
			}
		}
		if keep {
			continue
		}
		dir := filepath.Join(root, "versions", id)
		lease, e := lock(ctx, filepath.Join(dir, "lease.lock"), true, false)
		if e != nil {
			if own, ok := e.(*Error); ok && own.kind == "busy" {
				continue
			}
			// An interrupted creator can die before creating lease.lock. The
			// updater lock excludes creators; both slot targets were excluded.
			if !os.IsNotExist(e) {
				return removed, e
			}
		}
		// Gate remains held while releasing the lease handle and deleting on Windows.
		if lease != nil {
			if e = lease.Close(); e != nil {
				return removed, e
			}
		}
		for _, name := range []string{"hashes.bin", "prefix.idx", "manifest.json"} {

			path := filepath.Join(dir, name)
			st, statErr := os.Lstat(path)
			if os.IsNotExist(statErr) {
				continue
			}
			if statErr != nil {
				return removed, statErr
			}
			if !st.Mode().IsRegular() {
				return removed, problem("invalid_file")
			}
			e = os.Chmod(path, 0600)
			if e != nil && !os.IsNotExist(e) {
				return removed, e
			}
		}
		if e = os.RemoveAll(dir); e != nil {
			return removed, e
		}
		removed = append(removed, id)
	}
	err = syncDirectory(filepath.Join(root, "versions"))
	return removed, err
}
