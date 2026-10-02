package passworddb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Info is safe dataset provenance. It never contains lookup material.
type Info struct {
	DatasetID, AcquiredAt string
	Recovered             bool
}

// Snapshot pins immutable data. Close drains lookups and releases the lease.
// At most eight range buffers (each <=2 MiB) are admitted concurrently.
type Snapshot struct {
	mu           sync.RWMutex
	closed       bool
	data         *os.File
	index        []byte
	manifest     Manifest
	manifestHash [32]byte
	lease        io.Closer
	info         Info
	permits      chan struct{}
}

func (s *Snapshot) Info() Info { return s.info }
func (s *Snapshot) Close() (err error) {
	defer sanitize(&err)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err = s.data.Close()
	s.index = nil
	if s.lease != nil {
		if e := s.lease.Close(); err == nil {
			err = e
		}
	}
	return err
}
func (s *Snapshot) Lookup(ctx context.Context, key [20]byte) (count uint64, err error) {
	defer sanitize(&err)
	defer clear(key[:])
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, problem("closed")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case s.permits <- struct{}{}:
	}
	defer func() { <-s.permits }()
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	st, err := s.data.Stat()
	if err != nil {
		return 0, err
	}
	if st.Size() != s.manifest.DataSize {
		return 0, problem("truncated_data")
	}
	p := prefix(key[:])
	a, b := offset(s.index, p), offset(s.index, p+1)
	buf := make([]byte, int((b-a)*RecordSize)) // offsets/cap checked at open
	if len(buf) > 0 {
		if _, err = s.data.ReadAt(buf, HeaderSize+int64(a)*RecordSize); err != nil {
			return 0, err
		}
	}
	sum := sha256.Sum256(buf)
	if !bytes.Equal(sum[:], rangeDigest(s.index, p)) {
		return 0, problem("corrupt_range")
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	n := len(buf) / RecordSize
	i := sort.Search(n, func(i int) bool { return bytes.Compare(buf[i*RecordSize:i*RecordSize+20], key[:]) >= 0 })
	if i < n && bytes.Equal(buf[i*RecordSize:i*RecordSize+20], key[:]) {
		count = binary.BigEndian.Uint64(buf[i*RecordSize+20 : (i+1)*RecordSize])
		if count == 0 {
			return 0, problem("corrupt_range")
		}
	}
	return count, nil
}

// loadVersion is called with either a generation lease or the updater lock.
func loadVersion(ctx context.Context, dir, id string, expected *[32]byte) (s *Snapshot, err error) {
	defer sanitize(&err)
	raw, err := readBounded(ctx, filepath.Join(dir, "manifest.json"), maxManifest)
	if err != nil {
		return nil, err
	}
	mh := sha256.Sum256(raw)
	if expected != nil && mh != *expected {
		return nil, problem("manifest_mismatch")
	}
	m, err := decodeManifest(raw, id)
	if err != nil {
		return nil, err
	}
	idx, err := readBounded(ctx, filepath.Join(dir, "prefix.idx"), IndexSize)
	if err != nil {
		return nil, err
	}
	ih := sha256.Sum256(idx)
	if hex.EncodeToString(ih[:]) != m.IndexSHA256 {
		return nil, problem("invalid_index")
	}
	if err = checkIndex(idx, m); err != nil {
		return nil, err
	}
	f, err := openRegular(filepath.Join(dir, "hashes.bin"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() != m.DataSize {
		return nil, problem("truncated_data")
	}
	var hdr [HeaderSize]byte
	if _, err = f.ReadAt(hdr[:], 0); err != nil {
		return nil, err
	}
	if err = checkHeader(hdr[:], dataMagic, id, m.RecordCount); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return &Snapshot{data: f, index: idx, manifest: m, manifestHash: mh, info: Info{DatasetID: id, AcquiredAt: m.AcquiredAt}, permits: make(chan struct{}, 8)}, nil
}

// verifyContents is the full semantic scrub used before activation and on demand.
func (s *Snapshot) verifyContents(ctx context.Context) error {
	buf := make([]byte, MaxRangeBytes)
	h := sha256.New()
	h.Write(header(dataMagic, s.manifest.DatasetID, s.manifest.RecordCount))
	for p := 0; p < PrefixCount; p++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, b := offset(s.index, p), offset(s.index, p+1)
		chunk := buf[:int((b-a)*RecordSize)]
		if len(chunk) == 0 {
			continue
		}
		if _, err := s.data.ReadAt(chunk, HeaderSize+int64(a)*RecordSize); err != nil {
			return err
		}
		sum := sha256.Sum256(chunk)
		if !bytes.Equal(sum[:], rangeDigest(s.index, p)) {
			return problem("corrupt_range")
		}
		for i := 0; i < len(chunk); i += RecordSize {
			r := chunk[i : i+RecordSize]
			if prefix(r[:20]) != p || binary.BigEndian.Uint64(r[20:]) == 0 || i > 0 && bytes.Compare(chunk[i-RecordSize:i-RecordSize+20], r[:20]) >= 0 {
				return problem("invalid_records")
			}
		}
		h.Write(chunk)
	}
	if hex.EncodeToString(h.Sum(nil)) != s.manifest.DataSHA256 {
		return problem("data_checksum_mismatch")
	}
	st, err := s.data.Stat()
	if err != nil {
		return err
	}
	if st.Size() != s.manifest.DataSize {
		return problem("truncated_data")
	}
	return ctx.Err()
}
