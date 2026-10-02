package passworddb

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ImportOptions records the operator's source-identity and completion assertion.
// Neither that assertion nor a locally computed checksum certifies upstream completeness.
type ImportOptions struct {
	ExpectedSHA256 string
	AcquiredAt     time.Time
	Complete       bool
}

// parseLine accepts an optional BOM only at a new ascending prefix group.
func parseLine(line []byte, previous int) (record, int, error) {
	var r record
	if len(line) > 128 || len(line) == 0 || line[len(line)-1] != '\n' {
		return r, 0, problem("invalid_input")
	}
	line = line[:len(line)-1]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	bom := bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf})
	if bom {
		line = line[3:]
	}
	if len(line) < 42 || len(line) > 61 || line[40] != ':' {
		return r, 0, problem("invalid_input")
	}
	if _, e := hex.Decode(r[:20], line[:40]); e != nil {
		return r, 0, problem("invalid_input")
	}
	var n uint64
	for _, c := range line[41:] {
		if c < '0' || c > '9' || n > (^uint64(0)-uint64(c-'0'))/10 {
			return r, 0, problem("invalid_count")
		}
		n = n*10 + uint64(c-'0')
	}
	if n == 0 {
		return r, 0, problem("invalid_count")
	}
	binary.BigEndian.PutUint64(r[20:], n)
	p := prefix(r[:20])
	if p < previous || bom && p == previous {
		return r, 0, problem("invalid_prefix_order")
	}
	return r, p, nil
}

// Import builds and verifies an unpublished generation. It never activates it.
// Gaps represent no records in the attested artifact, not proof of empty upstream
// ranges. It accepts ascending prefix groups, sorting only inside each group.
func Import(ctx context.Context, root, input string, opt ImportOptions) (id string, err error) {
	defer sanitize(&err)
	if !validDigest(opt.ExpectedSHA256) || !opt.Complete || opt.AcquiredAt.IsZero() {
		return "", problem("acquisition_evidence_required")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	f, err := openRegular(input)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() < 43 {
		return "", problem("invalid_input")
	}
	root, err = initialize(root)
	if err != nil {
		return "", err
	}
	update, err := lock(ctx, filepath.Join(root, "update.lock"), true, false)
	if err != nil {
		return "", err
	}
	defer update.Close()
	// Conservative space bound from the shortest accepted, terminated record.
	maxN := uint64(st.Size() / 43)
	estimated, e := dataSize(maxN)
	if e != nil {
		return "", e
	}
	free, e := availableSpace(root)
	if e != nil {
		return "", e
	}
	if free < uint64(estimated)+IndexSize+maxManifest+(64<<20) {
		return "", problem("insufficient_space")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", err
	}
	id = hex.EncodeToString(random[:])
	dir := filepath.Join(root, "versions", id)
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", err
	}
	sealed := false
	defer func() {
		if !sealed {
			os.RemoveAll(dir)
		}
	}()
	if err = createFile(filepath.Join(dir, "lease.lock")); err != nil {
		return "", err
	}
	data, err := os.OpenFile(filepath.Join(dir, "hashes.bin"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer data.Close()
	if _, err = data.Write(make([]byte, HeaderSize)); err != nil {
		return "", err
	}
	writer := bufio.NewWriterSize(data, 1<<20)
	idx := makeIndex(id, 0)
	group := make([]record, 0, MaxRangeBytes/RecordSize)
	current, next := -1, 0
	var total, largest uint64
	flush := func() error {
		if len(group) == 0 {
			return nil
		}
		sort.Slice(group, func(i, j int) bool { return bytes.Compare(group[i][:20], group[j][:20]) < 0 })
		for i := 1; i < len(group); i++ {
			if bytes.Equal(group[i-1][:20], group[i][:20]) {
				return problem("duplicate_record")
			}
		}
		for next <= current {
			putOffset(idx, next, total)
			next++
		}
		h := sha256.New()
		for i := range group {
			if _, e := writer.Write(group[i][:]); e != nil {
				return e
			}
			h.Write(group[i][:])
		}
		copy(rangeDigest(idx, current), h.Sum(nil))
		size := uint64(len(group)) * RecordSize
		if size > largest {
			largest = size
		}
		total += uint64(len(group))
		group = group[:0]
		return nil
	}
	inputHash := sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(&contextReader{ctx: ctx, r: f}, inputHash), 1<<20)
	for {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		line, e := reader.ReadSlice('\n')
		if e == io.EOF && len(line) == 0 {
			break
		}
		if e != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", problem("invalid_or_incomplete_input")
		}
		r, p, e := parseLine(line, current)
		if e != nil {
			return "", e
		}
		if p != current {
			if e = flush(); e != nil {
				return "", e
			}
			current = p
		}
		if len(group) == cap(group) {
			return "", problem("capacity_exceeded")
		}
		group = append(group, r)
	}
	if total == 0 && len(group) == 0 {
		return "", problem("invalid_input")
	}
	if hex.EncodeToString(inputHash.Sum(nil)) != opt.ExpectedSHA256 {
		return "", problem("input_checksum_mismatch")
	}
	if err = flush(); err != nil {
		return "", err
	}
	for next <= PrefixCount {
		putOffset(idx, next, total)
		next++
	}
	copy(idx, header(indexMagic, id, total))
	if err = writer.Flush(); err != nil {
		return "", err
	}
	if _, err = data.WriteAt(header(dataMagic, id, total), 0); err != nil {
		return "", err
	}
	if err = data.Sync(); err != nil {
		return "", err
	}
	size, err := dataSize(total)
	if err != nil {
		return "", err
	}
	dataHash, err := hashFile(ctx, data, size)
	if err != nil {
		return "", err
	}
	indexHash := sha256.Sum256(idx)
	if err = writeSynced(filepath.Join(dir, "prefix.idx"), idx); err != nil {
		return "", err
	}
	m := Manifest{Version: formatVersion, Builder: "agentsearch-stage4-v1", DatasetID: id, RecordCount: total, DataSize: size, IndexSize: IndexSize, DataSHA256: dataHash, IndexSHA256: hex.EncodeToString(indexHash[:]), MaxRangeBytes: largest, BuiltAt: time.Now().UTC().Format(time.RFC3339Nano), AcquiredAt: opt.AcquiredAt.UTC().Format(time.RFC3339Nano), InputSHA256: opt.ExpectedSHA256, Profile: Profile, Complete: true}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err = writeSynced(filepath.Join(dir, "manifest.json"), append(raw, '\n')); err != nil {
		return "", err
	}
	// Independently reopen and verify encoded files before declaring them sealed.
	idx = nil
	group = nil
	check, err := loadVersion(ctx, dir, id, nil)
	if err != nil {
		return "", err
	}
	err = check.verifyContents(ctx)
	closeErr := check.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err = data.Close(); err != nil {
		return "", err
	}
	for _, name := range []string{"hashes.bin", "prefix.idx", "manifest.json"} {
		if err = os.Chmod(filepath.Join(dir, name), 0400); err != nil {
			return "", err
		}
	}
	if err = syncDirectory(dir); err != nil {
		return "", err
	}
	if err = syncDirectory(filepath.Join(root, "versions")); err != nil {
		return "", err
	}
	sealed = true
	return id, nil
}
func writeSynced(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
