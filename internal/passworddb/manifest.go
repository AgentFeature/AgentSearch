package passworddb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"
)

const Profile = "hibp-sha1-ordered-v1"
const maxManifest = 64 << 10

// Manifest describes a supplied artifact, not a certified global HIBP snapshot.
// Complete is an operator attestation; hashes detect subsequent modification.
type Manifest struct {
	Version       int    `json:"version"`
	Builder       string `json:"builder"`
	DatasetID     string `json:"dataset_id"`
	RecordCount   uint64 `json:"record_count"`
	DataSize      int64  `json:"data_size"`
	IndexSize     int64  `json:"index_size"`
	DataSHA256    string `json:"data_sha256"`
	IndexSHA256   string `json:"index_sha256"`
	MaxRangeBytes uint64 `json:"max_range_bytes"`
	BuiltAt       string `json:"built_at"`
	AcquiredAt    string `json:"acquired_at"`
	InputSHA256   string `json:"input_sha256"`
	Profile       string `json:"profile"`
	Complete      bool   `json:"acquisition_complete"`
}

func (m Manifest) validate(id string) error {
	size, err := dataSize(m.RecordCount)
	if err != nil {
		return err
	}
	if m.Version != formatVersion || m.Builder != "agentsearch-stage4-v1" || m.Profile != Profile {
		return problem("unsupported_format")
	}
	if !validID(id) || m.DatasetID != id || m.RecordCount == 0 || m.DataSize != size || m.IndexSize != IndexSize || !m.Complete || m.MaxRangeBytes == 0 || m.MaxRangeBytes > MaxRangeBytes || !validDigest(m.DataSHA256) || !validDigest(m.IndexSHA256) || !validDigest(m.InputSHA256) {
		return problem("invalid_manifest")
	}
	if _, err = time.Parse(time.RFC3339Nano, m.BuiltAt); err != nil {
		return problem("invalid_manifest")
	}
	if _, err = time.Parse(time.RFC3339Nano, m.AcquiredAt); err != nil {
		return problem("invalid_manifest")
	}
	return nil
}
func decodeManifest(b []byte, id string) (Manifest, error) {
	var m Manifest
	if len(b) == 0 || len(b) > maxManifest {
		return m, problem("invalid_manifest")
	}
	// encoding/json otherwise accepts duplicate object fields. This schema is flat.
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return m, problem("invalid_manifest")
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return m, problem("invalid_manifest")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return m, problem("invalid_manifest")
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return m, problem("invalid_manifest")
		}
	}
	if _, err = d.Token(); err != nil {
		return m, problem("invalid_manifest")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, problem("invalid_manifest")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return m, problem("invalid_manifest")
	}
	return m, m.validate(id)
}
func openRegular(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, problem("invalid_file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, problem("invalid_file")
	}
	return f, nil
}
func readBounded(ctx context.Context, path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < 0 || st.Size() > limit {
		return nil, problem("invalid_file_size")
	}
	b := make([]byte, int(st.Size()))
	reader := &contextReader{ctx: ctx, r: f}
	if _, err = io.ReadFull(reader, b); err != nil {
		return nil, err
	}
	var extra [1]byte
	n, e := reader.Read(extra[:])
	if n != 0 {
		return nil, problem("invalid_file_size")
	}
	if e != io.EOF {
		return nil, e
	}
	return b, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(b) > 1<<20 {
		b = b[:1<<20]
	}
	return r.r.Read(b)
}
func hashFile(ctx context.Context, f *os.File, size int64) (string, error) {
	h := sha256.New()
	n, err := io.CopyBuffer(h, &contextReader{ctx: ctx, r: io.NewSectionReader(f, 0, size)}, make([]byte, 1<<20))
	if err != nil {
		return "", err
	}
	if n != size {
		return "", problem("truncated_data")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
