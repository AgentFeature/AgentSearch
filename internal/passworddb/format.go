package passworddb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const (
	HeaderSize    = 128
	RecordSize    = 28
	PrefixBits    = 20
	PrefixCount   = 1 << PrefixBits
	MaxRangeBytes = 2 << 20
	IndexSize     = HeaderSize + 8*(PrefixCount+1) + 32*PrefixCount
	formatVersion = 1
	dataMagic     = "ASPWNDAT"
	indexMagic    = "ASPWNIDX"
)

var emptyDigest = sha256.Sum256(nil)

type record [RecordSize]byte

func prefix(key []byte) int { return int(key[0])<<12 | int(key[1])<<4 | int(key[2])>>4 }
func validID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == id
}
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func dataSize(n uint64) (int64, error) {
	// Also bounds every legal offset and conversion to int64.
	if n > uint64(PrefixCount)*(MaxRangeBytes/RecordSize) {
		return 0, problem("capacity_exceeded")
	}
	return HeaderSize + int64(n)*RecordSize, nil
}
func header(magic, id string, n uint64) []byte {
	b := make([]byte, HeaderSize)
	copy(b, magic)
	binary.BigEndian.PutUint32(b[8:12], formatVersion)
	b[12] = 1 // SHA-1
	b[13] = PrefixBits
	binary.BigEndian.PutUint16(b[14:16], RecordSize)
	raw, _ := hex.DecodeString(id)
	copy(b[16:32], raw)
	binary.BigEndian.PutUint64(b[32:40], n)
	return b
}
func checkHeader(b []byte, magic, id string, n uint64) error {
	if len(b) != HeaderSize || !bytes.Equal(b, header(magic, id, n)) {
		return problem("invalid_header")
	}
	return nil
}
func offset(idx []byte, p int) uint64 {
	return binary.BigEndian.Uint64(idx[HeaderSize+8*p : HeaderSize+8*(p+1)])
}
func putOffset(idx []byte, p int, n uint64) {
	binary.BigEndian.PutUint64(idx[HeaderSize+8*p:HeaderSize+8*(p+1)], n)
}
func rangeDigest(idx []byte, p int) []byte {
	a := HeaderSize + 8*(PrefixCount+1) + 32*p
	return idx[a : a+32]
}
func makeIndex(id string, n uint64) []byte {
	b := make([]byte, IndexSize)
	copy(b, header(indexMagic, id, n))
	for p := 0; p < PrefixCount; p++ {
		copy(rangeDigest(b, p), emptyDigest[:])
	}
	return b
}
func checkIndex(idx []byte, m Manifest) error {
	if len(idx) != IndexSize {
		return problem("invalid_index")
	}
	if err := checkHeader(idx[:HeaderSize], indexMagic, m.DatasetID, m.RecordCount); err != nil {
		return err
	}
	if offset(idx, 0) != 0 || offset(idx, PrefixCount) != m.RecordCount {
		return problem("invalid_index")
	}
	var largest uint64
	for p := 0; p < PrefixCount; p++ {
		a, b := offset(idx, p), offset(idx, p+1)
		if b < a || b > m.RecordCount {
			return problem("invalid_index")
		}
		size := (b - a) * RecordSize
		if size > MaxRangeBytes {
			return problem("capacity_exceeded")
		}
		if size > largest {
			largest = size
		}
		if size == 0 && !bytes.Equal(rangeDigest(idx, p), emptyDigest[:]) {
			return problem("invalid_index")
		}
	}
	if largest != m.MaxRangeBytes {
		return problem("manifest_mismatch")
	}
	return nil
}
