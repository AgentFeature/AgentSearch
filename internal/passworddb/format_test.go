package passworddb

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func TestFormatAndManifest(t *testing.T) {
	id := "00112233445566778899aabbccddeeff"
	h := header(dataMagic, id, 42)
	if len(h) != 128 || binary.BigEndian.Uint64(h[32:40]) != 42 || binary.BigEndian.Uint16(h[14:16]) != 28 || h[16] != 0 || h[31] != 0xff {
		t.Fatal("incorrect explicit encoding")
	}
	if checkHeader(h, dataMagic, id, 42) != nil {
		t.Fatal("valid header rejected")
	}
	h[127] = 1
	if checkHeader(h, dataMagic, id, 42) == nil {
		t.Fatal("reserved bytes accepted")
	}
	m := Manifest{Version: 1, Builder: "agentsearch-stage4-v1", DatasetID: id, RecordCount: 1, DataSize: 156, IndexSize: IndexSize, DataSHA256: string(make([]byte, 64)), IndexSHA256: string(make([]byte, 64)), MaxRangeBytes: 28, Complete: true, Profile: Profile, BuiltAt: time.Now().UTC().Format(time.RFC3339Nano), AcquiredAt: time.Now().UTC().Format(time.RFC3339Nano)}
	digest := "0000000000000000000000000000000000000000000000000000000000000000"
	m.DataSHA256 = digest
	m.IndexSHA256 = digest
	m.InputSHA256 = digest
	raw, _ := json.Marshal(m)
	if _, e := decodeManifest(raw, id); e != nil {
		t.Fatal(e)
	}
	bad := append([]byte(`{"version":1,`), raw[1:]...)
	if _, e := decodeManifest(bad, id); e == nil {
		t.Fatal("duplicate manifest fields accepted")
	}
	idx := makeIndex(id, 1)
	for p := 1; p <= PrefixCount; p++ {
		putOffset(idx, p, 1)
	}
	if e := checkIndex(idx, m); e != nil {
		t.Fatal(e)
	}
	putOffset(idx, 2, 0)
	if checkIndex(idx, m) == nil {
		t.Fatal("descending offset accepted")
	}
}
