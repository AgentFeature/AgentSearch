package report

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/models"
	"golang.org/x/net/html"
)

func fixture(t testing.TB, kind models.TargetType, empty bool) *Report {
	t.Helper()
	rows := []models.Result{}
	if !empty {
		rows = []models.Result{
			{Source: "fixture-provider", SourceType: models.SourceAPI, TargetType: kind, Target: "fixture", Status: models.StatusFound, URL: "https://example.test/provenance", Metadata: map[string]string{"provider": "local-fixture", "coverage_status": "partial", "history_truncated": "true"}, Evidence: []models.Evidence{
				{Kind: "observed-item", Value: "Caf\u00e9 \u0411\u0438\u0448\u043a\u0435\u043a \u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac"},
				{Kind: "correlated-item", Value: `{"satoshis":2100000000000000,"index":12}`},
				{Kind: "inferred-item", Value: "cooccurrence is not ownership"},
				{Kind: "unknown-item", Value: "quoted, \"value\"\nsecond line <script>alert(1)</script>"},
			}},
			{Source: "failed-provider", SourceType: models.SourceAPI, TargetType: kind, Target: "fixture", Status: models.StatusError, Error: "provider unavailable", Metadata: map[string]string{"error_kind": "timeout"}},
			{Source: "absent-provider", SourceType: models.SourceAPI, TargetType: kind, Target: "fixture", Status: models.StatusNotFound},
		}
	}
	target := map[models.TargetType]string{models.TargetUsername: "fixture", models.TargetEmail: "fixture@example.test", models.TargetDomain: "example.test", models.TargetIP: "192.0.2.1", models.TargetBitcoin: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", models.TargetBitcoinTransaction: strings.Repeat("a", 64), models.TargetPassword: "sensitive-fixture-input", models.TargetPasswordHash: strings.Repeat("A", 40)}[kind]
	for i := range rows {
		rows[i].Target = target
	}
	r, err := New(kind, target, rows, Options{CreatedAt: time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC), Duration: time.Second, Warnings: []string{"fixture warning"}, Annotations: []Annotation{{"fixture-provider", "observed-item", Observed}, {"fixture-provider", "correlated-item", Correlated}, {"fixture-provider", "inferred-item", Inferred}, {"fixture-provider", "unknown-item", Unknown}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func docxText(t testing.TB, b []byte) string {
	t.Helper()
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"[Content_Types].xml": false, "_rels/.rels": false, "word/document.xml": false, "word/styles.xml": false, "word/_rels/document.xml.rels": false, "docProps/core.xml": false, "docProps/app.xml": false}
	var text strings.Builder
	for _, f := range z.File {
		if _, ok := required[f.Name]; !ok {
			t.Fatalf("unexpected part %s", f.Name)
		}
		required[f.Name] = true
		reader, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`TargetMode="External"`)) {
			t.Fatal("external relationship")
		}
		d := xml.NewDecoder(bytes.NewReader(raw))
		for {
			tok, err := d.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if c, ok := tok.(xml.CharData); ok && f.Name == "word/document.xml" {
				text.Write(c)
				text.WriteByte('\n')
			}
		}
	}
	for part, found := range required {
		if !found {
			t.Fatal("missing part", part)
		}
	}
	return text.String()
}
func TestRendererMatrix(t *testing.T) {
	kinds := []models.TargetType{models.TargetUsername, models.TargetEmail, models.TargetDomain, models.TargetIP, models.TargetBitcoin, models.TargetBitcoinTransaction, models.TargetPassword, models.TargetPasswordHash}
	for _, kind := range kinds {
		for _, empty := range []bool{true, false} {
			r := fixture(t, kind, empty)
			for _, format := range Formats {
				t.Run(string(kind)+"/"+format+"/"+map[bool]string{true: "empty", false: "mixed"}[empty], func(t *testing.T) {
					b, err := Render(r, format)
					if err != nil {
						t.Fatal(err)
					}
					again, err := Render(r, format)
					if err != nil || !bytes.Equal(b, again) {
						t.Fatal("nondeterministic output", err)
					}
					text := string(b)
					switch format {
					case "json":
						var parsed document
						if err = json.Unmarshal(b, &parsed); err != nil {
							t.Fatal(err)
						}
						if parsed.Schema != SchemaVersion || len(parsed.Results) != len(r.data.Results) {
							t.Fatal("JSON data lost")
						}
					case "csv":
						records, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(records[0], CSVHeader) || len(records) != 2+len(r.data.Results)+r.data.Summary.Evidence {
							t.Fatal("CSV rows lost")
						}
						if !empty {
							found := false
							for _, row := range records {
								if row[8] == "unknown-item" {
									found = strings.Contains(row[10], "\nsecond line")
								}
							}
							if !found {
								t.Fatal("CSV multiline value lost")
							}
						}
					case "html":
						tree, err := html.Parse(bytes.NewReader(b))
						if err != nil {
							t.Fatal(err)
						}
						var visit func(*html.Node)
						visit = func(n *html.Node) {
							if n.Type == html.ElementNode {
								switch n.Data {
								case "script", "iframe", "img", "link", "object":
									t.Fatal("active HTML", n.Data)
								}
								for _, a := range n.Attr {
									if a.Key == "src" || a.Key == "href" || strings.HasPrefix(a.Key, "on") {
										t.Fatal("active attribute")
									}
								}
							}
							for c := n.FirstChild; c != nil; c = c.NextSibling {
								visit(c)
							}
						}
						visit(tree)
						if !empty && !strings.Contains(text, "&lt;script&gt;") {
							t.Fatal("HTML escaping")
						}
					case "txt":
						for _, line := range strings.Split(text, "\n") {
							if utf8.RuneCountInString(line) > 100 {
								t.Fatal("unbounded text line")
							}
						}
					case "docx":
						text = docxText(t, b)
					case "pdf":
						if !bytes.HasPrefix(b, []byte("%PDF-")) || !bytes.Contains(b, []byte("%%EOF")) {
							t.Fatal("invalid PDF")
						}
					}
					if !empty && format != "pdf" {
						for _, want := range []string{"fixture-provider", "failed-provider", "absent-provider", "2100000000000000", "observed", "correlated", "inferred", "unknown", "timeout", "partial"} {
							if !strings.Contains(text, want) {
								t.Fatalf("missing %q", want)
							}
						}
					}
				})
			}
		}
	}
}
func TestSnapshotOrderAndImmutability(t *testing.T) {
	rows := []models.Result{{Source: "b", Status: models.StatusFound, Metadata: map[string]string{"z": "last", "a": "first"}, Evidence: []models.Evidence{{Kind: "input", Value: `{"index":12}`}, {Kind: "input", Value: `{"index":2}`}}}, {Source: "a", Status: models.StatusError, Error: "timeout"}}
	r, err := New(models.TargetEmail, "a@example.test", rows, Options{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := Render(r, "json")
	rows[0], rows[1] = rows[1], rows[0]
	rows[1].Evidence[0], rows[1].Evidence[1] = rows[1].Evidence[1], rows[1].Evidence[0]
	other, err := New(models.TargetEmail, "a@example.test", rows, Options{})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := Render(other, "json")
	if !bytes.Equal(before, after) {
		t.Fatal("ordering changed snapshot")
	}
	rows[1].Metadata["z"] = "mutation"
	rows[1].Evidence[0].Value = "mutation"
	after, _ = Render(r, "json")
	if !bytes.Equal(before, after) {
		t.Fatal("input aliases snapshot")
	}
	if strings.Index(string(before), `\"index\":2`) > strings.Index(string(before), `\"index\":12`) {
		t.Fatal("indices sorted lexically")
	}
}
func TestRedactionAndControls(t *testing.T) {
	raw := `{"authorization":"Bearer private-1","cookie":"private-2","nested":{"password":"private-3"},"message":"Cookie: private-4","satoshis":2100000000000000}`
	r, err := New(models.TargetPassword, "private-password", []models.Result{{Source: "local", Target: "private-password", TargetType: models.TargetPassword, Error: raw, Metadata: map[string]string{"nested": raw, "api_key": "private-5"}, Evidence: []models.Evidence{{Kind: "item", Value: raw}, {Kind: "controls", Value: "safe\x00\x1b\u202e\ufffe\uffff"}}}}, Options{Warnings: []string{raw}, Errors: []string{raw}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Formats {
		b, err := Render(r, f)
		if err != nil {
			t.Fatal(f, err)
		}
		text := string(b)
		if f == "docx" {
			text = docxText(t, b)
		}
		for _, secret := range []string{"private-1", "private-2", "private-3", "private-4", "private-5", "private-password"} {
			if strings.Contains(text, secret) {
				t.Fatal(f, "secret leaked")
			}
		}
	}
	for _, o := range r.data.Results {
		if !json.Valid([]byte(o.Result.Error)) || !json.Valid([]byte(o.Result.Metadata["nested"])) {
			t.Fatal("structured redaction broke JSON")
		}
		for _, e := range o.Result.Evidence {
			if e.Kind == "item" && !json.Valid([]byte(e.Value)) {
				t.Fatal("invalid evidence JSON")
			}
		}
	}
}
func TestLimitsAndInvalidInputs(t *testing.T) {
	for _, rows := range [][]models.Result{make([]models.Result, MaxResults+1), {{Source: strings.Repeat("x", MaxFieldBytes+1)}}, {{Evidence: make([]models.Evidence, MaxEvidence+1)}}, {{Evidence: []models.Evidence{{Value: strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)}}}}, {{Source: string([]byte{0xff})}}} {
		if _, err := New(models.TargetUsername, "x", rows, Options{}); !errors.Is(err, ErrLimit) {
			t.Fatal("limit accepted", err)
		}
	}
	for _, f := range Formats {
		if _, err := Render(nil, f); err == nil {
			t.Fatal("nil report accepted")
		}
		if _, err := Render(&Report{}, f); err == nil {
			t.Fatal("uninitialized report accepted")
		}
	}
	if _, err := Render(fixture(t, models.TargetUsername, true), "unknown"); err == nil {
		t.Fatal("invalid format")
	}
	r, err := New(models.TargetUsername, "\u6f22\u5b57", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Render(r, "pdf"); err == nil {
		t.Fatal("missing glyph silently accepted")
	}
	if _, err = Render(r, "docx"); err != nil {
		t.Fatal(err)
	}
	r, err = New(models.TargetUsername, "x", nil, Options{Truncated: true})
	if err != nil || r.data.Status != "partial" || !r.data.Partial {
		t.Fatal("empty truncation hidden", err)
	}
	r, err = New(models.TargetUsername, "x", []models.Result{{Evidence: []models.Evidence{{Value: strings.Repeat("\n", MaxLines+1)}}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"txt", "docx", "pdf"} {
		if _, err = Render(r, f); !errors.Is(err, ErrLimit) {
			t.Fatal("line bound", f, err)
		}
	}
	var b boundedBuffer
	b.Buffer.Grow(MaxOutputBytes)
	b.Buffer.Write(make([]byte, MaxOutputBytes))
	if _, err = b.Write([]byte("x")); !errors.Is(err, ErrLimit) {
		t.Fatal("byte bound")
	}
}
func TestSafeAtomicOutputs(t *testing.T) {
	dir := t.TempDir()
	r := fixture(t, models.TargetEmail, false)
	if err := WriteOutputs(dir, Formats, nil, r); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".json", "_report.json", ".csv", "_report.csv", ".txt", ".html", ".pdf", ".docx"} {
		name := SafeBase(r.Target()) + suffix
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 || info.Mode().Perm() != 0600 {
			t.Fatal("invalid output", name, err)
		}
	}
	for _, v := range []string{"../escape", "..", "/absolute", `a\b`, "CON", "LPT1.txt", strings.Repeat("a", 300), "a:b", "a\x00b"} {
		base := SafeBase(v)
		if len(base) > 120 || strings.ContainsAny(base, "/\\\x00") || base == v {
			t.Fatal("unsafe name", base)
		}
	}
	outside := filepath.Join(t.TempDir(), "sentinel")
	os.WriteFile(outside, []byte("keep"), 0600)
	os.Symlink(outside, filepath.Join(dir, "link.txt"))
	if _, err := writeFile(dir, "link.txt", []byte("replace")); err == nil {
		t.Fatal("symlink accepted")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "keep" {
		t.Fatal("symlink target modified")
	}
	os.Mkdir(filepath.Join(dir, "directory.txt"), 0700)
	if _, err := writeFile(dir, "directory.txt", nil); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := writeFile(dir, "../escape", nil); err == nil {
		t.Fatal("traversal accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	os.Symlink(dir, alias)
	if _, err := writeFile(alias, "x.txt", nil); err == nil {
		t.Fatal("symlink directory accepted")
	}
	for _, e := range mustReadDir(t, dir) {
		if strings.HasPrefix(e.Name(), ".report-") {
			t.Fatal("temporary left behind")
		}
	}
	private := &OutputError{Err: errors.New("/private-email@example.test/token=secret")}
	if strings.Contains(private.Error(), "private-email") {
		t.Fatal("output diagnostic leaked destination")
	}
}
func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return es
}
func TestWriteFixtureArtifacts(t *testing.T) {
	dir := os.Getenv("AGENTSEARCH_REPORT_FIXTURES")
	if dir == "" {
		t.Skip("set AGENTSEARCH_REPORT_FIXTURES for offline external validation")
	}
	for _, kind := range []models.TargetType{models.TargetUsername, models.TargetEmail, models.TargetDomain, models.TargetIP, models.TargetBitcoin, models.TargetBitcoinTransaction, models.TargetPassword, models.TargetPasswordHash} {
		r := fixture(t, kind, false)
		for _, f := range Formats {
			if _, err := WriteReport(dir, string(kind), f, r); err != nil {
				t.Fatal(kind, f, err)
			}
		}
	}
	rows := []models.Result{{Source: "long-fixture", Status: models.StatusFound, Evidence: []models.Evidence{{Kind: "long-value", Value: strings.Repeat("long Unicode \u0411\u0438\u0448\u043a\u0435\u043a & < > paragraph. ", 1200)}}}}
	r, err := New(models.TargetUsername, "long-fixture", rows, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Formats {
		if _, err := WriteReport(dir, "long-fixture", f, r); err != nil {
			t.Fatal(f, err)
		}
	}
}
func FuzzCanonicalReport(f *testing.F) {
	for _, s := range []string{"plain", "<script>alert(1)</script>", "Cookie: secret", `{"satoshis":2100000000000000,"token":"secret"}`, "\u0411\u0438\u0448\u043a\u0435\u043a\nCaf\u00e9", "\x00\u202e"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		r, err := New(models.TargetUsername, "fixture", []models.Result{{Source: "local", Evidence: []models.Evidence{{Kind: "item", Value: s}}}}, Options{})
		if err != nil {
			return
		}
		for _, format := range []string{"json", "csv", "html", "txt", "docx"} {
			a, err := Render(r, format)
			if err != nil {
				continue
			}
			b, err := Render(r, format)
			if err != nil || !bytes.Equal(a, b) {
				t.Fatal("unstable render")
			}
			if format == "docx" {
				docxText(t, a)
			}
		}
	})
}

func TestConcurrentRender(t *testing.T) {
	r := fixture(t, models.TargetUsername, false)
	for _, format := range Formats {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < 3; i++ {
				if _, err := Render(r, format); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestDuplicateReferencesAndCSVCarriageReturns(t *testing.T) {
	row := models.Result{Source: "local", Evidence: []models.Evidence{{Kind: "item", Value: "first\rsecond\r\nthird"}}}
	r, err := New(models.TargetUsername, "x", []models.Result{row, row}, Options{Annotations: []Annotation{{"local", "item", Correlated}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.data.Results[0].ID == r.data.Results[1].ID || len(r.data.Correlations) != 2 {
		t.Fatal("ambiguous duplicate references")
	}
	b, err := Render(r, "csv")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[3][10] != "first\rsecond\nthird" {
		t.Fatal("literal carriage return discarded", rows[3][10])
	}
	// encoding/csv normalizes CRLF to LF when reading, while the file preserves it.
	if !bytes.Contains(b, []byte("first\rsecond\r\nthird")) {
		t.Fatal("CSV changed source bytes")
	}
}

func TestStructuredErrorsAndMixedIndices(t *testing.T) {
	for _, value := range []string{`{"password":"private-value"`, `{"index":1,"index":2}`, `[1] trailing`} {
		if _, err := New(models.TargetUsername, "x", []models.Result{{Evidence: []models.Evidence{{Value: value}}}}, Options{}); err == nil {
			t.Fatal("ambiguous/malformed JSON accepted")
		}
	}
	values := []string{`{"index":2}`, `{"index":12}`, `{"index":19.5}`}
	var want []byte
	for _, permutation := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		row := models.Result{}
		for _, i := range permutation {
			row.Evidence = append(row.Evidence, models.Evidence{Kind: "item", Value: values[i]})
		}
		r, err := New(models.TargetUsername, "x", []models.Result{row}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := Render(r, "json")
		if want == nil {
			want = b
		} else if !bytes.Equal(want, b) {
			t.Fatal("mixed indices violate deterministic ordering")
		}
	}
}

func TestStringWriterBoundAndPublicPDFFailure(t *testing.T) {
	var b boundedBuffer
	b.Buffer.Write(make([]byte, MaxOutputBytes))
	if _, err := io.WriteString(&b, "x"); !errors.Is(err, ErrLimit) {
		t.Fatal("StringWriter bypassed bound")
	}
	r, err := New(models.TargetUsername, "\u6f22", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = WriteOutputs(t.TempDir(), []string{"pdf", "json"}, nil, r)
	if err == nil || !strings.Contains(err.Error(), "U+6F22") {
		t.Fatal("unsupported glyph error hidden", err)
	}
}

func TestKnownProviderClassifications(t *testing.T) {
	for _, tc := range []struct {
		source     string
		kind       models.TargetType
		evidence   string
		want       Classification
		confidence string
	}{{"bitcoin", models.TargetBitcoin, "crypto_counterparty", Correlated, "0%"}, {"bitcoin-tx", models.TargetBitcoinTransaction, "crypto_tx_output", Observed, "not scored"}, {"bitcoin-labels", models.TargetBitcoin, "crypto_label", Observed, "not scored"}, {"hibp", models.TargetEmail, "breach", Observed, "0%"}} {
		r, err := New(tc.kind, "fixture", []models.Result{{Source: tc.source, SourceType: models.SourceAPI, TargetType: tc.kind, Status: models.StatusFound, Evidence: []models.Evidence{{Kind: tc.evidence, Value: `{"satoshis":2100000000000000}`}}}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		o := r.data.Results[0]
		if o.EvidenceClasses[0] != tc.want || r.confidence(o) != tc.confidence {
			t.Fatal(tc.source, "classification/score changed", o)
		}
	}
}
