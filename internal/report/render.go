package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/AgentFeature/agentsearch/internal/models"
)

var Formats = []string{"json", "csv", "txt", "html", "pdf", "docx"}

func ValidFormat(s string) bool {
	for _, f := range Formats {
		if s == f {
			return true
		}
	}
	return false
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > MaxOutputBytes-b.Len() {
		return 0, ErrLimit
	}
	return b.Buffer.Write(p)
}
func (b *boundedBuffer) WriteString(s string) (int, error) {
	if len(s) > MaxOutputBytes-b.Len() {
		return 0, ErrLimit
	}
	return b.Buffer.WriteString(s)
}
func Render(r *Report, format string) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	var out boundedBuffer
	var err error
	switch format {
	case "json":
		e := json.NewEncoder(&out)
		e.SetIndent("", "  ")
		err = e.Encode(r.data)
	case "csv":
		err = renderCSV(&out, r)
	case "txt":
		var lines []string
		lines, err = textLines(r)
		if err == nil {
			_, err = out.Write([]byte(strings.Join(lines, "\n") + "\n"))
		}
	case "html":
		v := makeView(r)
		v.Target = visible(v.Target)
		for i := range v.Blocks {
			v.Blocks[i].Heading = visible(v.Blocks[i].Heading)
			v.Blocks[i].Label = visible(v.Blocks[i].Label)
			v.Blocks[i].Value = visible(v.Blocks[i].Value)
		}
		v.group()
		err = htmlReport.Execute(&out, v)
	case "docx":
		err = renderDOCX(&out, r)
	case "pdf":
		err = renderPDF(&out, r)
	default:
		err = fmt.Errorf("unsupported report format")
	}
	if err != nil {
		return nil, err
	}
	if out.Len() > MaxOutputBytes {
		return nil, ErrLimit
	}
	return out.Bytes(), nil
}

type block struct {
	Heading, Label, Value string
	Class                 Classification
}
type view struct {
	Target, ID, Status string
	Blocks             []block
	Sections           []section
}

// section groups the flat block sequence under its preceding heading, so the
// HTML renderer can emit one card per logical group without changing content.
type section struct {
	Heading string
	Fields  []block
}

func (v *view) group() {
	for _, b := range v.Blocks {
		if b.Heading != "" {
			heading := b.Heading
			// The document title is already the page header; label its
			// field group descriptively instead of repeating the title.
			if len(v.Sections) == 0 && heading == "AgentSearch Investigation Report" {
				heading = "Target and Summary"
			}
			v.Sections = append(v.Sections, section{Heading: heading})
			continue
		}
		if len(v.Sections) == 0 {
			v.Sections = append(v.Sections, section{Heading: "Report"})
		}
		s := &v.Sections[len(v.Sections)-1]
		s.Fields = append(s.Fields, b)
	}
}

func makeView(r *Report) view {
	d := r.data
	v := view{Target: d.Target, ID: d.InvestigationID, Status: d.Status}
	add := func(label, value string) { v.Blocks = append(v.Blocks, block{Label: label, Value: value}) }
	heading := func(value string) { v.Blocks = append(v.Blocks, block{Heading: value}) }
	heading("AgentSearch Investigation Report")
	add("Target", d.Target)
	add("Type", string(d.TargetType))
	add("Investigation ID", d.InvestigationID)
	add("Generated (UTC)", d.CreatedAt)
	add("Duration (ns)", strconv.FormatInt(d.DurationNS, 10))
	add("Status", d.Status)
	add("Partial", strconv.FormatBool(d.Partial))
	add("Truncated", strconv.FormatBool(d.Truncated))
	add("Sources", strconv.Itoa(d.Summary.Sources))
	add("Source results", strconv.Itoa(d.Summary.Results))
	add("Evidence count", strconv.Itoa(d.Summary.Evidence))
	add("Successful / failed / partial sources", fmt.Sprintf("%d / %d / %d", d.Summary.Successful, d.Summary.Failed, d.Summary.Partial))
	heading("Sources and Evidence")
	for _, o := range d.Results {
		s := o.Result
		heading("Source: " + s.Source)
		add("Result ID", o.ID)
		add("Display name", s.SiteName)
		add("Source type", string(s.SourceType))
		add("Target", s.Target)
		add("Target type", string(s.TargetType))
		add("Status", string(s.Status))
		add("Outcome", s.OutcomeLabel())
		add("Confidence", r.confidence(o))
		add("Duration (ns)", strconv.FormatInt(int64(s.Duration), 10))
		add("Classification", string(o.Classification))
		add("Observation kind", string(o.ObservationKind))
		add("Meaning", string(o.Meaning))
		add("Provenance URL", s.URL)
		if s.FinalURL != "" {
			add("Final URL", s.FinalURL)
		}
		add("Partial", strconv.FormatBool(o.Partial))
		add("Truncated", strconv.FormatBool(o.Truncated))
		if o.ErrorKind != "" {
			add("Error kind", o.ErrorKind)
		}
		if s.Error != "" {
			add("Error", s.Error)
		}
		for i, e := range s.Evidence {
			v.Blocks = append(v.Blocks, block{Label: fmt.Sprintf("Evidence %d: %s", i, e.Kind), Value: e.Value, Class: o.EvidenceClasses[i]})
		}
		for _, k := range metadataKeys(s.Metadata) {
			add("Metadata: "+k, s.Metadata[k])
		}
	}
	heading("Correlations")
	if len(d.Correlations) == 0 {
		add("Correlations", "None supplied; no correlations invented.")
	} else {
		for _, c := range d.Correlations {
			add("Correlated evidence reference", fmt.Sprintf("%s evidence %d", c.ResultID, c.EvidenceIndex))
		}
	}
	heading("Warnings")
	if len(d.Warnings) == 0 {
		add("Warnings", "None")
	}
	for _, w := range d.Warnings {
		add("Warning", w)
	}
	heading("Errors")
	if len(d.Errors) == 0 {
		add("Investigation errors", "None; source-level errors, if any, are listed above.")
	}
	for _, e := range d.Errors {
		add("Error", e)
	}
	if a := d.Analysis; a != nil {
		heading("AI Analysis (interpretation, not source evidence)")
		add("AI status", a.Status)
		add("AI error code", a.ErrorCode)
		add("AI provider", a.Provider)
		add("AI model", a.Model)
		add("AI input digest", a.InputDigest)
		add("AI input truncated", strconv.FormatBool(a.InputTruncated))
		add("AI records sent", strconv.Itoa(a.RecordsSent))
		add("AI summary", a.Summary)
		for _, group := range []struct {
			name  string
			items []models.AnalysisFinding
		}{{"Findings", a.Findings}, {"Hypotheses", a.Hypotheses}, {"Anomalies", a.Anomalies}, {"Relationships", a.Relationships}} {
			heading("AI " + group.name)
			for _, f := range group.items {
				add("AI "+f.Classification+": "+f.Title, f.Description)
				add("AI evidence references", strings.Join(f.EvidenceRefs, ", "))
				add("AI caveat", f.Caveat)
			}
		}
		heading("AI Unanswered Questions")
		for _, q := range a.UnansweredQuestions {
			add("AI question", q)
		}
		heading("AI Limitations")
		for _, l := range a.Limitations {
			add("AI limitation", l)
		}
	}
	return v
}
func visible(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\n':
			b.WriteRune(c)
		case c == '\t':
			b.WriteString("    ")
		case c == 0xfffe || c == 0xffff || unicode.IsControl(c) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069):
			fmt.Fprintf(&b, "\\u%04x", c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
func wrap(s string, width int) []string {
	out := []string{}
	for _, line := range strings.Split(visible(s), "\n") {
		runes := []rune(line)
		for len(runes) > width {
			n := width
			for i := width; i > width/2; i-- {
				if unicode.IsSpace(runes[i]) {
					n = i
					break
				}
			}
			out = append(out, string(runes[:n]))
			runes = runes[n:]
			if len(runes) > 0 && runes[0] == ' ' {
				runes = runes[1:]
			}
		}
		out = append(out, string(runes))
	}
	return out
}
func textLines(r *Report) ([]string, error) {
	out := []string{}
	for _, b := range makeView(r).Blocks {
		if b.Heading != "" {
			out = append(out, "")
			out = append(out, wrap(b.Heading, 96)...)
			out = append(out, "----------------")
		} else {
			label := b.Label
			if b.Class != "" {
				label = "[" + string(b.Class) + "] " + label
			}
			lines := wrap(label+": "+b.Value, 96)
			for i, line := range lines {
				if i > 0 {
					line = "    " + line
				}
				out = append(out, line)
			}
		}
		if len(out) > MaxLines {
			return nil, ErrLimit
		}
	}
	return out, nil
}

var htmlReport = template.Must(template.New("canonical-report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>AgentSearch investigation report</title>
<style>body{margin:0;background:#f3f5f8;color:#172536;font:16px system-ui,sans-serif;line-height:1.6}main{max-width:1100px;margin:auto;padding:24px}header,section{background:white;border:1px solid #d7dfe8;border-radius:8px;padding:20px;margin:16px 0}h1{font-size:26px}h2{font-size:21px;border-bottom:2px solid #d7dfe8;padding-bottom:8px;margin-top:0}h2.divider{border-bottom:none;margin:24px 4px 0}.field{margin:12px 0;overflow-wrap:anywhere;white-space:pre-wrap}.label{font-weight:650}.badge{display:inline-block;font:12px system-ui;border:1px solid #567;border-radius:4px;padding:2px 6px;margin-right:6px}.observed{background:#e3f5ec}.correlated{background:#e5edff}.inferred{background:#fff1d5}.unknown{background:#eee}code{overflow-wrap:anywhere}@media print{body{background:white}main{padding:0}h2{break-after:avoid}section{break-inside:avoid-page}.field{orphans:3;widows:3}}</style></head>
<body><main><header><h1>AgentSearch Investigation Report</h1><p class="field">Target: {{.Target}}</p><p>Status: <strong>{{.Status}}</strong></p><p class="field">Investigation ID: {{.ID}}</p></header>
{{range .Sections}}{{if .Fields}}<section><h2>{{.Heading}}</h2>
{{range .Fields}}<div class="field">{{if .Class}}<span class="badge {{.Class}}">{{.Class}}</span>{{end}}<span class="label">{{.Label}}:</span> <span>{{.Value}}</span></div>{{end}}
</section>{{else}}<h2 class="divider">{{.Heading}}</h2>{{end}}{{end}}</main></body></html>`))

var CSVHeader = []string{"record_type", "investigation_id", "target_type", "target", "result_id", "source", "source_type", "status", "evidence_type", "classification", "value", "provenance"}

func renderCSV(w io.Writer, r *Report) error {
	writer := csv.NewWriter(w)
	// LF record endings preserve literal CR bytes inside quoted evidence.
	if err := writer.Write(CSVHeader); err != nil {
		return err
	}
	count := 0
	write := func(kind string, o Observation, e models.Evidence, c Classification, value string) error {
		count++
		if count > MaxResults+MaxEvidence+1 {
			return ErrLimit
		}
		provenance := struct {
			URL, FinalURL, Provider string
			Kind                    models.ObservationKind
			Meaning                 models.EvidenceMeaning
		}{o.Result.URL, o.Result.FinalURL, o.Result.Metadata["provider"], o.ObservationKind, o.Meaning}
		return writer.Write([]string{kind, r.ID(), string(r.data.TargetType), r.Target(), o.ID, o.Result.Source, string(o.Result.SourceType), string(o.Result.Status), e.Kind, string(c), value, string(encoded(provenance))})
	}
	metadata := r.data
	metadata.Results = nil
	if err := write("report", Observation{}, models.Evidence{}, Unknown, string(encoded(metadata))); err != nil {
		return err
	}
	for _, o := range r.data.Results {
		result := o
		result.Result.Evidence = nil
		result.EvidenceClasses = nil
		if err := write("result", o, models.Evidence{}, o.Classification, string(encoded(result))); err != nil {
			return err
		}
		for i, e := range o.Result.Evidence {
			if err := write("evidence", o, e, o.EvidenceClasses[i], e.Value); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	return writer.Error()
}

var LegacyCSVHeader = []string{"site_name", "target", "url", "found", "confidence", "status", "duration_ms", "error", "final_url"}

func LegacyCSVRecord(r models.Result) []string {
	r = r.Normalized()
	confidence := strconv.Itoa(r.Confidence)
	if r.UnscoredObservation() {
		confidence = ""
	}
	return []string{r.SiteName, r.Target, r.URL, strconv.FormatBool(r.Found), confidence, string(r.Status), strconv.FormatInt(r.Duration.Milliseconds(), 10), r.Error, r.FinalURL}
}

// Legacy JSON/CSV are compatibility projections, always accompanied by their
// complete canonical report files in the application output pipeline.
func RenderLegacy(r *Report, format string) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	var out boundedBuffer
	if format == "json" {
		rows := make([]reportResult, 0, len(r.data.Results))
		for _, o := range r.data.Results {
			rows = append(rows, reportResult(o.Result))
		}
		// Pretty-print for human readability; the array schema is unchanged.
		e := json.NewEncoder(&out)
		e.SetIndent("", "  ")
		err := e.Encode(rows)
		return out.Bytes(), err
	}
	if format != "csv" {
		return nil, fmt.Errorf("unsupported compatibility projection")
	}
	w := csv.NewWriter(&out)
	if err := w.Write(LegacyCSVHeader); err != nil {
		return nil, err
	}
	for _, o := range r.data.Results {
		if err := w.Write(LegacyCSVRecord(o.Result)); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return out.Bytes(), w.Error()
}
