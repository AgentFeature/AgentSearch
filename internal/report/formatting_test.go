package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"golang.org/x/net/html"
)

// Pretty canonical and legacy JSON must stay valid, multiline, consistently
// indented and semantically identical to a compact encoding of the same data.
func TestJSONPrettyFormatting(t *testing.T) {
	r := fixture(t, models.TargetUsername, false)
	for _, tc := range []struct {
		name   string
		render func() ([]byte, error)
	}{
		{"canonical", func() ([]byte, error) { return Render(r, "json") }},
		{"legacy", func() ([]byte, error) { return RenderLegacy(r, "json") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.render()
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(b) {
				t.Fatal("invalid JSON")
			}
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) < 10 {
				t.Fatalf("expected pretty multiline JSON, got %d lines", len(lines))
			}
			for i, line := range lines {
				trimmed := strings.TrimLeft(line, " ")
				indent := len(line) - len(trimmed)
				if indent%2 != 0 {
					t.Fatalf("line %d: odd indentation %d", i, indent)
				}
				if strings.ContainsRune(line[:indent], '\t') {
					t.Fatalf("line %d: tab indentation", i)
				}
			}
			// Unmarshalling the pretty output and a compact re-encoding must
			// describe the same data: formatting only, no semantic change.
			var pretty any
			if err := json.Unmarshal(b, &pretty); err != nil {
				t.Fatal(err)
			}
			compact, err := json.Marshal(pretty)
			if err != nil {
				t.Fatal(err)
			}
			var again any
			if err := json.Unmarshal(compact, &again); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pretty, again) {
				t.Fatal("pretty JSON does not round-trip")
			}
			// No trailing garbage after the single document.
			d := json.NewDecoder(bytes.NewReader(b))
			var first any
			if err := d.Decode(&first); err != nil {
				t.Fatal(err)
			}
			if d.More() {
				t.Fatal("trailing JSON content")
			}
		})
	}
}

// The legacy pretty array must keep the exact legacy field set and values.
func TestLegacyJSONSchemaUnchanged(t *testing.T) {
	r := fixture(t, models.TargetUsername, false)
	b, err := RenderLegacy(r, "json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []models.Result
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(r.data.Results) {
		t.Fatal("legacy rows lost")
	}
	for i, o := range r.data.Results {
		if rows[i].Source != o.Result.Source || rows[i].Status != o.Result.Status || rows[i].Target != o.Result.Target {
			t.Fatal("legacy row data changed")
		}
	}
	var generic []map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	for _, row := range generic {
		for key := range row {
			switch key {
			case "source", "source_type", "target_type", "site_name", "target", "url", "found", "confidence", "status", "duration", "error", "final_url", "evidence", "metadata":
			default:
				t.Fatalf("unexpected legacy JSON field %q", key)
			}
		}
	}
}

func TestSummaryJSONPretty(t *testing.T) {
	raw := summaryJSON(BuildSummary("alice", []models.Result{{Source: "local", Status: models.StatusFound}}, time.Second))
	if !json.Valid(raw) {
		t.Fatal("invalid summary JSON")
	}
	if !bytes.HasSuffix(raw, []byte("\n")) || bytes.Count(raw, []byte("\n")) < 8 {
		t.Fatalf("summary not pretty-printed: %q", raw)
	}
	var summary map[string]any
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if summary["target"] != "alice" || summary["found"] != float64(1) || summary["total"] != float64(1) {
		t.Fatal("summary data changed", summary)
	}
}

// The HTML report groups each logical heading into its own card without
// losing or duplicating any field content.
func TestHTMLCardStructure(t *testing.T) {
	r := fixture(t, models.TargetUsername, false)
	b, err := Render(r, "html")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	type card struct {
		heading string
		fields  int
	}
	var cards []card
	var dividers []string
	headers := 0
	var visit func(*html.Node)
	text := func(n *html.Node) string {
		var b strings.Builder
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.TextNode {
				b.WriteString(n.Data)
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(n)
		return b.String()
	}
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "header":
				headers++
			case "h2":
				for _, a := range n.Attr {
					if a.Key == "class" && strings.Contains(a.Val, "divider") {
						dividers = append(dividers, text(n))
					}
				}
			case "section":
				c := card{}
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					if child.Type != html.ElementNode {
						continue
					}
					if child.Data == "h2" {
						c.heading = text(child)
					}
					if child.Data == "div" {
						for _, a := range child.Attr {
							if a.Key == "class" && strings.Contains(a.Val, "field") {
								c.fields++
							}
						}
					}
				}
				cards = append(cards, c)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(tree)
	if headers != 1 {
		t.Fatalf("expected one header, got %d", headers)
	}
	if len(cards) < 5 {
		t.Fatalf("expected one card per logical group, got %d", len(cards))
	}
	wanted := map[string]bool{"Target and Summary": false, "Sources and Evidence": false, "Correlations": false, "Warnings": false, "Errors": false}
	for _, c := range cards {
		if c.heading == "" {
			t.Fatal("card without heading")
		}
		if c.fields == 0 {
			t.Fatalf("empty card %q", c.heading)
		}
		if _, ok := wanted[c.heading]; ok {
			wanted[c.heading] = true
		}
	}
	// Field-less group headings render as plain dividers, never empty boxes.
	for _, d := range dividers {
		if _, ok := wanted[d]; ok {
			wanted[d] = true
		}
	}
	for heading, seen := range wanted {
		if !seen {
			t.Fatalf("missing card or divider %q", heading)
		}
	}
	// Content parity: every non-heading block value must survive grouping.
	page := text(tree)
	for _, block := range makeView(r).Blocks {
		if block.Heading != "" {
			continue
		}
		if block.Value != "" && !strings.Contains(page, visible(block.Value)) {
			t.Fatalf("card grouping lost value %q", block.Value)
		}
	}
}

// Grouping is presentation-only: block order inside sections matches the
// flat block order used by TXT/PDF/DOCX.
func TestViewGroupingPreservesOrder(t *testing.T) {
	v := makeView(fixture(t, models.TargetEmail, false))
	v.group()
	var regrouped []block
	for _, s := range v.Sections {
		regrouped = append(regrouped, s.Fields...)
	}
	var flat []block
	for _, b := range v.Blocks {
		if b.Heading == "" {
			flat = append(flat, b)
		}
	}
	if !reflect.DeepEqual(flat, regrouped) {
		t.Fatal("grouping reordered or altered fields")
	}
}
