package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"
)

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(visible(s)))
	return b.String()
}

// DOCX is a deliberately small OOXML document: paragraphs and named styles,
// no macros, external relationships, active links, assets or license runtime.
func renderDOCX(w io.Writer, r *Report) error {
	lines, err := textLines(r)
	if err != nil {
		return err
	}
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for i, line := range lines {
		style := "Normal"
		if i == 1 {
			style = "Title"
		}
		body.WriteString(`<w:p><w:pPr><w:pStyle w:val="` + style + `"/></w:pPr><w:r><w:t xml:space="preserve">` + xmlText(line) + `</w:t></w:r></w:p>`)
		if body.Len() > MaxOutputBytes {
			return ErrLimit
		}
	}
	body.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>`)
	parts := []struct{ name, value string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`},
		{"word/document.xml", body.String()},
		{"word/styles.xml", `<?xml version="1.0" encoding="UTF-8"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:sz w:val="20"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80"/><w:widowControl/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style></w:styles>`},
		{"word/_rels/document.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`},
		{"docProps/core.xml", `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>AgentSearch Investigation Report</dc:title><dc:creator>AgentSearch</dc:creator><dc:identifier>` + r.ID() + `</dc:identifier><dcterms:created xsi:type="dcterms:W3CDTF">` + r.data.CreatedAt + `</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">` + r.data.CreatedAt + `</dcterms:modified></cp:coreProperties>`},
		{"docProps/app.xml", `<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>AgentSearch</Application></Properties>`},
	}
	z := zip.NewWriter(w)
	for _, p := range parts {
		header := &zip.FileHeader{Name: p.name, Method: zip.Deflate}
		header.SetModTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
		part, err := z.CreateHeader(header)
		if err != nil {
			_ = z.Close()
			return err
		}
		if _, err = io.WriteString(part, p.value); err != nil {
			_ = z.Close()
			return err
		}
	}
	return z.Close()
}

var pdfFont, _ = sfnt.Parse(goregular.TTF)

func renderPDF(w io.Writer, r *Report) error {
	lines, err := textLines(r)
	if err != nil {
		return err
	}
	var buffer sfnt.Buffer
	// Determine the boundary structurally, not by matching attacker-controlled text.
	aiStart := len(lines)
	if r.data.Analysis != nil {
		base := *r
		base.data.Analysis = nil
		prefix, e := textLines(&base)
		if e != nil {
			return e
		}
		aiStart = len(prefix)
	}
	for i, line := range lines {
		if i >= aiStart {
			var escaped strings.Builder
			for _, ch := range line {
				glyph, e := pdfFont.GlyphIndex(&buffer, ch)
				if e != nil || glyph == 0 {
					fmt.Fprintf(&escaped, "\\U%08X", ch)
				} else {
					escaped.WriteRune(ch)
				}
			}
			lines[i] = escaped.String()
			line = lines[i]
		}
		for _, ch := range line {
			glyph, e := pdfFont.GlyphIndex(&buffer, ch)
			if e != nil || glyph == 0 {
				return fmt.Errorf("PDF font does not support U+%04X; use HTML/DOCX instead", ch)
			}
		}
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCatalogSort(true)
	created, _ := time.Parse(time.RFC3339Nano, r.data.CreatedAt)
	pdf.SetCreationDate(created)
	pdf.SetModificationDate(created)
	pdf.SetMargins(16, 16, 16)
	pdf.SetAutoPageBreak(true, 16)
	pdf.SetCompression(true)
	pdf.SetTitle("AgentSearch Investigation Report", true)
	pdf.SetAuthor("AgentSearch", true)
	// fpdf's UTF8 parser uses this mutable byte slice; every renderer owns a copy.
	pdf.AddUTF8FontFromBytes("Report", "", append([]byte(nil), goregular.TTF...))
	pdf.SetFont("Report", "", 10)
	pdf.AddPage()
	for _, line := range lines {
		pdf.MultiCell(178, 5, line, "", "L", false)
		if pdf.PageNo() > MaxPages {
			return ErrLimit
		}
		if pdf.Error() != nil {
			return errors.New("PDF layout generation failed")
		}
	}
	if err := pdf.Output(w); err != nil {
		return fmt.Errorf("PDF finalization failed: %w", err)
	}
	return nil
}
