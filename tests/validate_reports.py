#!/usr/bin/env python3
"""Optional offline artifact checks; requires pypdf, PyMuPDF and python-docx.
Generate: AGENTSEARCH_REPORT_FIXTURES=/var/tmp/report-fixtures go test ./internal/report -run TestWriteFixtureArtifacts -count=1
Validate: python3 tests/validate_reports.py /var/tmp/report-fixtures
No network, Office automation, or provider calls are performed.
"""
import csv
import io
import json
from pathlib import Path
import posixpath
import sys
import zipfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
import pymupdf as fitz
from pypdf import PdfReader
from docx import Document

class InertHTML(HTMLParser):
    def handle_starttag(self, tag, attrs):
        assert tag not in {'script', 'iframe', 'object', 'embed', 'img', 'link'}
        for key, _ in attrs:
            assert key not in {'src', 'href'} and not key.startswith('on')

root = Path(sys.argv[1])
count = 0
for file in sorted(root.glob('*.json')):
    stem = file.stem
    data = json.loads(file.read_text())
    assert data['schema'] == 'agentsearch.report.v1'
    assert isinstance(data['results'], list)
    expected = ['long-fixture'] if stem == 'long-fixture' else [
        'fixture-provider', 'failed-provider', 'absent-provider',
        '2100000000000000', 'observed', 'correlated', 'inferred', 'unknown',
        'timeout', 'partial', '\u0411\u0438\u0448\u043a\u0435\u043a', 'Caf\u00e9', '\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac']
    rows = list(csv.DictReader(io.StringIO(root.joinpath(stem+'.csv').read_text())))
    assert len(rows) == 1 + len(data['results']) + data['summary']['evidence_count']
    csv_meta = json.loads(rows[0]['value'])
    assert csv_meta['investigation_id'] == data['investigation_id']
    for observation in data['results']:
        result_row = next(r for r in rows if r['record_type'] == 'result' and r['result_id'] == observation['id'])
        parsed = json.loads(result_row['value'])
        assert parsed['result']['status'] == observation['result']['status']
        evidence_rows = [r for r in rows if r['record_type'] == 'evidence' and r['result_id'] == observation['id']]
        assert [r['value'] for r in evidence_rows] == [e['value'] for e in observation['result'].get('evidence', [])]
    txt = root.joinpath(stem+'.txt').read_text()
    assert max(map(len, txt.splitlines())) <= 100
    html = root.joinpath(stem+'.html').read_text()
    InertHTML().feed(html)
    assert "default-src 'none'" in html
    pdf_file = root / (stem+'.pdf')
    reader = PdfReader(pdf_file, strict=True)
    assert 0 < len(reader.pages) <= 512
    pdf_text = '\n'.join(p.extract_text() for p in reader.pages)
    rendered = fitz.open(pdf_file)
    for page in rendered:
        for word in page.get_text('words'):
            assert word[0] >= 0 and word[1] >= 0 and word[2] <= page.rect.width + 1 and word[3] <= page.rect.height + 1, word
    if stem == 'username':
        rendered[0].get_pixmap(matrix=fitz.Matrix(1,1)).save(root/'pdf-first-page.png')
    docx_file = root / (stem+'.docx')
    with zipfile.ZipFile(docx_file) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == 7
        for name in archive.namelist():
            tree = ET.fromstring(archive.read(name))
            if name.endswith('.rels'):
                parent = '' if name == '_rels/.rels' else 'word'
                for relationship in tree:
                    assert relationship.attrib.get('TargetMode') != 'External'
                    dest = posixpath.normpath(posixpath.join(parent, relationship.attrib['Target']))
                    assert dest in archive.namelist(), dest
    doc = Document(docx_file)
    doc_text = '\n'.join(p.text for p in doc.paragraphs)
    for text in [txt, html, pdf_text, doc_text]:
        for value in expected:
            assert value in text, (stem, value)
    if stem == 'long-fixture':
        assert len(reader.pages) > 1
        assert pdf_text.count('paragraph.') == 1200
        assert doc_text.count('paragraph.') == 1200
    print(f'{stem}: six formats parsed; PDF {len(reader.pages)} pages; DOCX seven parts, relationships and python-docx read OK')
    count += 6
print(f'Validated {count} artifacts. Word/LibreOffice interoperability was NOT tested.')
