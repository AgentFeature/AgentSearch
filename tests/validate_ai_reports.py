#!/usr/bin/env python3
"""Optional offline AI report artifact validation. No network/model calls.
Generate with AGENTSEARCH_AI_FIXTURES=/var/tmp/ai-fixtures go test ./internal/analysis -run TestFakeFailuresAndAllTargetFormats -count=1
Requires pypdf, PyMuPDF and python-docx.
"""
import csv
import io
import json
from pathlib import Path
import sys
import zipfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pypdf import PdfReader
import pymupdf
from docx import Document

class Inert(HTMLParser):
    def handle_starttag(self, tag, attrs):
        assert tag not in {'script', 'iframe', 'embed', 'object', 'img', 'link'}
        assert all(not k.startswith('on') and k not in {'href', 'src'} for k, _ in attrs)

root = Path(sys.argv[1])
heading = 'AI Analysis (interpretation, not source evidence)'
count = 0
for path in sorted(root.glob('*.json')):
    stem = path.stem
    data = json.loads(path.read_text())
    assert data['analysis']['status'] == 'completed'
    assert data['status'] == 'partial' and len(data['results']) == 2
    ids = {r['id'] for r in data['results']}
    for group in ('findings', 'hypotheses', 'anomalies', 'relationships'):
        for claim in data['analysis'][group]:
            assert claim['evidence_refs']
            for ref in claim['evidence_refs']:
                assert ref.split('/')[0] in ids
    csv_rows = list(csv.DictReader(io.StringIO(root.joinpath(stem+'.csv').read_text())))
    assert json.loads(csv_rows[0]['value'])['analysis'] == data['analysis']
    text = root.joinpath(stem+'.txt').read_text()
    html = root.joinpath(stem+'.html').read_text()
    Inert().feed(html)
    assert '<system>' not in html
    reader = PdfReader(root / (stem+'.pdf'), strict=True)
    pdf_text = '\n'.join(p.extract_text() for p in reader.pages)
    pdf = pymupdf.open(root / (stem+'.pdf'))
    for page in pdf:
        for word in page.get_text('words'):
            assert 0 <= word[0] and 0 <= word[1] and word[2] <= page.rect.width + 1 and word[3] <= page.rect.height + 1
    if stem == 'username':
        for i, page in enumerate(pdf):
            if heading in page.get_text():
                page.get_pixmap().save(root / 'ai-section.png')
                break
    docx_path = root / (stem+'.docx')
    with zipfile.ZipFile(docx_path) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            ET.fromstring(archive.read(name))
    doc_text = '\n'.join(p.text for p in Document(docx_path).paragraphs)
    for content in (text, html, pdf_text, doc_text):
        assert heading in content and 'not source evidence' in content
        assert 'failed' in content and 'fixture' in content
        assert 'ai limitations' in content.lower()
    print(f'{stem}: six formats validated; PDF {len(reader.pages)} pages; evidence retained, AI separate')
    count += 6
assert count == 48
print('48 artifacts validated. No Word/LibreOffice or live model was used.')
