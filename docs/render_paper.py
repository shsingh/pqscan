#!/usr/bin/env python3
"""pqscan paper: markdown -> arXiv-style PDF (Sys body, PragmataPro Mono code).

Run: /opt/homebrew/opt/python@3.13/bin/python3.13 render_paper.py paper.md paper.pdf

Adapted from the chaos-ai render_paper.py (kailash lineage). pqscan specifics:
- TOC tokens: skips the doc-title token (starts "pqscan") and the injected
  Contents heading itself.
- Fronttoc carries its own page break; the marker pair sits between pagebreak
  divs, matching the sibling papers.
- Audit prints: page count, TOC dest resolution, back-to-contents coverage on
  every page after the TOC page, PDF metadata, and near-blank page check.
"""
import os
import re
import subprocess
import sys

import markdown

WEASYPRINT = "/opt/homebrew/bin/weasyprint"
PDF_TITLE = "pqscan: A Fast, Chainable Cipher-Configuration Scanner for TLS, QUIC, and Post-Quantum Readiness"
METADATA = {
    "title": PDF_TITLE,
    "author": "Shaineel Singh",
    "subject": "TLS, QUIC, and post-quantum cipher-configuration scanning: design, architecture, and verification",
    "creator": "pqscan Project",
    "producer": "WeasyPrint",
}

ATTR_LINE = re.compile(r"^\{:.*\}\s*$", re.M)

CSS = """
@page {
  size: A4;
  margin: 22mm 20mm 20mm 20mm;
  @bottom-center { content: counter(page); font-family: "Sys"; font-size: 9pt; color: #111827; }
  @top-right { content: element(contentslink); }
}
@page :first { @top-right { content: none; } @bottom-center { content: none; } }
body { font-family: "Sys", sans-serif; font-size: 10pt; line-height: 1.5;
       color: #111827; hyphens: none; }
h1 { font-family: "Sys"; font-weight: 700; font-size: 17pt; text-align: center;
     margin: 0 0 14pt 0; color: #111827; }
h1:not(:first-of-type) { text-align: left; font-size: 13.5pt; margin: 16pt 0 8pt 0; }
div.titleblock { text-align: center; margin: 18pt 0 6pt 0; }
div.titleblock p { margin: 3pt 0; }
.titleblock p.authorline { font-weight: 700; font-size: 11pt; }
.titleblock p.affilline { font-size: 10pt; }
.titleblock p.revsline { font-style: italic; color: #374151; font-size: 9.5pt; }
h2 { font-family: "Sys"; font-weight: 600; font-size: 11.5pt; margin: 13pt 0 5pt 0; }
h3 { font-family: "Sys"; font-weight: 600; font-size: 10.2pt; margin: 10pt 0 4pt 0; }
p { margin: 4pt 0 6pt 0; text-align: justify; }
div.titleblock p, p.abstractpara, p.keywordsline, li p, td p, th p { text-align: inherit; }
ul, ol { margin: 3pt 0 6pt 0; padding-left: 16pt; }
li { margin: 2pt 0; text-align: justify; }
code { font-family: "PragmataPro Mono", monospace; font-size: 8.6pt;
       background: #f3f4f6; padding: 0 2pt; border-radius: 2pt; }
pre { font-family: "PragmataPro Mono", monospace; font-size: 8pt; line-height: 1.4;
      background: none; border: none; border-left: 2pt solid #d1d5db;
      padding: 4pt 0 4pt 10pt; margin: 6pt 0 9pt 0; white-space: pre-wrap;
      break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8pt; }
table { border-collapse: collapse; width: 100%; margin: 7pt 0 11pt 0;
        font-size: 8.6pt; }
thead { border-top: 1.2pt solid #111827; border-bottom: 0.6pt solid #111827; }
th { font-family: "Sys"; font-weight: 600; text-align: left; padding: 3.5pt 6pt; }
td { padding: 3.5pt 6pt; vertical-align: top; text-align: left; }
tr { page-break-inside: avoid; }
blockquote { margin: 6pt 0 6pt 12pt; padding: 2pt 0 2pt 10pt;
             border-left: 1.5pt solid #111827; color: #111827; }
a { color: #111827; text-decoration: none; }
.pagebreak { page-break-after: always; }
p.abstractpara { margin-left: 18pt; margin-right: 18pt; font-size: 9.5pt; }
p.keywordsline { margin-left: 18pt; margin-right: 18pt; font-size: 9.5pt; }
.fronttoc { page-break-after: always; break-after: page; }
.fronttoc h2 { font-size: 13.5pt; margin: 16pt 0 8pt 0; }
.fronttoc li { margin: 0.5pt 0; }
.fronttoc a { font-size: 8.5pt; }
.fronttoc ul { padding-left: 12pt; }
.fronttoc li.lvl3 { padding-left: 14pt; font-size: 8.3pt; color: #374151; }
.contentslink { position: running(contentslink); }
.contentslink a { font-family: "Sys"; color: #6b7280; font-size: 8.5pt;
                  text-decoration: none; }
"""


def toc_rows(level_tokens, counter):
    out = []
    for tok in level_tokens:
        name = tok["name"].strip()
        if tok["level"] == 1 and (
            name.lower().startswith("pqscan") or name.lower().startswith("table of contents")
        ):
            continue
        if tok["level"] == 1:
            counter[0] += 1
            clean = re.sub(r"^\d+\.\s*", "", name)
            out.append('<li><a href="#%s">%d. %s</a></li>' % (tok["id"], counter[0], clean))
        else:
            out.append('<li class="lvl3"><a href="#%s">%s</a></li>' % (tok["id"], name))
        out += toc_rows(tok.get("children", []), counter)
    return out


def build_toc_html(md):
    flat = toc_rows(md.toc_tokens, [0])
    return (
        '<div class="fronttoc"><h2 id="table-of-contents">Table of Contents</h2><ul>'
        + "".join(flat)
        + "</ul></div>"
    )


def main():
    src, pdf = sys.argv[1], sys.argv[2]
    text = open(src).read()

    text = re.sub(r"<!-- TOC_BLOCK_START -->.*?<!-- TOC_BLOCK_END -->",
                  "<!-- TOC_BLOCK_START -->\n<!-- TOC_BLOCK_END -->",
                  text, count=1, flags=re.S)
    text = ATTR_LINE.sub("", text)

    probe = markdown.Markdown(extensions=["toc", "tables", "fenced_code", "sane_lists", "md_in_html"])
    probe.convert(text)
    entries = build_toc_html(probe)
    text = text.replace("<!-- TOC_BLOCK_START -->\n<!-- TOC_BLOCK_END -->", entries)

    md = markdown.Markdown(extensions=["toc", "tables", "fenced_code", "sane_lists", "md_in_html"])
    body = md.convert(text)

    link = '<a class="contentslink" href="#table-of-contents">▲ Contents</a>'
    body = link + body

    html_path = "/tmp/_pqscan_paper.html"
    with open(html_path, "w") as f:
        f.write('<!DOCTYPE html>\n<html><head><meta charset="UTF-8">'
                f"<style>{CSS}</style></head>\n<body>{body}</body></html>")

    r = subprocess.run([WEASYPRINT, html_path, pdf], capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        sys.exit("WEASYPRINT_ERROR: " + r.stderr[-1200:])
    for line in r.stderr.splitlines():
        if "No anchor" in line or "ERROR" in line:
            print("WEASY:", line)
    print("PDF OK: %.0f KB (%s)" % (os.path.getsize(pdf) / 1024, pdf))

    try:
        import pymupdf

        doc = pymupdf.open(pdf)
        doc.set_metadata(METADATA)
        doc.saveIncr()
        all_links = [l for i in range(doc.page_count) for l in doc[i].get_links()]
        toc_page = next((l["page"] for l in all_links if l.get("nameddest") == "table-of-contents"), None)
        if toc_page is None:
            missing = ["TOC dest 'table-of-contents' NOT FOUND"]
        else:
            missing = [i + 1 for i in range(toc_page, doc.page_count)
                       if not any(l.get("nameddest") == "table-of-contents" for l in doc[i].get_links())]
        print("back-to-TOC link missing on pages:", missing or "none")
        print("page count:", doc.page_count)
        blank = [i + 1 for i in range(doc.page_count) if len(doc[i].get_text().strip()) < 5]
        print("near-blank pages:", blank or "none")
        print("metadata:", {k: doc.metadata.get(k) for k in ("title", "author", "subject")})
    except ImportError:
        print("note: pymupdf missing - link verification skipped")


if __name__ == "__main__":
    main()
