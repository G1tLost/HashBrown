"""Offline, escaped HTML acquisition and custody record; no external assets."""
import html
import json

from .acquisition import summary
from .storage import atomic, now


def report(case):
    jobs, custody, gaps = summary(case)
    escape = lambda value: html.escape(str(value), quote=True)
    sections = []
    for job in jobs:
        links = ""
        if job.get("content_path"):
            links += f'<p><a href="{escape(job["content_path"])}">Preserved image bytes</a></p>'
        for ref in job["metadata"]:
            links += f'<p><a href="{escape(ref["file"])}">Original {escape(ref["source"])} metadata</a></p>'
        sections.append(f'<section><h2>{escape(job["id"])} · {escape(job["kind"])}</h2>'
                        f'<p>Status: <strong>{escape(job["status"])}</strong> · '
                        f'{"SYNTHETIC FIXTURE" if job["simulation"] else "Evidence"}</p>{links}'
                        f'<pre>{escape(json.dumps(job, ensure_ascii=False, indent=2))}</pre></section>')
    gap_html = "<ul>" + "".join(f'<li>{escape(gap["value"])}: {escape(gap["reason"])}</li>' for gap in gaps) + "</ul>" if gaps else "<p>No recorded acquisition gaps.</p>"
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>HashBrown {escape(case.id)}</title><style>
body{{font:16px/1.5 system-ui,sans-serif;color:#172029;background:#faf8f2;max-width:1100px;margin:40px auto;padding:0 24px}}
h1,h2{{line-height:1.2}}section{{background:white;border:1px solid #d7d0c0;border-radius:10px;margin:24px 0;padding:22px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,monospace}}a{{color:#655114}}
@media print{{body{{background:white;margin:0}}section{{break-inside:avoid}}}}
</style></head><body><h1>HashBrown acquisition record</h1>
<p>Case <strong>{escape(case.id)}</strong> · {escape(case.label)} · Generated {escape(now())}</p>
<p>This report checks recorded state, file presence, size and modification time. It does not rehash image bytes.
Run <code>hashbrown --root STORE verify {escape(case.id)}</code> for a full integrity check.
A matching hash establishes the integrity of received bytes, not capture completeness.</p>
<h2>Acquisition gaps</h2>{gap_html}{''.join(sections)}<h2>Custody entries</h2>
<pre>{escape(json.dumps(custody, ensure_ascii=False, indent=2))}</pre>
<p>The local SHA-256 custody chain is neither independently signed nor immutable. Keep an independently controlled
copy or hash anchor. Freeform references are analyst statements; HashBrown does not resolve other tools' cases.</p>
</body></html>'''
    path = case.path / "report.html"
    atomic(path, document.encode())
    return dict(case_id=case.id, images=len(jobs), verified_images=sum(j["integrity"] == "verified" for j in jobs),
                gaps=gaps, report=str(path))
