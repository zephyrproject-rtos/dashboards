#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
# SPDX-License-Identifier: Apache-2.0
"""
FOSSology multi-module index page generator.

Reads per-module JSON summaries produced by foss_report.py from a reports
directory and generates a self-contained HTML index page with an aggregate
compliance overview.

Expected directory layout::

  reports/
    <module>/
      summary.json   (produced by foss_report.py --json)
      report.html    (produced by foss_report.py --html)
    index.html       (written by this script)

Usage::

  python3 scripts/ci/foss_index.py [--reports-dir DIR] [--output FILE]
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


_COPYLEFT_SPDX = {
    "GPL-1.0-only", "GPL-1.0-or-later",
    "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
    "MPL-1.1", "MPL-2.0",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _h(s: object) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_modules(reports_dir: Path) -> list:
    """Load and parse all per-module summary.json files."""
    modules = []
    for summary_file in sorted(reports_dir.glob("*/summary.json")):
        module_name = summary_file.parent.name
        try:
            data = json.loads(summary_file.read_text(encoding="utf-8"))
        except Exception as exc:
            print(
                f"Warning: could not read {summary_file}: {exc}",
                file=sys.stderr,
            )
            continue

        summary = data.get("summary", {})
        lic_dist = data.get("license_distribution", {})
        copyleft = {l: c for l, c in lic_dist.items() if l in _COPYLEFT_SPDX}
        custom_lics = {l: c for l, c in lic_dist.items() if l.startswith("LicenseRef-")}

        total_violations = (
            summary.get("non_allowlisted_files", 0)
            + summary.get("copyright_violations", 0)
            + summary.get("keyword_violations", 0)
        )

        modules.append({
            "name": module_name,
            "report_url": f"{module_name}/report.html",
            "total_files": summary.get("total_files", 0),
            "distinct_licenses": summary.get("distinct_licenses", 0),
            "files_without_license": summary.get("files_without_license", 0),
            "files_without_copyright": summary.get("files_without_copyright", 0),
            "non_allowlisted": summary.get("non_allowlisted_files", 0),
            "copyright_violations": summary.get("copyright_violations", 0),
            "keyword_violations": summary.get("keyword_violations", 0),
            "total_violations": total_violations,
            "copyleft_licenses": copyleft,
            "custom_licenses": custom_lics,
            "has_issues": bool(total_violations or copyleft),
            "top_licenses": sorted(lic_dist.items(), key=lambda x: -x[1])[:5],
        })

    return modules


# ---------------------------------------------------------------------------
# CSS / JS
# ---------------------------------------------------------------------------

_INDEX_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px; color: #222; background: #f5f6fa;
}
#content { max-width: 1500px; margin: 0 auto; padding: 32px 24px; }
/* ---- header ---- */
.page-header {
  background: linear-gradient(135deg, #1e2a3a 0%, #2a4a72 100%);
  color: #fff; border-radius: 10px; padding: 28px 32px; margin-bottom: 32px;
}
.page-header h1 { font-size: 26px; font-weight: 700; }
.page-header p  { color: #a8c4e0; font-size: 13px; margin-top: 6px; }
/* ---- cards ---- */
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
  gap: 14px; margin-bottom: 32px;
}
.card {
  background: #fff; border: 1px solid #dde3ec; border-radius: 8px;
  padding: 18px 16px; text-align: center;
  box-shadow: 0 1px 4px rgba(0,0,0,.06);
}
.card .card-value { font-size: 32px; font-weight: 700; color: #1e2a3a; }
.card .card-value.warn { color: #e05c2e; }
.card .card-value.ok   { color: #2e8b57; }
.card .card-label { font-size: 11px; color: #666; margin-top: 5px;
                    text-transform: uppercase; letter-spacing: .05em; }
/* ---- sections ---- */
.section {
  background: #fff; border-radius: 8px; margin-bottom: 28px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden;
}
.section-header { background: #f0f4f9; border-bottom: 1px solid #dde3ec;
                  padding: 14px 20px; }
.section-header h2 { font-size: 16px; font-weight: 600; color: #1e2a3a; }
.section-body { padding: 20px; }
/* ---- tables ---- */
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
  background: #f0f4f9; color: #1e2a3a; font-weight: 600;
  padding: 9px 12px; text-align: left; border-bottom: 2px solid #dde3ec;
  white-space: nowrap;
}
td { padding: 8px 12px; border-bottom: 1px solid #eef0f4; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8fafd; }
td.num, th.num { text-align: right; }
td.warn { color: #e05c2e; font-weight: 600; }
td.ok   { color: #2e8b57; }
td.mono { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; }
/* ---- badges ---- */
.badge {
  display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11.5px;
  font-weight: 600; font-family: 'SFMono-Regular', Consolas, monospace;
  white-space: nowrap;
}
.badge-copyleft   { background: #f8d7da; color: #721c24; }
.badge-custom     { background: #fff3cd; color: #856404; }
.badge-permissive { background: #d4edda; color: #155724; }
/* ---- status ---- */
.status-ok     { color: #2e8b57; font-weight: 600; }
.status-warn   { color: #e05c2e; font-weight: 600; }
.status-review { color: #856404; font-weight: 600; }
/* ---- misc ---- */
a { color: #2a5fa5; text-decoration: none; }
a:hover { text-decoration: underline; }
.search-wrap { margin-bottom: 10px; }
.search-wrap input {
  width: 100%; max-width: 440px; padding: 7px 12px;
  border: 1px solid #ccc; border-radius: 6px; font-size: 13px;
}
.search-wrap input:focus { outline: none; border-color: #4e79a7; }
.table-scroll { overflow-x: auto; }
@media (max-width: 720px) {
  #content { padding: 16px 12px; }
}
"""

_INDEX_JS = """
document.addEventListener('DOMContentLoaded', function() {
  var inp = document.getElementById('module-search');
  if (inp) {
    inp.addEventListener('input', function() {
      var q = inp.value.toLowerCase();
      document.querySelectorAll('#module-table tbody tr').forEach(function(row) {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
});
"""


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def render_index(modules: list) -> str:
    """Render the full HTML index page from the loaded module data."""
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total_modules = len(modules)
    modules_with_issues = sum(1 for m in modules if m["has_issues"])
    total_violations = sum(m["total_violations"] for m in modules)
    total_files = sum(m["total_files"] for m in modules)
    total_copyleft_hits = sum(1 for m in modules if m["copyleft_licenses"])

    # aggregate copyleft licenses across all modules
    copyleft_by_lic: dict = defaultdict(list)
    for m in modules:
        for lic, cnt in m["copyleft_licenses"].items():
            copyleft_by_lic[lic].append((m["name"], cnt, m["report_url"]))

    lines: list = []
    a = lines.append

    a("<!DOCTYPE html>")
    a('<html lang="en">')
    a("<head>")
    a('<meta charset="UTF-8">')
    a('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    a("<title>FOSSology Reports &mdash; Module Index</title>")
    a(f"<style>{_INDEX_CSS}</style>")
    a("</head>")
    a("<body>")
    a('<div id="content">')

    # ---- page header -------------------------------------------------
    a('<div class="page-header">')
    a("<h1>FOSSology Scan Reports &mdash; Module Index</h1>")
    a(f'<p>Generated: {_h(generated)} &nbsp;&bull;&nbsp; '
      f'{_h(str(total_modules))} modules scanned</p>')
    a("</div>")

    # ---- summary cards -----------------------------------------------
    viol_cls = "warn" if total_violations > 0 else "ok"
    issue_cls = "warn" if modules_with_issues > 0 else "ok"
    copyleft_cls = "warn" if total_copyleft_hits > 0 else "ok"
    a('<div class="card-grid">')
    for val, label, cls in [
        (f"{total_modules:,}",       "Modules Scanned",        ""),
        (f"{total_files:,}",         "Total Files",            ""),
        (f"{modules_with_issues:,}", "Modules With Issues",    issue_cls),
        (f"{total_violations:,}",    "Total Violations",       viol_cls),
        (f"{total_copyleft_hits:,}", "Modules With Copyleft",  copyleft_cls),
    ]:
        a(f'<div class="card">'
          f'<div class="card-value {cls}">{_h(val)}</div>'
          f'<div class="card-label">{_h(label)}</div>'
          f'</div>')
    a("</div>")

    # ---- module compliance table -------------------------------------
    a('<div class="section">')
    a('<div class="section-header"><h2>Module Compliance Overview</h2></div>')
    a('<div class="section-body">')
    a('<div class="search-wrap">'
      '<input id="module-search" type="search" placeholder="Filter modules...">'
      '</div>')
    a('<div class="table-scroll">')
    a('<table id="module-table">')
    a("<thead><tr>")
    for col, cls in [
        ("Module",              ""),
        ("Files",               "num"),
        ("Licenses",            "num"),
        ("No License",          "num"),
        ("Non-Allowlisted",     "num"),
        ("Copyright Viol.",     "num"),
        ("Keyword Viol.",       "num"),
        ("Copyleft Licenses",   ""),
        ("Status",              ""),
    ]:
        a(f'<th class="{cls}">{_h(col)}</th>')
    a("</tr></thead>")
    a("<tbody>")
    for m in modules:
        status_txt = "Issues Found" if m["has_issues"] else "OK"
        status_cls = "status-warn" if m["has_issues"] else "status-ok"
        copyleft_html = " ".join(
            f'<span class="badge badge-copyleft">{_h(l)}</span>&nbsp;({c})'
            for l, c in m["copyleft_licenses"].items()
        ) or '<span class="status-ok">None</span>'
        nl_cls = "warn" if m["files_without_license"] else ""
        na_cls = "warn" if m["non_allowlisted"] else ""
        cv_cls = "warn" if m["copyright_violations"] else ""
        kv_cls = "warn" if m["keyword_violations"] else ""
        a("<tr>")
        a(f'<td><a href="{_h(m["report_url"])}">{_h(m["name"])}</a></td>')
        a(f'<td class="num">{m["total_files"]:,}</td>')
        a(f'<td class="num">{m["distinct_licenses"]:,}</td>')
        a(f'<td class="num {nl_cls}">{m["files_without_license"]:,}</td>')
        a(f'<td class="num {na_cls}">{m["non_allowlisted"]:,}</td>')
        a(f'<td class="num {cv_cls}">{m["copyright_violations"]:,}</td>')
        a(f'<td class="num {kv_cls}">{m["keyword_violations"]:,}</td>')
        a(f'<td>{copyleft_html}</td>')
        a(f'<td class="{status_cls}">{_h(status_txt)}</td>')
        a("</tr>")
    a("</tbody>")
    a("</table>")
    a("</div>")
    a("</div>")
    a("</div>")

    # ---- copyleft overview -------------------------------------------
    a('<div class="section">')
    a('<div class="section-header"><h2>Copyleft License Overview</h2></div>')
    a('<div class="section-body">')
    if copyleft_by_lic:
        a("<table>")
        a('<thead><tr>'
          '<th>License</th>'
          '<th class="num">Modules</th>'
          '<th>Affected Modules (files)</th>'
          '</tr></thead>')
        a("<tbody>")
        for lic in sorted(copyleft_by_lic):
            entries = copyleft_by_lic[lic]
            links = ", ".join(
                f'<a href="{_h(url)}">{_h(name)}</a>&nbsp;({cnt})'
                for name, cnt, url in sorted(entries)
            )
            a(f'<tr>'
              f'<td><span class="badge badge-copyleft">{_h(lic)}</span></td>'
              f'<td class="num">{len(entries):,}</td>'
              f'<td>{links}</td>'
              f'</tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">No copyleft licenses detected across any module.</p>')
    a("</div></div>")

    # ---- violations summary ------------------------------------------
    a('<div class="section">')
    a('<div class="section-header"><h2>Violations Summary</h2></div>')
    a('<div class="section-body">')
    violating = [m for m in modules if m["total_violations"] > 0]
    if violating:
        a("<table>")
        a('<thead><tr>'
          '<th>Module</th>'
          '<th class="num">Non-Allowlisted</th>'
          '<th class="num">Copyright</th>'
          '<th class="num">Keyword</th>'
          '<th class="num">Total</th>'
          '</tr></thead>')
        a("<tbody>")
        for m in sorted(violating, key=lambda x: -x["total_violations"]):
            na_cls = "warn" if m["non_allowlisted"] else ""
            cv_cls = "warn" if m["copyright_violations"] else ""
            kv_cls = "warn" if m["keyword_violations"] else ""
            a(f'<tr>'
              f'<td><a href="{_h(m["report_url"])}">{_h(m["name"])}</a></td>'
              f'<td class="num {na_cls}">{m["non_allowlisted"]:,}</td>'
              f'<td class="num {cv_cls}">{m["copyright_violations"]:,}</td>'
              f'<td class="num {kv_cls}">{m["keyword_violations"]:,}</td>'
              f'<td class="num warn">{m["total_violations"]:,}</td>'
              f'</tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">No violations found across any module.</p>')
    a("</div></div>")

    # ---- custom / LicenseRef overview --------------------------------
    custom_all: dict = defaultdict(list)
    for m in modules:
        for lic, cnt in m["custom_licenses"].items():
            custom_all[lic].append((m["name"], cnt, m["report_url"]))

    a('<div class="section">')
    a('<div class="section-header"><h2>Custom License References (LicenseRef-*)</h2></div>')
    a('<div class="section-body">')
    if custom_all:
        a("<table>")
        a('<thead><tr>'
          '<th>License ID</th>'
          '<th class="num">Modules</th>'
          '<th>Affected Modules (files)</th>'
          '</tr></thead>')
        a("<tbody>")
        for lic in sorted(custom_all):
            entries = custom_all[lic]
            links = ", ".join(
                f'<a href="{_h(url)}">{_h(name)}</a>&nbsp;({cnt})'
                for name, cnt, url in sorted(entries)
            )
            a(f'<tr>'
              f'<td><span class="badge badge-custom">{_h(lic)}</span></td>'
              f'<td class="num">{len(entries):,}</td>'
              f'<td>{links}</td>'
              f'</tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">No custom LicenseRef-* identifiers detected.</p>')
    a("</div></div>")

    a("</div>")
    a(f"<script>{_INDEX_JS}</script>")
    a("</body>")
    a("</html>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate an HTML index page for FOSSology multi-module reports."
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        metavar="DIR",
        help="Directory containing per-module subdirectories (default: reports/)",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Output HTML file (default: <reports-dir>/index.html)",
    )
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    if not reports_dir.is_dir():
        print(f"ERROR: directory '{reports_dir}' not found.", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else reports_dir / "index.html"

    print(f"Loading module summaries from {reports_dir} ...", file=sys.stderr)
    modules = load_modules(reports_dir)
    if not modules:
        print("No module summaries found.", file=sys.stderr)
        return 1

    print(f"Generating index for {len(modules)} module(s) ...", file=sys.stderr)
    html = render_index(modules)
    output_path.write_text(html, encoding="utf-8")
    print(f"Index written to: {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
