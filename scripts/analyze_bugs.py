#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
# SPDX-License-Identifier: Apache-2.0
"""Analyze open bug issues in the Zephyr GitHub repository.

For every open issue carrying the ``bug`` label the script collects a set
of signals, classifies the issue into one or more backlog categories, and
writes a self-contained HTML dashboard.

Signals collected per bug
--------------------------
- Age (days since opened) and idle time (days since ``updated_at``)
- Priority derived from labels (critical / high / medium / low / none)
- Area / subsystem / architecture labels
- Assignment status (assignee logins)
- Comment count (engagement proxy; available without extra API calls)
- Milestone (version the bug is targeted at, if any)
- Whether the bug carries Stale, Help Wanted, or Good First Issue labels

Categories
----------
- critical         : Priority: critical
- high             : Priority: high
- medium           : Priority: medium
- low              : Priority: low
- no_priority      : no priority label at all
- unassigned       : no assignee
- stale            : carries Stale label
- long_open        : open > 365 days
- no_comments      : zero comments since opening
- help_wanted      : carries Help Wanted label
- good_first_issue : carries Good First Issue label
- needs_triage     : no priority AND no area label

Usage
-----
    # Requires a GitHub token with repo:read scope
    export GITHUB_TOKEN=<token>

    python3 scripts/analyze_bugs.py \\
        [--org zephyrproject-rtos] \\
        [--repo zephyr] \\
        [--max-issues 2000] \\
        [--output bugs.html] \\
        [--history bugs_history.json] \\
        [--cache bugs_cache.json] \\
        [--verbose]
"""

import argparse
import collections
import datetime
import html
import json
import os
import pathlib
import re
import sys
import time

try:
    from github import Auth, Github, GithubException
except ImportError:
    sys.exit("PyGitHub is required.  Install with: pip install PyGithub")

# ---------------------------------------------------------------------------
# Bug backlog categories
# ---------------------------------------------------------------------------
CAT_HIGH             = "high"
CAT_MEDIUM           = "medium"
CAT_LOW              = "low"
CAT_NO_PRIORITY      = "no_priority"
CAT_UNASSIGNED       = "unassigned"
CAT_STALE            = "stale"
CAT_LONG_OPEN        = "long_open"
CAT_NO_COMMENTS      = "no_comments"
CAT_HELP_WANTED      = "help_wanted"
CAT_GOOD_FIRST_ISSUE = "good_first_issue"
CAT_NEEDS_TRIAGE     = "needs_triage"
CAT_RELEASE_BLOCKER  = "release_blocker"

CATEGORY_META = {
    CAT_RELEASE_BLOCKER: {
        "label": "Release Blocker",
        "color": "#641e16",
        "description": (
            "Carries the 'Release Blocker' label — must be resolved before "
            "the next release ships."
        ),
    },
    CAT_HIGH: {
        "label": "High Priority",
        "color": "#c0392b",
        "description": "Bugs marked Priority: high.",
    },
    CAT_MEDIUM: {
        "label": "Medium Priority",
        "color": "#e67e22",
        "description": "Bugs marked Priority: medium.",
    },
    CAT_LOW: {
        "label": "Low Priority",
        "color": "#f0b429",
        "description": "Bugs marked Priority: low.",
    },
    CAT_NO_PRIORITY: {
        "label": "No Priority",
        "color": "#95a5a6",
        "description": "No priority label has been set on this bug yet.",
    },
    CAT_UNASSIGNED: {
        "label": "Unassigned",
        "color": "#e74c3c",
        "description": (
            "No assignee — nobody is currently responsible for fixing this bug."
        ),
    },
    CAT_STALE: {
        "label": "Stale",
        "color": "#bdc3c7",
        "description": (
            "Carries the Stale label — no meaningful activity for an extended period."
        ),
    },
    CAT_LONG_OPEN: {
        "label": "Long Open (> 365 d)",
        "color": "#8e44ad",
        "description": "Has been open for more than one year without being resolved.",
    },
    CAT_NO_COMMENTS: {
        "label": "No Comments",
        "color": "#7f8c8d",
        "description": (
            "Zero comments — the bug has been completely ignored since filing."
        ),
    },
    CAT_HELP_WANTED: {
        "label": "Help Wanted",
        "color": "#27ae60",
        "description": "Explicitly tagged for community contribution.",
    },
    CAT_GOOD_FIRST_ISSUE: {
        "label": "Good First Issue",
        "color": "#1abc9c",
        "description": "Suitable entry-point for new contributors.",
    },
    CAT_NEEDS_TRIAGE: {
        "label": "Needs Triage",
        "color": "#f39c12",
        "description": (
            "No priority label and no area label — has not been triaged yet."
        ),
    },
}

# Ordered priority list (highest → lowest) for sorting / display
PRIORITY_ORDER = {
    "high":   0,
    "medium": 1,
    "low":    2,
    None:     3,
}

LONG_OPEN_DAYS = 365

# Labels (lower-cased) whose prefix identifies the priority.
# Format used in zephyr: "priority: high", "priority: medium", "priority: low"
_PRIORITY_RE = re.compile(
    r"^priority\s*:\s*(high|medium|low)$", re.IGNORECASE
)

# Label prefixes that signal an area / subsystem
_AREA_PREFIXES = (
    "area:",
    "subsys:",
    "subsystem:",
    "arch:",
    "platform:",
    "driver:",
    "module:",
    "board:",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gh_connect(token):
    if token:
        return Github(auth=Auth.Token(token))
    return Github()


def _age_days(dt):
    """Days since *dt* (tz-aware or naive)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return (now - dt).days


def _parse_priority(label_names):
    """Return the priority string, or None if no priority label found."""
    for name in label_names:
        m = _PRIORITY_RE.match(name.strip())
        if m:
            return m.group(1).lower()
    return None


def _parse_areas(label_names):
    """Return labels that look like area / subsystem markers."""
    areas = []
    for name in label_names:
        low = name.lower()
        if any(low.startswith(p) for p in _AREA_PREFIXES):
            areas.append(name)
    return areas


# ---------------------------------------------------------------------------
# Per-issue analysis
# ---------------------------------------------------------------------------

def _analyze_issue(issue, verbose=False):
    """
    Collect all signals for a single GitHub issue.

    *issue* is a PyGitHub ``Issue`` object.
    Returns a plain dict that is JSON-serialisable.
    """
    if verbose:
        print(f"  #{issue.number}: {issue.title[:70]}", flush=True)

    now = datetime.datetime.now(datetime.timezone.utc)

    created_at = issue.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=datetime.timezone.utc)

    updated_at = issue.updated_at
    if updated_at is None:
        updated_at = created_at
    elif updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=datetime.timezone.utc)

    age_days  = (now - created_at).days
    idle_days = (now - updated_at).days

    label_names = [lbl.name for lbl in issue.labels]

    priority  = _parse_priority(label_names)
    areas     = _parse_areas(label_names)
    assignees = [a.login for a in issue.assignees]

    comment_count = issue.comments  # available without extra API call

    milestone = issue.milestone.title if issue.milestone else None

    is_stale             = any(l.lower() == "stale"            for l in label_names)
    has_help_wanted      = any(l.lower() == "help wanted"       for l in label_names)
    has_good_first       = any(l.lower() == "good first issue"  for l in label_names)
    has_release_blocker  = any(l.lower() == "release blocker"   for l in label_names)

    # ---- Issue type (GitHub native issue types, not labels) ----
    issue_type = None
    try:
        raw_type = issue._rawData.get("type") or {}
        issue_type = raw_type.get("name")
    except Exception:
        pass

    # ---- Categorize ----
    categories = []

    # Release blocker first — highest urgency signal
    if has_release_blocker:
        categories.append(CAT_RELEASE_BLOCKER)

    # Priority
    if priority == "high":
        categories.append(CAT_HIGH)
    elif priority == "medium":
        categories.append(CAT_MEDIUM)
    elif priority == "low":
        categories.append(CAT_LOW)
    else:
        categories.append(CAT_NO_PRIORITY)

    if not assignees:
        categories.append(CAT_UNASSIGNED)
    if is_stale:
        categories.append(CAT_STALE)
    if age_days > LONG_OPEN_DAYS:
        categories.append(CAT_LONG_OPEN)
    if comment_count == 0:
        categories.append(CAT_NO_COMMENTS)
    if has_help_wanted:
        categories.append(CAT_HELP_WANTED)
    if has_good_first:
        categories.append(CAT_GOOD_FIRST_ISSUE)
    if priority is None and not areas:
        categories.append(CAT_NEEDS_TRIAGE)

    return {
        "number":        issue.number,
        "title":         issue.title,
        "url":           issue.html_url,
        "author":        issue.user.login if issue.user else "unknown",
        "created_at":    created_at.strftime("%Y-%m-%d"),
        "updated_at":    updated_at.strftime("%Y-%m-%d"),
        "age_days":      age_days,
        "idle_days":     idle_days,
        "labels":        label_names,
        "issue_type":    issue_type,
        "priority":      priority,
        "areas":         areas,
        "assignees":     assignees,
        "comment_count": comment_count,
        "milestone":     milestone,
        "is_stale":      is_stale,
        "has_help_wanted":      has_help_wanted,
        "has_good_first_issue": has_good_first,
        "has_release_blocker":  has_release_blocker,
        "categories":    categories,
    }


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zephyr Bug Tracker Analysis</title>
<style>
  :root {{
    --bg: #f4f6f9; --card: #ffffff; --border: #dde1e7; --text: #2c3e50;
    --muted: #7f8c8d; --link: #2980b9;
    --header-bg: #2c3e50; --header-fg: #ecf0f1;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    sans-serif; background: var(--bg); color: var(--text); font-size: 14px; }}
  header {{ background: var(--header-bg); color: var(--header-fg);
    padding: 18px 32px; }}
  header h1 {{ font-size: 1.5rem; font-weight: 600; }}
  header p {{ margin-top: 4px; opacity: 0.7; font-size: 0.85rem; }}
  main {{ max-width: 1400px; margin: 0 auto; padding: 24px 24px 64px; }}

  /* ---- summary cards ---- */
  .summary-grid {{ display: grid;
    grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: 14px; margin-bottom: 28px; }}
  .card {{ background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
  .card .lbl {{ margin-top: 6px; color: var(--muted); font-size: 0.78rem;
    text-transform: uppercase; letter-spacing: .04em; }}
  .card .delta {{ display:block; margin-top:4px; font-size:0.72rem; font-weight:600; }}
  .delta-good  {{ color: #27ae60; }}
  .delta-bad   {{ color: #e74c3c; }}
  .delta-neutral {{ color: var(--muted); }}

  /* ---- section titles ---- */
  .section-title {{ font-size: 1.1rem; font-weight: 600; margin: 28px 0 12px;
    border-bottom: 2px solid var(--border); padding-bottom: 6px; }}

  /* ---- category cards ---- */
  .cat-grid {{ display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 12px; margin-bottom: 28px; }}
  .cat-card {{ background: var(--card); border-left: 5px solid #ccc;
    border-radius: 6px; padding: 12px 14px; }}
  .cat-card .cat-label {{ font-weight: 600; font-size: 0.9rem; }}
  .cat-card .cat-count {{ font-size: 1.5rem; font-weight: 700; float: right; margin-top: -2px; }}
  .cat-card .cat-desc {{ margin-top: 6px; font-size: 0.78rem; color: var(--muted); clear: both; }}

  /* ---- bar chart ---- */
  .bar-chart {{ background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 18px 20px; margin-bottom: 28px; }}
  .bar-row {{ display: flex; align-items: center; margin-bottom: 8px; gap: 10px; }}
  .bar-name {{ width: 260px; white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis; font-size: 0.82rem; flex-shrink: 0; }}
  .bar-outer {{ flex: 1; background: #ecf0f1; border-radius: 4px; height: 18px; overflow: hidden; }}
  .bar-inner {{ height: 100%; border-radius: 4px; }}
  .bar-val {{ width: 40px; text-align: right; font-size: 0.82rem; font-weight: 600;
    color: var(--muted); flex-shrink: 0; }}

  /* ---- issue table ---- */
  .filters {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px;
    align-items: flex-start; }}
  .filters input {{ border: 1px solid var(--border); border-radius: 4px;
    padding: 5px 10px; font-size: 0.82rem; width: 220px; }}
  .filters select {{ border: 1px solid var(--border); border-radius: 4px;
    padding: 5px 8px; font-size: 0.82rem; }}
  .filters select[multiple] {{ height: auto; min-height: 80px; max-height: 130px; padding: 3px 4px; }}
  .filters label {{ font-size: 0.82rem; color: var(--muted); }}
  .table-scroll {{ overflow-x: auto; margin-bottom: 28px; }}
  table {{ width: 100%; border-collapse: collapse;
    background: var(--card); border-radius: 8px; overflow: hidden;
    border: 1px solid var(--border); font-size: 0.82rem; }}
  thead {{ background: var(--header-bg); color: var(--header-fg); position: sticky; top: 0; z-index: 2; }}
  thead th {{ padding: 10px 12px; text-align: left; font-weight: 500;
    font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em;
    cursor: pointer; white-space: nowrap; user-select: none; }}
  thead th:hover {{ background: #3d5068; }}
  thead th.sort-asc::after  {{ content: " ▲"; }}
  thead th.sort-desc::after {{ content: " ▼"; }}
  tbody tr {{ border-top: 1px solid var(--border); }}
  tbody tr:hover {{ background: #f8f9fc; }}
  td {{ padding: 9px 12px; vertical-align: top; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  a {{ color: var(--link); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* ---- two-row issue table ---- */
  .iss-title-row td {{ padding: 10px 12px 2px; border-top: 2px solid var(--border); }}
  .iss-meta-row  td {{ padding: 2px 12px 8px; border-top: none; background: #fafbfc; }}
  .iss-title-cell {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    max-width: 0; }}
  .iss-num-link   {{ font-weight: 700; color: var(--muted); margin-right: 10px; font-size: 0.82rem; }}
  .iss-title-link {{ font-weight: 500; margin-right: 12px; }}
  .iss-by         {{ font-size: 0.78rem; color: var(--muted); }}

  /* ---- badges ---- */
  .badge {{ display: inline-block; border-radius: 3px; padding: 1px 6px;
    font-size: 0.72rem; font-weight: 600; color: #fff;
    white-space: nowrap; margin: 1px 1px 1px 0; }}
  .prio-critical {{ background: #922b21; }}
  .prio-high     {{ background: #c0392b; }}
  .prio-medium   {{ background: #e67e22; }}
  .prio-low      {{ background: #f0b429; color: #333; }}
  .prio-none     {{ background: #95a5a6; }}
  .age-old {{ color: #c0392b; font-weight: 700; }}
  .age-mid {{ color: #e67e22; font-weight: 600; }}

  /* ---- area chips ---- */
  .area-chip {{ display: inline-block; border-radius: 3px; padding: 1px 5px;
    font-size: 0.70rem; font-weight: 500; margin: 1px 2px 1px 0;
    white-space: nowrap; color: #fff; }}
  .area-list {{ font-size: 0.72rem; color: var(--muted); margin-top: 3px; }}
  details summary {{ cursor: pointer; color: var(--link); font-size: 0.78rem; }}
  details[open] summary {{ margin-bottom: 4px; }}

  /* ---- simple tables ---- */
  .simple-table {{ width: 100%; border-collapse: collapse;
    background: var(--card); border-radius: 8px; overflow: hidden;
    border: 1px solid var(--border); font-size: 0.82rem; margin-bottom: 28px; }}
  .simple-table thead {{ background: var(--header-bg); color: var(--header-fg); }}
  .simple-table thead th {{ padding: 10px 12px; text-align: left; font-weight: 500;
    font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; }}
  .simple-table tbody tr {{ border-top: 1px solid var(--border); }}
  .simple-table tbody tr:hover {{ background: #f8f9fc; }}
  .simple-table td {{ padding: 8px 12px; vertical-align: top; }}
  .simple-table td.num {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .pr-link-list a {{ display: inline-block; margin: 1px 3px 1px 0; }}

  /* ---- trend table ---- */
  .trend-tbl {{ width:100%; border-collapse:collapse; font-size:0.82rem; }}
  .trend-tbl th {{ background:var(--header-bg); color:var(--header-fg);
    padding:6px 10px; text-align:right; white-space:nowrap; }}
  .trend-tbl th:first-child {{ text-align:left; }}
  .trend-tbl td {{ padding:5px 10px; border-bottom:1px solid var(--border);
    text-align:right; white-space:nowrap; }}
  .trend-tbl td:first-child {{ text-align:left; }}
  .trend-tbl tr:nth-child(even) td {{ background:#f9fafb; }}
  .trend-tbl .delta {{ display:inline; font-size:0.70rem; margin-left:3px; }}

  @media(max-width:800px) {{
    .bar-name {{ width: 140px; }}
    .summary-grid {{ grid-template-columns: repeat(2,1fr); }}
  }}
</style>
</head>
<body>
<header>
  <h1>Zephyr Bug Tracker Analysis</h1>
  <p>Repository: <strong>{org}/{repo}</strong> &nbsp;|&nbsp;
     Generated: <strong>{generated}</strong> &nbsp;|&nbsp;
     Open bugs analysed: <strong>{total_bugs}</strong></p>
</header>
<main>

<!-- ======================== SUMMARY CARDS ======================== -->
<div class="section-title">Overview</div>
<div class="summary-grid">
  {summary_cards}
</div>

<!-- ======================== CATEGORY BREAKDOWN ======================== -->
<div class="section-title">Bug Categories</div>
<div class="cat-grid">
  {cat_cards}
</div>

<!-- ======================== PRIORITY DISTRIBUTION ======================== -->
<div class="section-title">Priority Distribution</div>
<div class="bar-chart">
  {priority_chart}
</div>

<!-- ======================== TOP AREAS ======================== -->
<div class="section-title">Top Areas by Bug Count</div>
<p style="font-size:.8rem;color:var(--muted);margin-bottom:8px;">
  Derived from area:, subsys:, arch:, platform:, driver:, and board: labels.</p>
<div class="bar-chart">
  {area_chart}
</div>

<!-- ======================== BUG TABLE ======================== -->
<div class="section-title">Bug Detail Table</div>
<div class="filters">
  <label>Filter:&nbsp;</label>
  <input id="filter-text" type="search" placeholder="Issue #, title, author…"
    oninput="applyFilters()">
  <select id="filter-priority" onchange="applyFilters()">
    <option value="">All priorities</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="none">No priority</option>
  </select>
  <div style="display:flex;flex-direction:column;gap:2px;">
    <label style="font-size:.78rem;color:var(--muted);">Categories
      <span style="font-weight:normal;">(Ctrl/⌘+click, AND logic):</span>
    </label>
    <select id="filter-cat" multiple size="5" onchange="applyFilters()"
      title="AND logic: shows bugs matching ALL selected categories.">
      {cat_options}
    </select>
    <button onclick="document.getElementById('filter-cat').selectedIndex=-1;applyFilters()"
      style="font-size:.72rem;padding:2px 6px;cursor:pointer;border:1px solid var(--border);
             border-radius:3px;background:var(--card);color:var(--muted);">Clear</button>
  </div>
  <select id="filter-assignee" onchange="applyFilters()">
    <option value="">All assignees</option>
    <option value="(unassigned)">(unassigned)</option>
    {assignee_options}
  </select>
  <select id="filter-milestone" onchange="applyFilters()">
    <option value="">All milestones</option>
    {milestone_options}
  </select>
  <span id="row-count" style="font-size:.8rem;color:var(--muted);margin-left:8px;"></span>
</div>
<div class="table-scroll">
<table id="bug-table">
  <thead>
    <tr>
      <th data-col="0" title="Days since issue was opened">Age</th>
      <th data-col="1" title="Days since last update (comment, label, etc.)">Idle</th>
      <th data-col="2">Priority</th>
      <th data-col="3">Areas</th>
      <th data-col="4">Assignee</th>
      <th data-col="5" title="Number of comments">Comments</th>
      <th data-col="6">Milestone</th>
      <th data-col="7">Categories</th>
    </tr>
  </thead>
  <tbody id="bug-tbody">
    {bug_rows}
  </tbody>
</table>
</div>

<!-- ======================== BY ASSIGNEE ======================== -->
<div class="section-title">Bugs by Assignee</div>
<p style="font-size:.8rem;color:var(--muted);margin-bottom:8px;">
  Sorted by total open bugs.  "(unassigned)" = no assignee set.</p>
{assignee_table}

<!-- ======================== TOP REPORTERS ======================== -->
<div class="section-title">Top Bug Reporters</div>
<p style="font-size:.8rem;color:var(--muted);margin-bottom:8px;">
  Accounts that have filed the most open bugs in the current backlog.</p>
{reporter_table}

<!-- ======================== AREA × PRIORITY HEATMAP ======================== -->
<div class="section-title">Area × Priority Heatmap</div>
<p style="font-size:.8rem;color:var(--muted);margin-bottom:8px;">
  Number of open bugs per area (top 20) and priority.  Darker = more bugs.</p>
<div style="overflow-x:auto;margin-bottom:28px;">
  {area_priority_heatmap}
</div>

<!-- ======================== MILESTONE BREAKDOWN ======================== -->
<div class="section-title">Bugs by Milestone</div>
{milestone_table}

<!-- ======================== TREND HISTORY ======================== -->
{trend_section}

<!-- ======================== HISTORY CHART ======================== -->
{history_chart_section}

</main>
<script>
/* ---- raw data ---- */
const BUG_DATA = {bug_json};
const HISTORY_DATA = {history_data_json};

/* ---- sorting ---- */
let sortCol = 0;
let sortDir = -1;

function sortTable(col) {{
  if (sortCol === col) {{ sortDir *= -1; }} else {{ sortCol = col; sortDir = -1; }}
  document.querySelectorAll("thead th").forEach((th, i) => {{
    th.classList.remove("sort-asc","sort-desc");
    if (i === col) th.classList.add(sortDir > 0 ? "sort-asc" : "sort-desc");
  }});
  applyFilters();
}}
document.querySelectorAll("thead th[data-col]").forEach(th => {{
  th.addEventListener("click", () => sortTable(+th.dataset.col));
}});

/* ---- filtering + rendering ---- */
function applyFilters() {{
  const txt      = document.getElementById("filter-text").value.toLowerCase();
  const prio     = document.getElementById("filter-priority").value;
  const selCats  = Array.from(
    document.getElementById("filter-cat").selectedOptions
  ).map(o => o.value).filter(Boolean);
  const assignee  = document.getElementById("filter-assignee").value;
  const milestone = document.getElementById("filter-milestone").value;

  let rows = BUG_DATA.filter(b => {{
    if (txt && !(
      String(b.number).includes(txt) ||
      b.title.toLowerCase().includes(txt) ||
      b.author.toLowerCase().includes(txt)
    )) return false;
    if (prio) {{
      if (prio === "none" && b.priority !== null) return false;
      if (prio !== "none" && b.priority !== prio) return false;
    }}
    if (selCats.length > 0 && !selCats.every(c => b.categories.includes(c))) return false;
    if (assignee) {{
      if (assignee === "(unassigned)") {{
        if (b.assignees.length > 0) return false;
      }} else {{
        if (!b.assignees.includes(assignee)) return false;
      }}
    }}
    if (milestone) {{
      if (milestone === "(none)" && b.milestone !== null) return false;
      if (milestone !== "(none)" && b.milestone !== milestone) return false;
    }}
    return true;
  }});

  const keys = ["age_days","idle_days","priority","areas","assignees",
    "comment_count","milestone","categories"];
  rows.sort((a,b) => {{
    let av = a[keys[sortCol]], bv = b[keys[sortCol]];
    if (Array.isArray(av)) av = av.length;
    if (Array.isArray(bv)) bv = bv.length;
    if (keys[sortCol] === "priority") {{
      const po = {{high:0,medium:1,low:2,null:3}};
      av = po[av] ?? 3; bv = po[bv] ?? 3;
    }}
    if (typeof av === "string") return sortDir * av.localeCompare(bv);
    return sortDir * ((av ?? 999) - (bv ?? 999));
  }});

  document.getElementById("row-count").textContent = rows.length + " bugs";
  document.getElementById("bug-tbody").innerHTML = rows.map(rowHtml).join("");
}}

const CAT_COLORS = {cat_colors_json};
const CAT_LABELS = {cat_labels_json};

function prioClass(p) {{
  return {{high:"prio-high",medium:"prio-medium",low:"prio-low"}}[p] || "prio-none";
}}
function ageClass(d) {{
  return d > 365 ? "age-old" : d > 180 ? "age-mid" : "";
}}
function strHue(s) {{
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return ((h >>> 0) % 360);
}}
function areaColor(name) {{ return `hsl(${{strHue(name)}},42%,38%)`; }}
function areaChip(name) {{
  return `<span class="area-chip" style="background:${{areaColor(name)}}"
    title="${{escHtml(name)}}">${{escHtml(name)}}</span>`;
}}
function escHtml(s) {{
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}}

function rowHtml(b) {{
  const cats = b.categories.map(c =>
    `<span class="badge" style="background:${{CAT_COLORS[c]||'#95a5a6'}}">${{
      escHtml(CAT_LABELS[c]||c)}}</span>`).join(" ");
  const assignee = b.assignees.length
    ? escHtml(b.assignees.join(", "))
    : '<span style="color:#c0392b">none</span>';
  const areas = b.areas.length
    ? `<details><summary>${{b.areas.length}} area(s)</summary>
       <div class="area-list">${{b.areas.map(areaChip).join("")}}</div></details>`
    : '<span style="color:var(--muted)">—</span>';
  const prioLabel = b.priority
    ? `<span class="badge ${{prioClass(b.priority)}}">${{escHtml(b.priority)}}</span>`
    : '<span class="badge prio-none">none</span>';
  const ageC  = ageClass(b.age_days);
  const idleC = ageClass(b.idle_days);
  const ms = b.milestone ? escHtml(b.milestone) : '<span style="color:var(--muted)">—</span>';
  const da = `data-cats="${{b.categories.join(" ")}}"`;
  return (
    `<tr class="iss-title-row" ${{da}}>` +
    `<td class="iss-title-cell" colspan="8">` +
    `<a class="iss-num-link" href="${{b.url}}" target="_blank">#${{b.number}}</a>` +
    `<a class="iss-title-link" href="${{b.url}}" target="_blank">${{escHtml(b.title)}}</a>` +
    `<span class="iss-by">by ${{escHtml(b.author)}}</span>` +
    `</td></tr>` +
    `<tr class="iss-meta-row" ${{da}}>` +
    `<td class="num ${{ageC}}">${{b.age_days}}d</td>` +
    `<td class="num ${{idleC}}" title="Last update: ${{b.updated_at}}">${{b.idle_days}}d</td>` +
    `<td>${{prioLabel}}</td>` +
    `<td>${{areas}}</td>` +
    `<td>${{assignee}}</td>` +
    `<td class="num">${{b.comment_count}}</td>` +
    `<td>${{ms}}</td>` +
    `<td style="min-width:180px">${{cats}}</td>` +
    `</tr>`
  );
}}

applyFilters();
document.querySelectorAll("thead th[data-col]").forEach((th, i) => {{
  if (i === 0) th.classList.add("sort-desc");
}});

{history_chart_js}
</script>
</body>
</html>
"""


def _summary_card(num, label, color="var(--text)", delta_html=""):
    return (
        f'<div class="card">'
        f'<div class="num" style="color:{color}">{num}</div>'
        f'<div class="lbl">{html.escape(label)}</div>'
        f'{delta_html}'
        f'</div>'
    )


def _delta_html(current, prev, lower_is_better=True):
    if prev is None:
        return ""
    try:
        diff = current - prev
    except TypeError:
        return ""
    if diff == 0:
        return '<span class="delta delta-neutral">—</span>'
    improving = (diff < 0) == lower_is_better
    cls   = "delta-good" if improving else "delta-bad"
    arrow = "▼" if diff < 0 else "▲"
    label = f"{diff:+.1f}" if isinstance(current, float) else f"{diff:+d}"
    return f'<span class="delta {cls}">{arrow} {label}</span>'


def _bar_chart_rows(counts, max_val, color_fn=None, default_color="#3498db"):
    rows = []
    for name, val in counts:
        pct   = (val / max_val * 100) if max_val else 0
        color = color_fn(name) if color_fn else default_color
        rows.append(
            f'<div class="bar-row">'
            f'<div class="bar-name" title="{html.escape(name)}">{html.escape(name)}</div>'
            f'<div class="bar-outer">'
            f'<div class="bar-inner" style="width:{pct:.1f}%;background:{color}"></div>'
            f'</div>'
            f'<div class="bar-val">{val}</div>'
            f'</div>'
        )
    return "\n".join(rows)


def _area_color(name):
    h = 0
    for ch in name:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    return f"hsl({h % 360},42%,38%)"


def _area_chip_html(name):
    escaped = html.escape(name)
    color   = _area_color(name)
    return (
        f'<span class="area-chip" style="background:{color}" '
        f'title="{escaped}">{escaped}</span>'
    )


def _issue_row_html(issue):
    """Render an issue as two <tr> rows: title + metrics."""
    cats_html = " ".join(
        f'<span class="badge" style="background:{CATEGORY_META[c]["color"]}">'
        f'{html.escape(CATEGORY_META[c]["label"])}</span>'
        for c in issue["categories"]
    )
    assignee_html = (
        html.escape(", ".join(issue["assignees"]))
        if issue["assignees"]
        else '<span style="color:#c0392b">none</span>'
    )
    if issue["areas"]:
        area_html = (
            f'<details><summary>{len(issue["areas"])} area(s)</summary>'
            f'<div class="area-list">'
            + "".join(_area_chip_html(a) for a in issue["areas"])
            + "</div></details>"
        )
    else:
        area_html = '<span style="color:var(--muted)">—</span>'

    prio = issue["priority"]
    prio_class = {
        "high": "prio-high", "medium": "prio-medium", "low": "prio-low",
    }.get(prio, "prio-none")
    prio_label = prio if prio else "none"
    prio_html  = f'<span class="badge {prio_class}">{html.escape(prio_label)}</span>'

    age_cls  = "age-old" if issue["age_days"]  > 365 else \
               "age-mid" if issue["age_days"]  > 180 else ""
    idle_cls = "age-old" if issue["idle_days"] > 365 else \
               "age-mid" if issue["idle_days"] > 180 else ""

    ms_html = html.escape(issue["milestone"]) if issue["milestone"] \
        else '<span style="color:var(--muted)">—</span>'

    data_attrs = f'data-cats="{html.escape(" ".join(issue["categories"]))}"'

    return (
        f'<tr class="iss-title-row" {data_attrs}>'
        f'<td class="iss-title-cell" colspan="8">'
        f'<a class="iss-num-link" href="{issue["url"]}" target="_blank">#{issue["number"]}</a>'
        f'<a class="iss-title-link" href="{issue["url"]}" target="_blank">'
        f'{html.escape(issue["title"])}</a>'
        f'<span class="iss-by">by {html.escape(issue["author"])}</span>'
        f'</td></tr>'
        f'<tr class="iss-meta-row" {data_attrs}>'
        f'<td class="num {age_cls}">{issue["age_days"]}d</td>'
        f'<td class="num {idle_cls}" title="Last update: {issue["updated_at"]}">'
        f'{issue["idle_days"]}d</td>'
        f'<td>{prio_html}</td>'
        f'<td>{area_html}</td>'
        f'<td>{assignee_html}</td>'
        f'<td class="num">{issue["comment_count"]}</td>'
        f'<td>{ms_html}</td>'
        f'<td style="min-width:180px">{cats_html}</td>'
        f'</tr>'
    )


def _assignee_table_html(sorted_assignees):
    if not sorted_assignees:
        return '<p style="color:var(--muted);font-size:.82rem">No data.</p>'
    rows = []
    for login, d in sorted_assignees[:30]:
        issue_links = " ".join(
            f'<a href="{url}" target="_blank" title="{html.escape(title[:80])}">'
            f'#{num}</a>'
            for num, url, title in d["issues"]
        )
        rows.append(
            f'<tr>'
            f'<td><strong>{html.escape(login)}</strong></td>'
            f'<td class="num">{d["total"]}</td>'
            f'<td class="num">{d["release_blocker"] or "—"}</td>'
            f'<td class="num">{d["high"] or "—"}</td>'
            f'<td class="num">{d["no_priority"] or "—"}</td>'
            f'<td class="num">{d["stale"] or "—"}</td>'
            f'<td class="num">{d["long_open"] or "—"}</td>'
            f'<td class="pr-link-list">{issue_links}</td>'
            f'</tr>'
        )
    return (
        '<table class="simple-table"><thead><tr>'
        '<th>Assignee</th>'
        '<th title="Total open bugs assigned"># Bugs</th>'
        '<th title="Bugs carrying the Release Blocker label">Rel. Blocker</th>'
        '<th title="High priority bugs">High</th>'
        '<th title="Bugs with no priority label">No Priority</th>'
        '<th title="Bugs carrying the Stale label">Stale</th>'
        '<th title="Bugs open more than 365 days">Long Open</th>'
        '<th>Issues</th>'
        '</tr></thead>'
        '<tbody>' + "\n".join(rows) + '</tbody></table>'
    )


def _reporter_table_html(sorted_reporters):
    if not sorted_reporters:
        return '<p style="color:var(--muted);font-size:.82rem">No data.</p>'
    rows = []
    for login, d in sorted_reporters[:30]:
        rows.append(
            f'<tr>'
            f'<td><a href="https://github.com/{html.escape(login)}" target="_blank">'
            f'{html.escape(login)}</a></td>'
            f'<td class="num">{d["total"]}</td>'
            f'<td class="num">{d["release_blocker"] or "—"}</td>'
            f'<td class="num">{d["high"] or "—"}</td>'
            f'<td class="num">{d["unassigned"] or "—"}</td>'
            f'<td class="num">{d["avg_age"]:.0f}d</td>'
            f'</tr>'
        )
    return (
        '<table class="simple-table"><thead><tr>'
        '<th>Reporter</th>'
        '<th title="Open bugs filed by this account"># Bugs filed</th>'
        '<th title="Bugs with the Release Blocker label">Rel. Blocker</th>'
        '<th>High</th>'
        '<th title="Filed bugs with no assignee">Unassigned</th>'
        '<th title="Average age of their open bugs">Avg age</th>'
        '</tr></thead>'
        '<tbody>' + "\n".join(rows) + '</tbody></table>'
    )


def _milestone_table_html(sorted_milestones):
    if not sorted_milestones:
        return '<p style="color:var(--muted);font-size:.82rem">No milestone data.</p>'
    rows = []
    for ms_title, d in sorted_milestones[:20]:
        rows.append(
            f'<tr>'
            f'<td><strong>{html.escape(ms_title)}</strong></td>'
            f'<td class="num">{d["total"]}</td>'
            f'<td class="num">{d["release_blocker"] or "—"}</td>'
            f'<td class="num">{d["high"] or "—"}</td>'
            f'<td class="num">{d["unassigned"] or "—"}</td>'
            f'</tr>'
        )
    return (
        '<table class="simple-table"><thead><tr>'
        '<th>Milestone</th>'
        '<th># Bugs</th><th>Rel. Blocker</th><th>High</th><th>Unassigned</th>'
        '</tr></thead>'
        '<tbody>' + "\n".join(rows) + '</tbody></table>'
    )


def _area_priority_heatmap_html(issues, top_n=20):
    """Build an area × priority heatmap table."""
    area_counter = collections.Counter()
    for iss in issues:
        for a in iss["areas"]:
            area_counter[a] += 1
    top_areas = [a for a, _ in area_counter.most_common(top_n)]
    if not top_areas:
        return '<p style="color:var(--muted);font-size:.82rem">No area label data.</p>'

    priorities = ["high", "medium", "low", None]
    prio_labels = {
        "high": "High", "medium": "Medium", "low": "Low", None: "None",
    }
    # count[area][prio]
    count = {a: collections.Counter() for a in top_areas}
    for iss in issues:
        p = iss["priority"]
        for a in iss["areas"]:
            if a in count:
                count[a][p] += 1

    max_val = max(
        (count[a][p] for a in top_areas for p in priorities),
        default=1
    )

    def hm_class(v):
        if v == 0:   return "hm0"
        if v <= max_val * 0.25: return "hm1"
        if v <= max_val * 0.5:  return "hm2"
        if v <= max_val * 0.75: return "hm3"
        return "hm4"

    # Inline heatmap CSS (can't reuse existing .heatmap-wrapper since that's
    # from pr_backlog; just inline enough styles here)
    style = (
        '<style>'
        '.bh td,.bh th{padding:4px 8px;text-align:right;font-size:.78rem;}'
        '.bh th:first-child{text-align:left;white-space:nowrap;max-width:200px;'
        'overflow:hidden;text-overflow:ellipsis;}'
        '.bh .hm0{background:#f7f7f7}.bh .hm1{background:#c6e0f5}'
        '.bh .hm2{background:#7ab8e8}.bh .hm3{background:#2e86de;color:#fff}'
        '.bh .hm4{background:#1a5276;color:#fff}'
        '</style>'
    )
    header = "".join(
        f'<th>{html.escape(prio_labels[p])}</th>' for p in priorities
    )
    rows_html = []
    for a in top_areas:
        cells = "".join(
            f'<td class="{hm_class(count[a][p])}">'
            f'{"" if count[a][p] == 0 else count[a][p]}</td>'
            for p in priorities
        )
        rows_html.append(
            f'<tr><th title="{html.escape(a)}">{html.escape(a)}</th>{cells}</tr>'
        )
    return (
        style +
        '<table class="simple-table bh" style="margin-bottom:0;">'
        f'<thead><tr><th>Area</th>{header}</tr></thead>'
        '<tbody>' + "\n".join(rows_html) + '</tbody>'
        '</table>'
    )


def _trend_table_html(history):
    if len(history) < 2:
        return (
            '<p style="color:var(--muted);font-size:.85rem;margin-top:8px;">'
            'Trend data will appear here after two or more runs.</p>'
        )
    cols = [
        ("Date",           "generated",          None),
        ("Total",          "total",              True),
        ("Avg Age (d)",    "avg_age",            True),
        ("Avg Idle (d)",   "avg_idle",           True),
        ("Rel. Blocker",   "num_release_blocker",True),
        ("High",           "num_high",           True),
        ("No Priority",    "no_priority",        True),
        ("Unassigned",     "unassigned",         True),
        ("Stale",          "num_stale",          True),
        ("Long Open",      "long_open",          True),
        ("No Comments",    "no_comments",        True),
        ("Needs Triage",   "needs_triage",       True),
    ]
    header = "".join(f"<th>{c[0]}</th>" for c in cols)
    rows = []
    for i in range(len(history) - 1, -1, -1):
        snap = history[i]
        prev = history[i - 1] if i > 0 else None
        cells = []
        for (_, key, lib) in cols:
            val = snap.get(key, "")
            if lib is None:
                cells.append(f"<td>{html.escape(str(val))}</td>")
            else:
                dh = _delta_html(val, prev.get(key) if prev else None,
                                 lower_is_better=lib)
                if isinstance(val, float):
                    cells.append(f"<td>{val:.1f}{dh}</td>")
                else:
                    cells.append(f"<td>{val}{dh}</td>")
        rows.append(f"<tr>{''.join(cells)}</tr>")
    return (
        '<div style="overflow-x:auto">'
        '<table class="trend-tbl">'
        f'<thead><tr>{header}</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table></div>'
    )


def _history_chart_section_html():
    metrics = [
        ("total",               "Total Bugs",     "#2c3e50"),
        ("num_release_blocker", "Release Blocker", "#641e16"),
        ("num_high",            "High",            "#c0392b"),
        ("num_medium",          "Medium",          "#e67e22"),
        ("num_low",             "Low",             "#f0b429"),
        ("no_priority",         "No Priority",     "#95a5a6"),
        ("unassigned",          "Unassigned",      "#e74c3c"),
        ("num_stale",           "Stale",           "#bdc3c7"),
        ("long_open",           "Long Open",       "#8e44ad"),
        ("no_comments",         "No Comments",     "#7f8c8d"),
        ("needs_triage",        "Needs Triage",    "#f39c12"),
    ]
    checkboxes = "\n".join(
        f'<label style="margin-right:12px;font-size:.8rem;cursor:pointer;">'
        f'<input type="checkbox" checked data-metric="{key}" '
        f'onchange="toggleHistorySeries(this)" '
        f'style="accent-color:{color};margin-right:3px;">'
        f'<span style="color:{color}">{label}</span></label>'
        for key, label, color in metrics
    )
    return (
        '<div class="section-title">Bug Metrics Over Time</div>\n'
        '<p style="font-size:.8rem;color:var(--muted);margin-bottom:8px;">'
        'Requires --history data.  Toggle series with the checkboxes below.</p>\n'
        '<div style="margin-bottom:8px;line-height:2;">' + checkboxes + '</div>\n'
        '<div style="position:relative;height:380px;">'
        '<canvas id="history-chart"></canvas></div>\n'
        '<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js">'
        '</script>\n'
    )


def _history_chart_js():
    metrics = [
        ("total",               "Total Bugs",     "#2c3e50"),
        ("num_release_blocker", "Release Blocker", "#641e16"),
        ("num_high",            "High",            "#c0392b"),
        ("num_medium",          "Medium",          "#e67e22"),
        ("num_low",             "Low",             "#f0b429"),
        ("no_priority",         "No Priority",     "#95a5a6"),
        ("unassigned",          "Unassigned",      "#e74c3c"),
        ("num_stale",           "Stale",           "#bdc3c7"),
        ("long_open",           "Long Open",       "#8e44ad"),
        ("no_comments",         "No Comments",     "#7f8c8d"),
        ("needs_triage",        "Needs Triage",    "#f39c12"),
    ]
    datasets_js = json.dumps([
        {"key": key, "label": label, "color": color}
        for key, label, color in metrics
    ])
    return (
        '/* ---- history chart ---- */\n'
        'if (HISTORY_DATA.length >= 2 && document.getElementById("history-chart")) {\n'
        '  (function() {\n'
        '    const METRICS = ' + datasets_js + ';\n'
        '    const runs = HISTORY_DATA;\n'
        '    const labels = runs.map(r => (r.generated || r.timestamp || "").slice(0,10));\n'
        '    const datasets = METRICS.map(m => ({\n'
        '      label: m.label,\n'
        '      data: runs.map(r => r[m.key] != null ? r[m.key] : null),\n'
        '      borderColor: m.color,\n'
        '      backgroundColor: m.color + "33",\n'
        '      tension: 0.3, pointRadius: 3, borderWidth: 2,\n'
        '    }));\n'
        '    const ctx = document.getElementById("history-chart").getContext("2d");\n'
        '    window._histChart = new Chart(ctx, {\n'
        '      type: "line",\n'
        '      data: { labels: labels, datasets: datasets },\n'
        '      options: {\n'
        '        responsive: true, maintainAspectRatio: false,\n'
        '        interaction: { mode: "index", intersect: false },\n'
        '        plugins: { legend: { position: "bottom", '
        'labels: { boxWidth: 12, font: { size: 11 } } } },\n'
        '        scales: {\n'
        '          x: { ticks: { maxRotation: 45, font: { size: 10 } } },\n'
        '          y: { beginAtZero: true },\n'
        '        },\n'
        '      },\n'
        '    });\n'
        '  })();\n'
        '}\n'
        'function toggleHistorySeries(cb) {\n'
        '  const chart = window._histChart;\n'
        '  if (!chart) return;\n'
        '  const label = cb.closest("label").querySelector("span").textContent;\n'
        '  const idx = chart.data.datasets.findIndex(d => d.label === label);\n'
        '  if (idx === -1) return;\n'
        '  chart.setDatasetVisibility(idx, cb.checked);\n'
        '  chart.update();\n'
        '}\n'
    )


# ---------------------------------------------------------------------------
# Main render function
# ---------------------------------------------------------------------------

def render_html(org, repo, issues, generated, history=None):
    """
    Render the full HTML bug dashboard.

    Returns ``(html_string, snapshot)`` where *snapshot* is a dict of
    summary stats for this run (to be persisted to the history file).
    """
    if history is None:
        history = []
    total = len(issues)

    # ---- Category counts ----
    cat_counts = collections.Counter()
    for iss in issues:
        for c in iss["categories"]:
            cat_counts[c] += 1

    # ---- Summary stats ----
    avg_age  = sum(i["age_days"]  for i in issues) / total if total else 0.0
    avg_idle = sum(i["idle_days"] for i in issues) / total if total else 0.0

    num_release_blocker = cat_counts[CAT_RELEASE_BLOCKER]
    num_high      = cat_counts[CAT_HIGH]
    num_medium    = cat_counts[CAT_MEDIUM]
    num_low       = cat_counts[CAT_LOW]
    no_priority   = cat_counts[CAT_NO_PRIORITY]
    unassigned    = cat_counts[CAT_UNASSIGNED]
    num_stale     = cat_counts[CAT_STALE]
    long_open     = cat_counts[CAT_LONG_OPEN]
    no_comments   = cat_counts[CAT_NO_COMMENTS]
    help_wanted   = cat_counts[CAT_HELP_WANTED]
    good_first    = cat_counts[CAT_GOOD_FIRST_ISSUE]
    needs_triage  = cat_counts[CAT_NEEDS_TRIAGE]

    snapshot = {
        "timestamp":            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "generated":            generated,
        "total":                total,
        "avg_age":              round(avg_age,  1),
        "avg_idle":             round(avg_idle, 1),
        "num_release_blocker":  num_release_blocker,
        "num_high":             num_high,
        "num_medium":           num_medium,
        "num_low":              num_low,
        "no_priority":          no_priority,
        "unassigned":           unassigned,
        "num_stale":            num_stale,
        "long_open":            long_open,
        "no_comments":          no_comments,
        "help_wanted":          help_wanted,
        "good_first":           good_first,
        "needs_triage":         needs_triage,
    }

    prev = history[-1] if history else None

    def _d(cur, key, lib=True):
        return _delta_html(cur, prev.get(key) if prev else None,
                           lower_is_better=lib)

    # ---- Summary cards ----
    cards = [
        _summary_card(total,              "Open Bugs",        "#2c3e50", _d(total,              "total")),
        _summary_card(f"{avg_age:.0f}d",  "Avg Age",          "#e67e22", _d(avg_age,            "avg_age")),
        _summary_card(f"{avg_idle:.0f}d", "Avg Idle",         "#e67e22", _d(avg_idle,           "avg_idle")),
        _summary_card(num_release_blocker,"Release Blocker",  "#641e16", _d(num_release_blocker,"num_release_blocker")),
        _summary_card(num_high,           "High",             "#c0392b", _d(num_high,           "num_high")),
        _summary_card(num_medium,         "Medium",           "#e67e22", _d(num_medium,         "num_medium")),
        _summary_card(num_low,            "Low",              "#f0b429", _d(num_low,            "num_low")),
        _summary_card(no_priority,        "No Priority",      "#95a5a6", _d(no_priority,        "no_priority")),
        _summary_card(unassigned,         "Unassigned",       "#e74c3c", _d(unassigned,         "unassigned")),
        _summary_card(num_stale,          "Stale",            "#bdc3c7", _d(num_stale,          "num_stale")),
        _summary_card(long_open,          "Open > 1 Year",    "#8e44ad", _d(long_open,          "long_open")),
        _summary_card(no_comments,        "No Comments",      "#7f8c8d", _d(no_comments,        "no_comments")),
        _summary_card(needs_triage,       "Needs Triage",     "#f39c12", _d(needs_triage,       "needs_triage")),
        _summary_card(help_wanted,        "Help Wanted",      "#27ae60", _d(help_wanted,        "help_wanted", lib=False)),
        _summary_card(good_first,         "Good First Issue", "#1abc9c", _d(good_first,         "good_first",  lib=False)),
    ]

    # ---- Category cards ----
    cat_cards_html = []
    for key, meta in CATEGORY_META.items():
        cnt = cat_counts.get(key, 0)
        cat_cards_html.append(
            f'<div class="cat-card" style="border-left-color:{meta["color"]}">'
            f'<span class="cat-count" style="color:{meta["color"]}">{cnt}</span>'
            f'<div class="cat-label">{html.escape(meta["label"])}</div>'
            f'<div class="cat-desc">{html.escape(meta["description"])}</div>'
            f'</div>'
        )

    # ---- Priority chart ----
    prio_colors = {
        "high": "#c0392b", "medium": "#e67e22",
        "low":  "#f0b429", "No Priority": "#95a5a6",
    }
    prio_counts = [
        ("high",        num_high),
        ("medium",      num_medium),
        ("low",         num_low),
        ("No Priority", no_priority),
    ]
    max_prio = max(v for _, v in prio_counts) if prio_counts else 1
    priority_chart_html = _bar_chart_rows(
        prio_counts, max_prio,
        color_fn=lambda name: prio_colors.get(name, "#3498db"),
    )

    # ---- Area chart ----
    area_counter = collections.Counter()
    for iss in issues:
        for a in iss["areas"]:
            area_counter[a] += 1
    top_areas = area_counter.most_common(20)
    max_area  = top_areas[0][1] if top_areas else 1
    area_chart_html = _bar_chart_rows(
        top_areas, max_area, color_fn=_area_color
    )

    # ---- Category filter options ----
    cat_option_html = "\n".join(
        f'<option value="{k}">{html.escape(CATEGORY_META[k]["label"])}</option>'
        for k in CATEGORY_META
    )

    # ---- Assignee table ----
    assignee_data = collections.defaultdict(lambda: {
        "total": 0, "release_blocker": 0, "high": 0,
        "no_priority": 0, "stale": 0, "long_open": 0, "issues": [],
    })
    for iss in issues:
        buckets = iss["assignees"] if iss["assignees"] else ["(unassigned)"]
        for a in buckets:
            d = assignee_data[a]
            d["total"] += 1
            if iss.get("has_release_blocker"): d["release_blocker"] += 1
            if iss["priority"] == "high":      d["high"]            += 1
            if iss["priority"] is None:        d["no_priority"]     += 1
            if iss["is_stale"]:                d["stale"]           += 1
            if iss["age_days"] > LONG_OPEN_DAYS: d["long_open"]     += 1
            d["issues"].append((iss["number"], iss["url"], iss["title"]))
    sorted_assignees = sorted(
        assignee_data.items(), key=lambda x: x[1]["total"], reverse=True
    )
    assignee_table_html = _assignee_table_html(sorted_assignees)
    assignee_options_html = "\n".join(
        f'<option value="{html.escape(a)}">{html.escape(a)}</option>'
        for a, _ in sorted_assignees
        if a != "(unassigned)"
    )

    # ---- Reporter table ----
    reporter_data = collections.defaultdict(lambda: {
        "total": 0, "release_blocker": 0, "high": 0,
        "unassigned": 0, "total_age": 0,
    })
    for iss in issues:
        author = iss["author"]
        d = reporter_data[author]
        d["total"]    += 1
        d["total_age"] += iss["age_days"]
        if iss.get("has_release_blocker"): d["release_blocker"] += 1
        if iss["priority"] == "high":      d["high"]            += 1
        if not iss["assignees"]:           d["unassigned"]      += 1
    for d in reporter_data.values():
        d["avg_age"] = d["total_age"] / d["total"] if d["total"] else 0
    sorted_reporters = sorted(
        reporter_data.items(), key=lambda x: x[1]["total"], reverse=True
    )
    reporter_table_html = _reporter_table_html(sorted_reporters)

    # ---- Milestone table ----
    ms_data = collections.defaultdict(lambda: {
        "total": 0, "release_blocker": 0, "high": 0, "unassigned": 0,
    })
    for iss in issues:
        ms = iss["milestone"] or "(no milestone)"
        d  = ms_data[ms]
        d["total"] += 1
        if iss.get("has_release_blocker"): d["release_blocker"] += 1
        if iss["priority"] == "high":      d["high"]            += 1
        if not iss["assignees"]:           d["unassigned"]      += 1
    sorted_ms = sorted(
        ms_data.items(), key=lambda x: x[1]["total"], reverse=True
    )
    milestone_table_html = _milestone_table_html(sorted_ms)

    # ---- Milestone filter options ----
    milestone_options_html = "\n".join(
        f'<option value="{html.escape(ms)}">{html.escape(ms)}</option>'
        for ms, _ in sorted_ms
    )

    # ---- Area × priority heatmap ----
    heatmap_html = _area_priority_heatmap_html(issues)

    # ---- Issue rows (sorted by age desc) ----
    sorted_issues = sorted(issues, key=lambda i: i["age_days"], reverse=True)
    bug_rows_html = "\n".join(_issue_row_html(i) for i in sorted_issues)

    # ---- JSON for client-side filtering ----
    bug_json = json.dumps(
        [{
            "number":        i["number"],
            "title":         i["title"],
            "url":           i["url"],
            "author":        i["author"],
            "age_days":      i["age_days"],
            "idle_days":     i["idle_days"],
            "updated_at":    i["updated_at"],
            "priority":      i["priority"],
            "areas":         i["areas"],
            "assignees":     i["assignees"],
            "comment_count": i["comment_count"],
            "milestone":     i["milestone"],
            "categories":    i["categories"],
            "is_stale":      i["is_stale"],
        }
        for i in issues],
        indent=None,
    )

    cat_colors_json = json.dumps({k: v["color"] for k, v in CATEGORY_META.items()})
    cat_labels_json = json.dumps({k: v["label"] for k, v in CATEGORY_META.items()})

    # ---- Trend ----
    all_runs = list(history) + [snapshot]
    if len(all_runs) >= 2:
        trend_section = (
            '<div class="section-title">Bug Backlog Trend History</div>\n'
            '<p style="font-size:.8rem;color:var(--muted);margin-bottom:8px;">'
            'Each row is one saved run.  Arrows show change vs. the previous run; '
            'green = improving, red = worsening.</p>\n'
            + _trend_table_html(all_runs)
        )
    else:
        trend_section = ""

    history_data_json = json.dumps(all_runs, ensure_ascii=False, default=str)
    if len(all_runs) >= 2:
        history_chart_section = _history_chart_section_html()
        history_chart_js      = _history_chart_js()
    else:
        history_chart_section = ""
        history_chart_js      = ""

    report = _HTML_TEMPLATE.format(
        org=html.escape(org),
        repo=html.escape(repo),
        generated=html.escape(generated),
        total_bugs=total,
        summary_cards="\n".join(cards),
        cat_cards="\n".join(cat_cards_html),
        priority_chart=priority_chart_html,
        area_chart=area_chart_html,
        cat_options=cat_option_html,
        assignee_options=assignee_options_html,
        milestone_options=milestone_options_html,
        bug_rows=bug_rows_html,
        assignee_table=assignee_table_html,
        reporter_table=reporter_table_html,
        milestone_table=milestone_table_html,
        area_priority_heatmap=heatmap_html,
        trend_section=trend_section,
        history_chart_section=history_chart_section,
        history_chart_js=history_chart_js,
        history_data_json=history_data_json,
        bug_json=bug_json,
        cat_colors_json=cat_colors_json,
        cat_labels_json=cat_labels_json,
    )
    return report, snapshot


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _load_cache(path):
    """Load per-issue analysis cache.  Returns {} on any error."""
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARNING: Could not read cache {path}: {exc}; starting fresh.",
              file=sys.stderr)
        return {}


def _save_cache(path, cache):
    """Write cache atomically via a temp file."""
    p   = pathlib.Path(path)
    tmp = p.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(cache, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        tmp.replace(p)
    except Exception as exc:
        print(f"WARNING: Could not write cache {path}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# History helpers
# ---------------------------------------------------------------------------

def _load_history(path):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARNING: Could not load history {path}: {exc}", file=sys.stderr)
        return []


def _save_snapshot(path, snapshot, history):
    updated = list(history) + [snapshot]
    try:
        pathlib.Path(path).write_text(
            json.dumps(updated, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"WARNING: Could not write history {path}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--org", default="zephyrproject-rtos",
        help="GitHub organisation (default: zephyrproject-rtos).",
    )
    parser.add_argument(
        "--repo", default="zephyr",
        help="GitHub repository name (default: zephyr).",
    )
    parser.add_argument(
        "--max-issues", type=int, default=5000, metavar="N",
        help="Maximum number of issues to analyse (default: 5000).",
    )
    parser.add_argument(
        "--output", default="bugs.html", metavar="FILE",
        help="Output HTML file (default: bugs.html).",
    )
    parser.add_argument(
        "--token", default=os.environ.get("GITHUB_TOKEN"), metavar="TOKEN",
        help="GitHub personal access token (default: $GITHUB_TOKEN).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Print progress to stdout.",
    )
    parser.add_argument(
        "--history", default=None, metavar="FILE",
        help=(
            "Path to a JSON file used to persist run history.  "
            "If the file exists, previous snapshots are loaded and the "
            "report shows trend indicators comparing this run to the last "
            "saved run.  The current run is appended after rendering."
        ),
    )
    parser.add_argument(
        "--cache", default=None, metavar="FILE",
        help=(
            "Path to a JSON file used to cache per-issue analysis results.  "
            "Issues whose updated_at timestamp is unchanged since the last "
            "run are loaded from the cache instead of making fresh API calls.  "
            "Example: --cache bugs_cache.json"
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.token:
        print(
            "WARNING: No GitHub token found.  "
            "Set GITHUB_TOKEN or pass --token to avoid rate limiting.",
            file=sys.stderr,
        )

    if args.verbose:
        print(f"Connecting to GitHub ({args.org}/{args.repo})…", flush=True)

    gh      = _gh_connect(args.token)
    gh_repo = gh.get_repo(f"{args.org}/{args.repo}")

    # ---- Load cache ----
    issue_cache = {}
    if args.cache:
        issue_cache = _load_cache(args.cache)
        if args.verbose and issue_cache:
            print(f"Loaded {len(issue_cache)} cached issue entries from {args.cache}",
                  flush=True)

    # ---- Fetch open Bug-type issues via the search API ----
    # GitHub issue types are first-class objects (not labels); using the
    # search qualifier `type:Bug` is the correct way to filter them.
    # The search API returns full Issue objects just like get_issues().
    search_query = (
        f"repo:{args.org}/{args.repo} is:issue is:open type:Bug"
    )
    if args.verbose:
        print(f"Fetching open issues with type:Bug (query: {search_query})…",
              flush=True)

    issues_list = []
    fetched     = 0

    for issue in gh.search_issues(search_query, sort="created", order="asc"):
        if fetched >= args.max_issues:
            if args.verbose:
                print(f"Reached --max-issues={args.max_issues} limit.", flush=True)
            break

        cache_key  = str(issue.number)
        updated_at = issue.updated_at
        if updated_at is not None and updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=datetime.timezone.utc)
        updated_iso = updated_at.isoformat() if updated_at is not None else ""

        cached = issue_cache.get(cache_key) if args.cache else None
        if cached is not None and cached.get("updated_at") == updated_iso:
            if args.verbose:
                print(f"  #{issue.number}: cache hit", flush=True)
            data = cached["data"]
            # Backfill any categories that might have been added after
            # this entry was first cached (e.g. a new category key).
            # Re-derive categories from the stored fields.
            _backfill_categories(data)
            issues_list.append(data)
        else:
            try:
                data = _analyze_issue(issue, verbose=args.verbose)
                issues_list.append(data)
                if args.cache:
                    issue_cache[cache_key] = {
                        "updated_at": updated_iso,
                        "data":       data,
                    }
            except GithubException as exc:
                print(f"  Skipping #{issue.number}: {exc}", file=sys.stderr)
            except Exception as exc:
                print(f"  Error on #{issue.number}: {exc}", file=sys.stderr)

        fetched += 1

        # Brief pause every 50 issues to avoid secondary rate limiting
        if fetched % 50 == 0 and cached is None:
            time.sleep(1)

    if args.verbose:
        print(f"Analysed {len(issues_list)} open bugs.", flush=True)

    if not issues_list:
        print("No bug issues found.  Check your token permissions.", file=sys.stderr)
        sys.exit(1)

    # ---- Persist cache ----
    if args.cache:
        _save_cache(args.cache, issue_cache)
        if args.verbose:
            print(f"Cache saved to {args.cache} ({len(issue_cache)} entries).",
                  flush=True)

    # ---- Load run history ----
    history = []
    if args.history:
        history = _load_history(args.history)

    # ---- Render ----
    generated = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    if args.verbose:
        print("Rendering HTML report…", flush=True)

    report, snapshot = render_html(
        org=args.org,
        repo=args.repo,
        issues=issues_list,
        generated=generated,
        history=history,
    )

    pathlib.Path(args.output).write_text(report, encoding="utf-8")
    if args.verbose:
        print(f"Report written to {args.output}", flush=True)

    # ---- Persist history ----
    if args.history:
        _save_snapshot(args.history, snapshot, history)
        if args.verbose:
            print(f"Snapshot appended to {args.history}", flush=True)


def _backfill_categories(data):
    """
    Re-derive categories from the stored fields in a cached issue dict.

    This handles cache entries that were created before a new category key
    was introduced.  The function is idempotent — running it on a fully
    up-to-date entry is harmless.
    """
    label_names   = data.get("labels", [])
    priority      = data.get("priority")
    areas         = data.get("areas", [])
    assignees     = data.get("assignees", [])
    comment_count = data.get("comment_count", 0)
    age_days      = data.get("age_days", 0)
    is_stale      = data.get("is_stale", False)
    has_help      = data.get("has_help_wanted", False)
    has_gfi       = data.get("has_good_first_issue", False)
    # Derive release_blocker from stored labels if the field is missing
    has_rb = data.get(
        "has_release_blocker",
        any(l.lower() == "release blocker" for l in label_names),
    )
    data["has_release_blocker"] = has_rb

    cats = []
    if has_rb:                           cats.append(CAT_RELEASE_BLOCKER)
    if priority == "high":               cats.append(CAT_HIGH)
    elif priority == "medium":           cats.append(CAT_MEDIUM)
    elif priority == "low":              cats.append(CAT_LOW)
    else:                                cats.append(CAT_NO_PRIORITY)

    if not assignees:                    cats.append(CAT_UNASSIGNED)
    if is_stale:                         cats.append(CAT_STALE)
    if age_days > LONG_OPEN_DAYS:        cats.append(CAT_LONG_OPEN)
    if comment_count == 0:               cats.append(CAT_NO_COMMENTS)
    if has_help:                         cats.append(CAT_HELP_WANTED)
    if has_gfi:                          cats.append(CAT_GOOD_FIRST_ISSUE)
    if priority is None and not areas:   cats.append(CAT_NEEDS_TRIAGE)

    data["categories"] = cats


if __name__ == "__main__":
    main()
