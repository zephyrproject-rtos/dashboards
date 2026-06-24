#!/usr/bin/env python3
# Copyright (c) 2026 The Zephyr Project Contributors
# SPDX-License-Identifier: Apache-2.0
"""Pull GitHub Actions workflow-run data over time and graph usage.

Fetches workflow runs for a repository via the GitHub REST API and produces a
self-contained HTML report charting usage:

  * runs and minutes **per day**
  * runs and minutes **per week** (ISO weeks)
  * a **per-workflow** breakdown (runs, minutes, average duration, outcome mix)

"Usage" defaults to *wall-clock* duration (``updated_at - run_started_at``),
which is free to compute from the run metadata.  Pass ``--billable`` to fetch
each run's billable timing (``/timing`` endpoint, GitHub-billed minutes summed
across runner OSes) -- accurate, but one extra API call per run.

A JSON cache (``--cache``) stores raw run records so scheduled invocations only
pull runs created since the last fetch.  A JSON history file (``--history``)
keeps one summary snapshot per invocation for long-term trend lines.

Example
-------

    python3 scripts/actions_usage.py \\
        --repo zephyrproject-rtos/zephyr \\
        --workflow twister.yaml \\
        --since 90 \\
        --output actions_usage.html \\
        --cache actions_usage_cache.json \\
        --history actions_usage_history.json
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

API_ROOT = "https://api.github.com"
_PER_PAGE = 100

# Colour palette cycled across workflows in the stacked charts.
_PALETTE = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
    "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
    "#393b79", "#637939", "#8c6d31", "#843c39", "#7b4173",
]

_CONCLUSION_COLOR = {
    "success":   "#2da44e",
    "failure":   "#cf222e",
    "cancelled": "#9a6700",
    "skipped":   "#6e7781",
    "startup_failure": "#cf222e",
    "timed_out": "#bf8700",
    "action_required": "#bf8700",
    "neutral":   "#6e7781",
    None:        "#6e7781",
}


# ---------------------------------------------------------------------------
# GitHub REST helpers
# ---------------------------------------------------------------------------

class GitHub:
    """Minimal authenticated REST client with pagination and rate handling."""

    def __init__(self, token: str | None, verbose: bool = False,
                 fallback_token: str | None = None):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        self.verbose = verbose
        # A second token (typically from `gh auth token`) tried once if the
        # primary token turns out to be missing or stale (401).
        self.fallback_token = fallback_token if fallback_token != token else None
        self._set_token(token)

    def _set_token(self, token: str | None) -> None:
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        else:
            self.session.headers.pop("Authorization", None)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr)

    def get(self, url: str, params: dict | None = None) -> requests.Response:
        """GET with basic rate-limit / secondary-limit back-off."""
        for attempt in range(6):
            resp = self.session.get(url, params=params, timeout=60)
            if resp.status_code == 200:
                return resp
            # Primary rate limit exhausted.
            if (resp.status_code in (403, 429)
                    and resp.headers.get("X-RateLimit-Remaining") == "0"):
                reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
                wait = max(reset - int(time.time()), 1) + 1
                self._log(f"  rate limited, sleeping {wait}s")
                time.sleep(min(wait, 300))
                continue
            # Secondary / abuse limit -- honour Retry-After.
            if resp.status_code in (403, 429):
                wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                self._log(f"  secondary limit, sleeping {wait}s")
                time.sleep(min(wait, 60))
                continue
            if resp.status_code == 401:
                if self.fallback_token:
                    self._log("  401 with primary token, retrying with "
                              "`gh auth token`")
                    self._set_token(self.fallback_token)
                    self.fallback_token = None
                    continue
                raise SystemExit(
                    "error: GitHub returned 401 Unauthorized. The token is "
                    "missing or invalid.\n"
                    "  Reading workflow-run data requires a valid token. Pass "
                    "--token, set a valid $GITHUB_TOKEN, or run `gh auth "
                    "login`.\n"
                    "  Tip: if $GITHUB_TOKEN is set to a stale value, unset it "
                    "(`unset GITHUB_TOKEN`) so the script can fall back to "
                    "`gh auth token`."
                )
            resp.raise_for_status()
        resp.raise_for_status()
        return resp

    def paginate(self, url: str, params: dict, item_key: str, cap: int | None,
                 stop=None):
        """Yield items across pages.

        ``stop(item)`` -- when it returns True for an item, that item is
        skipped and pagination halts (used for incremental early-exit on
        already-cached, completed runs).
        """
        params = dict(params)
        params["per_page"] = _PER_PAGE
        params["page"] = 1
        seen = 0
        while True:
            resp = self.get(url, params=params)
            payload = resp.json()
            items = payload.get(item_key, []) if isinstance(payload, dict) else payload
            if not items:
                return
            for item in items:
                if stop is not None and stop(item):
                    return
                yield item
                seen += 1
                if cap is not None and seen >= cap:
                    return
            if "next" not in resp.links:
                return
            params["page"] += 1


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def list_workflows(gh: GitHub, repo: str) -> list[dict]:
    url = f"{API_ROOT}/repos/{repo}/actions/workflows"
    return list(gh.paginate(url, {}, "workflows", cap=None))


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _duration_seconds(run: dict) -> float:
    """Wall-clock seconds from run start to completion (>= 0)."""
    start = _parse_dt(run.get("run_started_at") or run.get("created_at"))
    end = _parse_dt(run.get("updated_at"))
    if not start or not end:
        return 0.0
    return max((end - start).total_seconds(), 0.0)


def fetch_billable_ms(gh: GitHub, repo: str, run_id: int) -> int:
    """Total GitHub-billed milliseconds for a run, summed across runner OSes."""
    url = f"{API_ROOT}/repos/{repo}/actions/runs/{run_id}/timing"
    try:
        data = gh.get(url).json()
    except requests.HTTPError:
        return 0
    billable = data.get("billable") or {}
    return sum(int(v.get("total_ms", 0)) for v in billable.values())


def _record(run: dict) -> dict:
    """Project a raw API run into the compact record we cache and aggregate."""
    return {
        "id": run["id"],
        "workflow_id": run.get("workflow_id"),
        "name": run.get("name") or "",
        "path": run.get("path") or "",
        "event": run.get("event") or "",
        "branch": run.get("head_branch") or "",
        "status": run.get("status") or "",
        "conclusion": run.get("conclusion"),
        "created_at": run.get("created_at"),
        "run_started_at": run.get("run_started_at"),
        "updated_at": run.get("updated_at"),
        "run_attempt": run.get("run_attempt", 1),
        "duration_s": _duration_seconds(run),
        # billable_ms filled in lazily when --billable is set
    }


def _day_windows(start: datetime, end: datetime):
    """Yield ``(lo, hi)`` ISO date strings for each UTC day in [start, end]."""
    day = start.date()
    last = end.date()
    while day <= last:
        iso = day.isoformat()
        yield iso, iso
        day += timedelta(days=1)


def fetch_runs(gh: GitHub, repo: str, workflows: list[dict], start: datetime,
               end: datetime | None, branch: str | None, cap: int | None,
               cache: dict, verbose: bool) -> dict:
    """Return ``{run_id: record}`` for runs in the window, merged with cache.

    The runs-listing endpoint is capped at 1000 results per query, so we fetch
    one UTC day at a time per workflow (a busy workflow can exceed 1000 runs
    over a multi-week window but rarely within a single day) and stop paging a
    day once it reaches runs already cached as completed.
    """
    win_end = end or datetime.now(timezone.utc)
    records: dict[int, dict] = dict(cache.get("runs", {}))

    def is_cached_complete(run: dict) -> bool:
        rec = records.get(str(run["id"]))
        return bool(rec) and rec.get("status") == "completed"

    for wf in workflows:
        wf_id = wf["id"]
        url = f"{API_ROOT}/repos/{repo}/actions/workflows/{wf_id}/runs"
        n = 0
        for lo, hi in _day_windows(start, win_end):
            params = {"created": f"{lo}..{hi}",
                      "exclude_pull_requests": "false"}
            if branch:
                params["branch"] = branch
            day_n = 0
            for run in gh.paginate(url, params, "workflow_runs", cap,
                                   stop=is_cached_complete):
                records[str(run["id"])] = _record(run)
                day_n += 1
                n += 1
            if day_n >= 1000:
                print(f"  warning: {wf.get('path')} hit the 1000-run cap on "
                      f"{lo}; counts for that day are truncated.",
                      file=sys.stderr)
        if verbose:
            print(f"  {wf.get('path', wf.get('name'))}: {n} new/updated runs",
                  file=sys.stderr)

    # Drop runs that fell outside the requested window (cache may be wider).
    lo = start.date().isoformat()
    hi = end.date().isoformat() if end else "9999-12-31"
    return {
        rid: rec for rid, rec in records.items()
        if rec.get("created_at") and lo <= rec["created_at"][:10] <= hi
    }


def enrich_billable(gh: GitHub, repo: str, records: dict, verbose: bool) -> None:
    """Populate ``billable_ms`` for completed runs missing it (in place)."""
    pending = [r for r in records.values()
               if r.get("billable_ms") is None
               and r.get("status") == "completed"]
    if verbose and pending:
        print(f"  fetching billable timing for {len(pending)} runs...",
              file=sys.stderr)
    for i, rec in enumerate(pending, 1):
        rec["billable_ms"] = fetch_billable_ms(gh, repo, rec["id"])
        if verbose and i % 100 == 0:
            print(f"    {i}/{len(pending)}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _wf_label(rec: dict) -> str:
    """Stable per-workflow label: the workflow file basename, else the name."""
    path = rec.get("path") or ""
    if path:
        return path.split("/")[-1]
    return rec.get("name") or f"workflow-{rec.get('workflow_id')}"


def _iso_week(date_str: str) -> str:
    y, w, _ = datetime.fromisoformat(date_str).isocalendar()
    return f"{y}-W{w:02d}"


def _minutes(rec: dict, billable: bool) -> float:
    if billable and rec.get("billable_ms") is not None:
        return rec["billable_ms"] / 60000.0
    return rec.get("duration_s", 0.0) / 60.0


def aggregate(records: dict, billable: bool) -> dict:
    """Build per-day, per-week and per-workflow rollups for charting."""
    workflows = sorted({_wf_label(r) for r in records.values()})

    per_day_runs: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    per_day_min: dict[str, dict] = defaultdict(lambda: defaultdict(float))
    per_week_runs: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    per_week_min: dict[str, dict] = defaultdict(lambda: defaultdict(float))
    conclusions: dict[str, int] = defaultdict(int)
    wf_conclusions: dict[str, dict] = defaultdict(lambda: defaultdict(int))

    wf_stats: dict[str, dict] = defaultdict(
        lambda: {"runs": 0, "minutes": 0.0, "success": 0, "failure": 0,
                 "other": 0})

    for rec in records.values():
        day = (rec.get("created_at") or "")[:10]
        if not day:
            continue
        wf = _wf_label(rec)
        mins = _minutes(rec, billable)
        week = _iso_week(day)

        per_day_runs[day][wf] += 1
        per_day_min[day][wf] += mins
        per_week_runs[week][wf] += 1
        per_week_min[week][wf] += mins

        concl = rec.get("conclusion") or rec.get("status") or "unknown"
        conclusions[concl] += 1
        wf_conclusions[wf][concl] += 1

        s = wf_stats[wf]
        s["runs"] += 1
        s["minutes"] += mins
        if concl == "success":
            s["success"] += 1
        elif concl in ("failure", "startup_failure", "timed_out"):
            s["failure"] += 1
        else:
            s["other"] += 1

    days = sorted(per_day_runs)
    weeks = sorted(per_week_runs)

    def stack(series_runs, series_min, keys):
        runs = {wf: [series_runs[k].get(wf, 0) for k in keys]
                for wf in workflows}
        mins = {wf: [round(series_min[k].get(wf, 0.0), 1) for k in keys]
                for wf in workflows}
        return runs, mins

    day_runs, day_min = stack(per_day_runs, per_day_min, days)
    week_runs, week_min = stack(per_week_runs, per_week_min, weeks)

    return {
        "workflows": workflows,
        "days": days,
        "weeks": weeks,
        "day_runs": day_runs,
        "day_min": day_min,
        "week_runs": week_runs,
        "week_min": week_min,
        "wf_stats": {wf: wf_stats[wf] for wf in workflows},
        "conclusions": dict(conclusions),
        "wf_conclusions": {wf: dict(wf_conclusions[wf]) for wf in workflows},
        "total_runs": len(records),
        "total_minutes": round(sum(s["minutes"] for s in wf_stats.values()), 1),
        "billable": billable,
    }


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def _color_for(index: int) -> str:
    return _PALETTE[index % len(_PALETTE)]


def render_html(repo: str, agg: dict, generated: str, window: str) -> str:
    workflows = agg["workflows"]
    wf_colors = {wf: _color_for(i) for i, wf in enumerate(workflows)}
    usage_kind = "billable" if agg["billable"] else "wall-clock"

    # Per-workflow summary table rows (sorted by total minutes desc).
    rows = []
    for wf in sorted(workflows, key=lambda w: agg["wf_stats"][w]["minutes"],
                     reverse=True):
        s = agg["wf_stats"][wf]
        runs = s["runs"]
        avg = s["minutes"] / runs if runs else 0.0
        rate = 100.0 * s["success"] / runs if runs else 0.0
        rows.append(
            f'<tr data-wf="{html.escape(wf)}">'
            f'<td><span class="dot" style="background:{wf_colors[wf]}"></span>'
            f"{html.escape(wf)}</td>"
            f"<td class='num'>{runs}</td>"
            f"<td class='num'>{s['minutes']:.0f}</td>"
            f"<td class='num'>{avg:.1f}</td>"
            f"<td class='num'>{s['success']}</td>"
            f"<td class='num'>{s['failure']}</td>"
            f"<td class='num'>{rate:.0f}%</td>"
            "</tr>"
        )
    wf_table = "\n".join(rows)

    # Datasets for the stacked charts.
    def datasets(series: dict) -> str:
        return json.dumps([
            {"label": wf, "data": series[wf],
             "backgroundColor": wf_colors[wf], "stack": "s"}
            for wf in workflows
        ])

    # Stable colour per conclusion label (used by the outcomes doughnut as it
    # is rebuilt for the selected workflow).
    all_concls = sorted(agg["conclusions"], key=agg["conclusions"].get,
                        reverse=True)
    concl_colors = {k: _CONCLUSION_COLOR.get(k, "#6e7781") for k in all_concls}

    # Per-workflow rollups consumed by the selector in the browser.
    wf_stats_js = {wf: {"runs": s["runs"], "minutes": round(s["minutes"], 1)}
                   for wf, s in agg["wf_stats"].items()}

    # Selector options, sorted by total minutes desc to match the table.
    wf_order = sorted(workflows, key=lambda w: agg["wf_stats"][w]["minutes"],
                      reverse=True)
    options = '<option value="__all__">All workflows</option>\n' + "\n".join(
        f'<option value="{html.escape(wf)}">{html.escape(wf)}</option>'
        for wf in wf_order
    )

    return _TEMPLATE.format(
        repo=html.escape(repo),
        generated=html.escape(generated),
        window=html.escape(window),
        usage_kind=usage_kind,
        total_runs=agg["total_runs"],
        total_minutes=f"{agg['total_minutes']:.0f}",
        total_hours=f"{agg['total_minutes'] / 60:.0f}",
        n_workflows=len(workflows),
        wf_table=wf_table,
        wf_options=options,
        days_json=json.dumps(agg["days"]),
        weeks_json=json.dumps(agg["weeks"]),
        day_runs_json=datasets(agg["day_runs"]),
        day_min_json=datasets(agg["day_min"]),
        week_runs_json=datasets(agg["week_runs"]),
        week_min_json=datasets(agg["week_min"]),
        conclusion_json=json.dumps(agg["conclusions"]),
        wf_conclusion_json=json.dumps(agg["wf_conclusions"]),
        concl_colors_json=json.dumps(concl_colors),
        wf_stats_json=json.dumps(wf_stats_js),
    )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GitHub Actions Usage — {repo}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:#0d1117; --card:#161b22; --border:#30363d; --fg:#e6edf3;
    --muted:#8b949e; --accent:#58a6ff;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    font-size:14px; }}
  header {{ padding:20px 28px; border-bottom:1px solid var(--border); }}
  h1 {{ margin:0 0 4px; font-size:1.3rem; }}
  .sub {{ color:var(--muted); font-size:.85rem; }}
  main {{ padding:20px 28px; max-width:1280px; margin:0 auto; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat {{ background:var(--card); border:1px solid var(--border);
    border-radius:8px; padding:14px 18px; min-width:150px; }}
  .stat .v {{ font-size:1.6rem; font-weight:700; }}
  .stat .l {{ color:var(--muted); font-size:.78rem; text-transform:uppercase;
    letter-spacing:.04em; }}
  .card {{ background:var(--card); border:1px solid var(--border);
    border-radius:8px; padding:16px 18px; margin-bottom:24px; }}
  .card h2 {{ margin:0 0 12px; font-size:1rem; }}
  .chart-wrap {{ position:relative; height:360px; }}
  .row {{ display:flex; gap:24px; flex-wrap:wrap; }}
  .row > .card {{ flex:1; min-width:320px; }}
  table {{ border-collapse:collapse; width:100%; font-size:.85rem; }}
  th,td {{ padding:7px 10px; border-bottom:1px solid var(--border);
    text-align:left; }}
  th {{ color:var(--muted); font-weight:600; cursor:pointer; user-select:none; }}
  td.num,th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:2px;
    margin-right:7px; vertical-align:middle; }}
  .toggle {{ font-size:.8rem; color:var(--muted); margin-bottom:10px; }}
  .toggle button {{ background:var(--card); color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:4px 10px;
    cursor:pointer; margin-right:6px; }}
  .toggle button.active {{ border-color:var(--accent); color:var(--accent); }}
  .controls {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    margin-bottom:20px; }}
  .controls label {{ color:var(--muted); font-size:.85rem; }}
  .controls select {{ background:var(--card); color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px;
    font-size:.9rem; min-width:240px; max-width:100%; }}
  .controls button {{ background:var(--card); color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px;
    cursor:pointer; font-size:.85rem; }}
  #wfTable tbody tr.dim {{ opacity:.32; }}
</style>
</head>
<body>
<header>
  <h1>GitHub Actions Usage — {repo}</h1>
  <div class="sub">Window: {window} &nbsp;·&nbsp; usage = {usage_kind} minutes
    &nbsp;·&nbsp; generated {generated}</div>
</header>
<main>
  <div class="controls">
    <label for="wfSelect">Workflow</label>
    <select id="wfSelect" onchange="applyFilter(this.value)">{wf_options}</select>
    <button onclick="document.getElementById('wfSelect').value='__all__';applyFilter('__all__')">Reset</button>
  </div>
  <div class="cards">
    <div class="stat"><div class="v" id="statRuns">{total_runs}</div><div class="l">Runs</div></div>
    <div class="stat"><div class="v" id="statMin">{total_minutes}</div><div class="l">Minutes</div></div>
    <div class="stat"><div class="v" id="statHours">{total_hours}</div><div class="l">Hours</div></div>
    <div class="stat"><div class="v" id="statWf">{n_workflows}</div><div class="l">Workflows</div></div>
  </div>

  <div class="card">
    <h2>Per day</h2>
    <div class="toggle">
      <button id="d-runs" class="active" onclick="setDay('runs')">Runs</button>
      <button id="d-min" onclick="setDay('min')">Minutes</button>
    </div>
    <div class="chart-wrap"><canvas id="dayChart"></canvas></div>
  </div>

  <div class="card">
    <h2>Per week</h2>
    <div class="toggle">
      <button id="w-runs" class="active" onclick="setWeek('runs')">Runs</button>
      <button id="w-min" onclick="setWeek('min')">Minutes</button>
    </div>
    <div class="chart-wrap"><canvas id="weekChart"></canvas></div>
  </div>

  <div class="row">
    <div class="card">
      <h2>Per workflow</h2>
      <table id="wfTable">
        <thead><tr>
          <th>Workflow</th><th class="num">Runs</th><th class="num">Minutes</th>
          <th class="num">Avg min</th><th class="num">OK</th>
          <th class="num">Fail</th><th class="num">Success</th>
        </tr></thead>
        <tbody>{wf_table}</tbody>
      </table>
    </div>
    <div class="card" style="max-width:420px;">
      <h2>Outcomes</h2>
      <div class="chart-wrap" style="height:300px;"><canvas id="conclChart"></canvas></div>
    </div>
  </div>
</main>

<script>
const DAYS = {days_json};
const WEEKS = {weeks_json};
const DAY_RUNS = {day_runs_json};
const DAY_MIN = {day_min_json};
const WEEK_RUNS = {week_runs_json};
const WEEK_MIN = {week_min_json};
const CONCL = {conclusion_json};            // global {{label: count}}
const WF_CONCL = {wf_conclusion_json};      // {{wf: {{label: count}}}}
const CONCL_COLORS = {concl_colors_json};   // {{label: color}}
const WF_STATS = {wf_stats_json};           // {{wf: {{runs, minutes}}}}

const ALL = '__all__';
const state = {{ wf: ALL, dayMetric: 'runs', weekMetric: 'runs' }};

const stackOpts = (unit, stacked) => ({{
  responsive:true, maintainAspectRatio:false,
  interaction:{{ mode:'index', intersect:false }},
  plugins:{{
    legend:{{ display:stacked, position:'bottom',
             labels:{{ boxWidth:12, font:{{size:11}} }} }},
    tooltip:{{ callbacks:{{ label:(c)=>`${{c.dataset.label}}: ${{Math.round(c.parsed.y)}} ${{unit}}` }} }}
  }},
  scales:{{ x:{{ stacked:true, ticks:{{ font:{{size:10}}, maxRotation:60 }} }},
            y:{{ stacked:true, beginAtZero:true,
                 title:{{ display:true, text:unit }} }} }}
}});

// Datasets filtered to the selected workflow (or all of them).
function seriesFor(sets) {{
  const picked = state.wf === ALL ? sets : sets.filter(s => s.label === state.wf);
  return picked.map(s => ({{...s, data:[...s.data]}}));
}}

function conclData() {{
  const src = state.wf === ALL ? CONCL : (WF_CONCL[state.wf] || {{}});
  const labels = Object.keys(src);
  return {{
    labels,
    data: labels.map(k => src[k]),
    colors: labels.map(k => CONCL_COLORS[k] || '#6e7781'),
  }};
}}

const dayChart = new Chart(document.getElementById('dayChart'), {{
  type:'bar', data:{{ labels:DAYS, datasets:seriesFor(DAY_RUNS) }},
  options:stackOpts('runs', true)
}});
const weekChart = new Chart(document.getElementById('weekChart'), {{
  type:'bar', data:{{ labels:WEEKS, datasets:seriesFor(WEEK_RUNS) }},
  options:stackOpts('runs', true)
}});
const conclChart = new Chart(document.getElementById('conclChart'), {{
  type:'doughnut', data:{{ labels:[], datasets:[{{ data:[], backgroundColor:[] }}] }},
  options:{{ responsive:true, maintainAspectRatio:false,
            plugins:{{ legend:{{ position:'right', labels:{{ boxWidth:12, font:{{size:11}} }} }} }} }}
}});

function renderDay() {{
  const runs = state.dayMetric === 'runs';
  dayChart.data.datasets = seriesFor(runs ? DAY_RUNS : DAY_MIN);
  dayChart.options = stackOpts(runs ? 'runs' : 'minutes', state.wf === ALL);
  dayChart.update();
  document.getElementById('d-runs').classList.toggle('active', runs);
  document.getElementById('d-min').classList.toggle('active', !runs);
}}
function renderWeek() {{
  const runs = state.weekMetric === 'runs';
  weekChart.data.datasets = seriesFor(runs ? WEEK_RUNS : WEEK_MIN);
  weekChart.options = stackOpts(runs ? 'runs' : 'minutes', state.wf === ALL);
  weekChart.update();
  document.getElementById('w-runs').classList.toggle('active', runs);
  document.getElementById('w-min').classList.toggle('active', !runs);
}}
function renderConcl() {{
  const d = conclData();
  conclChart.data.labels = d.labels;
  conclChart.data.datasets[0].data = d.data;
  conclChart.data.datasets[0].backgroundColor = d.colors;
  conclChart.update();
}}
function renderStats() {{
  let runs = 0, mins = 0, n = 0;
  if (state.wf === ALL) {{
    for (const k in WF_STATS) {{ runs += WF_STATS[k].runs; mins += WF_STATS[k].minutes; n++; }}
  }} else if (WF_STATS[state.wf]) {{
    runs = WF_STATS[state.wf].runs; mins = WF_STATS[state.wf].minutes; n = 1;
  }}
  document.getElementById('statRuns').textContent = runs.toLocaleString();
  document.getElementById('statMin').textContent = Math.round(mins).toLocaleString();
  document.getElementById('statHours').textContent = Math.round(mins/60).toLocaleString();
  document.getElementById('statWf').textContent = n;
}}
function renderTable() {{
  document.querySelectorAll('#wfTable tbody tr').forEach(tr => {{
    tr.classList.toggle('dim',
      state.wf !== ALL && tr.dataset.wf !== state.wf);
  }});
}}

function applyFilter(wf) {{
  state.wf = wf;
  renderDay(); renderWeek(); renderConcl(); renderStats(); renderTable();
}}
function setDay(kind) {{ state.dayMetric = kind; renderDay(); }}
function setWeek(kind) {{ state.weekMetric = kind; renderWeek(); }}

renderConcl();  // initial doughnut

// Click-to-sort for the per-workflow table.
document.querySelectorAll('#wfTable th').forEach((th, i) => {{
  let asc = false;
  th.addEventListener('click', () => {{
    asc = !asc;
    const tb = document.querySelector('#wfTable tbody');
    const rows = [...tb.rows];
    const num = i > 0;
    rows.sort((a,b) => {{
      let x=a.cells[i].textContent.trim(), y=b.cells[i].textContent.trim();
      if (num) {{ x=parseFloat(x)||0; y=parseFloat(y)||0; return asc?x-y:y-x; }}
      return asc ? x.localeCompare(y) : y.localeCompare(x);
    }});
    rows.forEach(r => tb.appendChild(r));
  }});
}});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_json(path: str | None) -> dict:
    if path and Path(path).exists():
        try:
            return json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_cache(path: str | None, records: dict) -> None:
    if not path:
        return
    Path(path).write_text(json.dumps({"runs": records}, indent=0))


def append_history(path: str | None, agg: dict, generated: str) -> None:
    if not path:
        return
    history = load_json(path)
    snapshots = history.get("snapshots", []) if isinstance(history, dict) else []
    snapshots.append({
        "generated": generated,
        "total_runs": agg["total_runs"],
        "total_minutes": agg["total_minutes"],
        "billable": agg["billable"],
        "per_workflow_minutes": {
            wf: round(s["minutes"], 1) for wf, s in agg["wf_stats"].items()
        },
    })
    Path(path).write_text(json.dumps({"snapshots": snapshots}, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--repo", default="zephyrproject-rtos/zephyr",
                   help="owner/repo (default: zephyrproject-rtos/zephyr)")
    p.add_argument("--workflow", action="append", default=[],
                   help="Workflow file basename to include, e.g. twister.yaml "
                        "(repeatable; default: all workflows)")
    p.add_argument("--since", type=int, default=30,
                   help="Look back this many days (default: 30)")
    p.add_argument("--start", help="Start date YYYY-MM-DD (overrides --since)")
    p.add_argument("--end", help="End date YYYY-MM-DD (default: today)")
    p.add_argument("--branch", help="Restrict to a single branch")
    p.add_argument("--billable", action="store_true",
                   help="Fetch GitHub-billed timing per run (accurate but slow)")
    p.add_argument("--max-runs", type=int,
                   help="Cap runs fetched per workflow per day (safety limit)")
    p.add_argument("--output", default="actions_usage.html",
                   help="Output HTML path (default: actions_usage.html)")
    p.add_argument("--cache", help="JSON cache of run records for incremental pulls")
    p.add_argument("--history", help="JSON history file for trend snapshots")
    p.add_argument("--token", help="GitHub token (default: $GITHUB_TOKEN)")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def gh_cli_token() -> str | None:
    """Return a token from the `gh` CLI, querying it without $GITHUB_TOKEN.

    A stale $GITHUB_TOKEN in the environment shadows the keyring token `gh`
    would otherwise use, so we strip it before asking.
    """
    import shutil
    import subprocess
    if not shutil.which("gh"):
        return None
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
    try:
        out = subprocess.run(["gh", "auth", "token"], env=env,
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    token = out.stdout.strip()
    return token or None


def main() -> int:
    args = parse_args()
    token = args.token or os.environ.get("GITHUB_TOKEN")
    # Resolved lazily and used only if the primary token 401s.
    fallback = None if args.token else gh_cli_token()
    if not token and not fallback:
        print("warning: no token (set --token or $GITHUB_TOKEN); "
              "unauthenticated requests are heavily rate limited.",
              file=sys.stderr)
    elif not token and fallback:
        token, fallback = fallback, None

    if args.start:
        start = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc)
    else:
        start = datetime.now(timezone.utc) - timedelta(days=args.since)
    end = (datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc)
           if args.end else None)
    window = (f"{start.date()} → "
              f"{(end.date() if end else datetime.now(timezone.utc).date())}")

    gh = GitHub(token, verbose=args.verbose, fallback_token=fallback)

    if args.verbose:
        print(f"Listing workflows for {args.repo}...", file=sys.stderr)
    workflows = list_workflows(gh, args.repo)
    if args.workflow:
        wanted = set(args.workflow)
        workflows = [w for w in workflows
                     if w.get("path", "").split("/")[-1] in wanted
                     or w.get("name") in wanted]
        if not workflows:
            print(f"No workflows matched {args.workflow}", file=sys.stderr)
            return 1
    if args.verbose:
        print(f"Selected {len(workflows)} workflow(s).", file=sys.stderr)

    cache = load_json(args.cache)
    records = fetch_runs(gh, args.repo, workflows, start, end, args.branch,
                         args.max_runs, cache, args.verbose)

    if args.billable:
        # Carry forward billable_ms already in cache, then fill gaps.
        cached = cache.get("runs", {})
        for rid, rec in records.items():
            if rec.get("billable_ms") is None and rid in cached:
                rec["billable_ms"] = cached[rid].get("billable_ms")
        enrich_billable(gh, args.repo, records, args.verbose)

    save_cache(args.cache, records)

    agg = aggregate(records, billable=args.billable)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_out = render_html(args.repo, agg, generated, window)
    Path(args.output).write_text(html_out, encoding="utf-8")
    append_history(args.history, agg, generated)

    print(f"Wrote {args.output}: {agg['total_runs']} runs, "
          f"{agg['total_minutes']:.0f} {'billable' if args.billable else 'wall-clock'} "
          f"minutes across {len(agg['workflows'])} workflow(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
