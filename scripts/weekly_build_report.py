#!/usr/bin/env python3
# Copyright (c) 2026 The Zephyr Project Contributors
# SPDX-License-Identifier: Apache-2.0
"""Dashboard for Zephyr's weekly (scheduled) twister build CI run.

Finds the most recent scheduled run of ``twister.yaml`` in
zephyrproject-rtos/zephyr, downloads every ``Unit Test Results (Subset N)``
artifact it produced, aggregates the ``twister.json`` inside each one and
renders a single self-contained HTML dashboard covering:

  * headline counters for the whole run (suites built, failures, filtered...)
  * the CI run itself: duration, per-job conclusions, slowest/failed jobs
  * platforms that failed, ranked by failure count
  * test suites that failed, and on how many platforms
  * failure reasons, grouped and counted
  * a detailed failure table with an excerpt of the build log
  * build-time, architecture and toolchain statistics
  * a trend chart over previous runs (with ``--history``)

The weekly run is a *build-only* run of the whole tree (``--all``), so most
suites end up as ``not run`` (built, never executed) or ``filtered``.  The
dashboard is built around that: "failures" means build errors.

Example
-------
    ./scripts/weekly_build_report.py \\
        --output weekly_build.html \\
        --history weekly_build_history.json \\
        --cache-dir .cache/weekly

Authentication uses ``GITHUB_TOKEN``/``GH_TOKEN`` if set, otherwise the
token from a logged-in ``gh`` CLI.
"""

from __future__ import annotations

import argparse
import html
import io
import json
import os
import re
import subprocess
import sys
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    print("The 'requests' package is required.  Install with: pip install requests",
          file=sys.stderr)
    raise SystemExit(1)

API_ROOT = "https://api.github.com"

DEFAULT_REPO = "zephyrproject-rtos/zephyr"
DEFAULT_WORKFLOW = "twister.yaml"
DEFAULT_EVENT = "schedule"
DEFAULT_PATTERN = r"^Unit Test Results \(Subset \d+\)$"

# Suite statuses twister can report.  Order is the display order.
SUITE_STATUSES = ["passed", "failed", "error", "skipped", "filtered", "not run"]

# Statuses that count as a failure of the build CI run.
FAILURE_STATUSES = {"failed", "error"}

# Statuses where nothing was built (so they do not count towards a pass rate).
NOT_ATTEMPTED_STATUSES = {"filtered", "skipped"}

STATUS_COLOR = {
    "passed":   "#2da44e",
    "failed":   "#cf222e",
    "error":    "#a40e26",
    "skipped":  "#bf8700",
    "filtered": "#9a6700",
    "not run":  "#6e7781",
}

STATUS_DESC = {
    "passed":   "Built and executed successfully.",
    "failed":   "Built, executed, and produced unexpected results.",
    "error":    "Failed to build, or errored before producing a result.",
    "skipped":  "Explicitly skipped (unmet precondition).",
    "filtered": "Not applicable to this platform; never built.",
    "not run":  "Built successfully but not executed (build-only run).",
}

# How much of a failing build log to keep for the detail table.
LOG_EXCERPT_CHARS = 600
LOG_EXCERPT_LINES = 6


def log(msg: str, verbose: bool = True) -> None:
    if verbose:
        print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

def resolve_token(explicit: str | None = None) -> str | None:
    """Return a GitHub token from the CLI flag, the environment, or ``gh``."""
    if explicit:
        return explicit
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True,
                             text=True, timeout=15)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


class GitHub:
    """Minimal GitHub REST client with retries and pagination."""

    def __init__(self, token: str | None, verbose: bool = False):
        self.session = requests.Session()
        self.verbose = verbose
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "zephyr-weekly-build-dashboard",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def get(self, path: str, params: dict | None = None, retries: int = 4) -> dict | list:
        url = path if path.startswith("http") else f"{API_ROOT}{path}"
        delay = 2.0
        for attempt in range(retries):
            resp = self.session.get(url, headers=self.headers, params=params, timeout=60)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 429) and "rate limit" in resp.text.lower():
                reset = resp.headers.get("X-RateLimit-Reset")
                wait = delay
                if reset:
                    wait = max(delay, float(reset) - time.time() + 5)
                log(f"Rate limited, sleeping {wait:.0f}s", self.verbose)
                time.sleep(min(wait, 900))
                continue
            if resp.status_code >= 500 and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"GitHub API {resp.status_code} for {url}: {resp.text[:300]}")
        raise RuntimeError(f"GitHub API failed after {retries} attempts: {url}")

    def paged(self, path: str, key: str, params: dict | None = None,
              max_pages: int = 50) -> list:
        """Collect ``key`` from every page of a paginated endpoint."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        items: list = []
        for page in range(1, max_pages + 1):
            params["page"] = page
            data = self.get(path, params)
            batch = data.get(key, []) if isinstance(data, dict) else data
            items.extend(batch)
            if len(batch) < params["per_page"]:
                break
        return items

    def download(self, url: str, retries: int = 4) -> bytes:
        """Download a redirecting artifact URL.

        The redirect target is signed storage that rejects (and must not see)
        our Authorization header, so the redirect is followed manually.
        """
        delay = 2.0
        for attempt in range(retries):
            try:
                resp = self.session.get(url, headers=self.headers,
                                        allow_redirects=False, timeout=120)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers["Location"]
                    resp = self.session.get(loc, timeout=300)
                if resp.status_code == 200:
                    return resp.content
                if resp.status_code == 410:
                    raise RuntimeError("artifact expired")
                if attempt == retries - 1:
                    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
            except requests.RequestException as exc:
                if attempt == retries - 1:
                    raise RuntimeError(str(exc)) from exc
            time.sleep(delay)
            delay *= 2
        raise RuntimeError(f"download failed: {url}")


# ---------------------------------------------------------------------------
# Run / artifact discovery
# ---------------------------------------------------------------------------

def find_run(gh: GitHub, repo: str, workflow: str, event: str, branch: str | None,
             run_id: int | None, verbose: bool = False) -> dict:
    """Return the workflow run to report on."""
    if run_id:
        log(f"Fetching run {run_id} from {repo}", verbose)
        return gh.get(f"/repos/{repo}/actions/runs/{run_id}")

    params = {"event": event, "status": "completed", "per_page": 10}
    if branch:
        params["branch"] = branch
    log(f"Looking for the latest {event} run of {workflow} in {repo}", verbose)
    data = gh.get(f"/repos/{repo}/actions/workflows/{workflow}/runs", params)
    runs = data.get("workflow_runs", [])
    if not runs:
        raise SystemExit(
            f"No completed '{event}' runs found for {workflow} in {repo}")
    return runs[0]


def fetch_jobs(gh: GitHub, repo: str, run_id: int, verbose: bool = False) -> list[dict]:
    log(f"Fetching jobs for run {run_id}", verbose)
    try:
        return gh.paged(f"/repos/{repo}/actions/runs/{run_id}/jobs", "jobs",
                        {"filter": "latest"})
    except RuntimeError as exc:
        log(f"WARNING: could not fetch jobs: {exc}", True)
        return []


def select_artifacts(gh: GitHub, repo: str, run_id: int, pattern: str,
                     verbose: bool = False) -> list[dict]:
    log(f"Listing artifacts for run {run_id}", verbose)
    arts = gh.paged(f"/repos/{repo}/actions/runs/{run_id}/artifacts", "artifacts")
    rx = re.compile(pattern)
    matched = [a for a in arts if rx.search(a["name"])]
    live = [a for a in matched if not a.get("expired")]
    if len(live) < len(matched):
        log(f"WARNING: {len(matched) - len(live)} matching artifacts have expired", True)
    matched = sorted(live, key=lambda a: _subset_index(a["name"]))
    log(f"{len(arts)} artifacts on the run, {len(matched)} match {pattern!r}", verbose)
    return matched


def _subset_index(name: str) -> tuple[int, str]:
    m = re.search(r"(\d+)", name)
    return (int(m.group(1)) if m else 0, name)


# ---------------------------------------------------------------------------
# Loading twister results
# ---------------------------------------------------------------------------

def _twister_json_from_zip(blob: bytes, source: str) -> list[dict]:
    """Yield every parsed twister.json document inside an artifact zip."""
    docs = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        log(f"WARNING: {source} is not a valid zip ({exc})", True)
        return docs
    with zf:
        names = [n for n in zf.namelist() if n.endswith("twister.json")]
        if not names:
            log(f"WARNING: no twister.json inside {source}", True)
        for name in names:
            try:
                with zf.open(name) as fh:
                    docs.append(json.load(fh))
            except (json.JSONDecodeError, OSError) as exc:
                log(f"WARNING: could not parse {name} in {source}: {exc}", True)
    return docs


def iter_remote_results(gh: GitHub, artifacts: list[dict], jobs: int,
                        cache_dir: Path | None, run_id: int,
                        verbose: bool = False):
    """Download artifacts in parallel and yield (source, twister.json doc).

    Downloads run in a thread pool while parsing happens here, so peak memory
    stays at a handful of artifacts rather than the whole run.
    """
    run_cache = (cache_dir / str(run_id)) if cache_dir else None
    if run_cache:
        run_cache.mkdir(parents=True, exist_ok=True)

    def fetch(art: dict) -> tuple[str, bytes | None]:
        name = art["name"]
        cached = (run_cache / f"{_safe_name(name)}.zip") if run_cache else None
        if cached and cached.exists():
            return name, cached.read_bytes()
        try:
            blob = gh.download(art["archive_download_url"])
        except RuntimeError as exc:
            log(f"WARNING: download of {name!r} failed: {exc}", True)
            return name, None
        if cached:
            try:
                cached.write_bytes(blob)
            except OSError as exc:
                log(f"WARNING: could not cache {name!r}: {exc}", True)
        return name, blob

    done = 0
    total = len(artifacts)
    workers = max(1, jobs)
    batch_size = workers * 2
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, total, batch_size):
            batch = artifacts[start:start + batch_size]
            for name, blob in pool.map(fetch, batch):
                done += 1
                if verbose and (done % 10 == 0 or done == total):
                    log(f"  [{done}/{total}] artifacts downloaded", True)
                if blob is None:
                    continue
                for doc in _twister_json_from_zip(blob, name):
                    yield name, doc
                del blob


def iter_local_results(paths: list[str]):
    """Yield (source, twister.json doc) from a local directory or file list."""
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(p.rglob("twister.json")))
            files.extend(sorted(p.rglob("*.zip")))
        elif p.exists():
            files.append(p)
        else:
            log(f"WARNING: {p} does not exist", True)
    if not files:
        raise SystemExit(f"No twister.json files found in: {', '.join(paths)}")
    for path in files:
        if path.suffix == ".zip":
            for doc in _twister_json_from_zip(path.read_bytes(), str(path)):
                yield path.name, doc
            continue
        try:
            with open(path) as fh:
                yield path.name, json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log(f"WARNING: could not read {path}: {exc}", True)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

_ERROR_LINE_RX = re.compile(r"\b(error|Error|ERROR|fatal|undefined reference)\b")

# Reasons are free-form strings; fold the volatile parts so they group.
_REASON_CLEANERS = [
    (re.compile(r"/[\w./+-]+/(?=[\w.+-]+:)"), ""),        # strip leading paths
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "0x…"),
    (re.compile(r"\b\d{3,}\b"), "N"),
    (re.compile(r"\s+"), " "),
]


def normalise_reason(reason: str | None) -> str:
    if not reason:
        return "(no reason reported)"
    text = str(reason).strip().splitlines()[0]
    for rx, repl in _REASON_CLEANERS:
        text = rx.sub(repl, text)
    text = text.strip()
    return (text[:140] + "…") if len(text) > 140 else text or "(no reason reported)"


def log_excerpt(build_log: str | None) -> str:
    """Return the most interesting tail of a failing build log."""
    if not build_log:
        return ""
    lines = [ln.rstrip() for ln in str(build_log).splitlines() if ln.strip()]
    if not lines:
        return ""
    hits = [ln for ln in lines if _ERROR_LINE_RX.search(ln)]
    chosen = hits[-LOG_EXCERPT_LINES:] if hits else lines[-LOG_EXCERPT_LINES:]
    text = "\n".join(chosen)
    if len(text) > LOG_EXCERPT_CHARS:
        text = "…" + text[-LOG_EXCERPT_CHARS:]
    return text


class Aggregate:
    """Streaming accumulator over ~1M test suites.

    Only failures and per-key counters are retained; suite records (which
    embed full build logs) are dropped as soon as they are folded in.
    """

    MAX_SLOWEST = 40
    MAX_FAILURE_PLATFORMS = 12

    def __init__(self):
        self.environment: dict = {}
        self.subsets: set[str] = set()
        self.sources: set[str] = set()
        self.total = 0
        self.status = Counter()
        self.case_status = Counter()
        self.case_total = 0

        self.platforms: dict[str, Counter] = defaultdict(Counter)
        self.platform_arch: dict[str, str] = {}
        self.archs: dict[str, Counter] = defaultdict(Counter)
        self.toolchains: dict[str, Counter] = defaultdict(Counter)

        self.tests: dict[str, Counter] = defaultdict(Counter)
        self.test_path: dict[str, str] = {}
        self.test_fail_platforms: dict[str, list[str]] = defaultdict(list)

        self.reasons: Counter = Counter()
        self.reason_tests: dict[str, set] = defaultdict(set)
        self.failures: list[dict] = []

        self.build_time_total = 0.0
        self.build_time_count = 0
        self.exec_time_total = 0.0
        self.retries_total = 0
        self.suites_retried = 0
        self.slowest: list[tuple[float, str, str]] = []

    # -- ingestion ---------------------------------------------------------

    def add_document(self, source: str, doc: dict) -> int:
        self.sources.add(source)
        env = doc.get("environment") or {}
        if env and not self.environment:
            self.environment = env
        subset = (env.get("options") or {}).get("subset")
        if subset:
            self.subsets.add(str(subset))
        suites = doc.get("testsuites") or []
        for suite in suites:
            self.add_suite(suite, subset)
        return len(suites)

    def add_suite(self, suite: dict, subset: str | None = None) -> None:
        status = (suite.get("status") or "not run").lower()
        platform = suite.get("platform") or "(unknown)"
        name = suite.get("name") or "(unnamed)"
        arch = suite.get("arch") or "(unknown)"
        toolchain = suite.get("toolchain") or "(unknown)"

        self.total += 1
        self.status[status] += 1
        self.platforms[platform][status] += 1
        self.platforms[platform]["total"] += 1
        self.platform_arch.setdefault(platform, arch)
        self.archs[arch][status] += 1
        self.archs[arch]["total"] += 1
        self.toolchains[toolchain][status] += 1
        self.toolchains[toolchain]["total"] += 1

        self.tests[name][status] += 1
        self.tests[name]["total"] += 1
        self.test_path.setdefault(name, suite.get("path") or "")

        build_time = _as_float(suite.get("build_time"))
        if build_time:
            self.build_time_total += build_time
            self.build_time_count += 1
            self.platforms[platform]["build_seconds"] += int(build_time)
            self._note_slow(build_time, name, platform)
        self.exec_time_total += _as_float(suite.get("execution_time"))

        retries = int(suite.get("retries") or 0)
        if retries:
            self.retries_total += retries
            self.suites_retried += 1

        cases = suite.get("testcases") or []
        self.case_total += len(cases)
        for case in cases:
            self.case_status[(case.get("status") or "not run").lower()] += 1

        if status in FAILURE_STATUSES:
            reason = normalise_reason(suite.get("reason"))
            self.reasons[reason] += 1
            self.reason_tests[reason].add(name)
            if len(self.test_fail_platforms[name]) < self.MAX_FAILURE_PLATFORMS:
                self.test_fail_platforms[name].append(platform)
            self.failures.append({
                "name": name,
                "path": suite.get("path") or "",
                "platform": platform,
                "arch": arch,
                "status": status,
                "reason": reason,
                "raw_reason": (suite.get("reason") or "").strip(),
                "excerpt": log_excerpt(suite.get("log")),
                "build_time": build_time,
                "retries": retries,
                "subset": subset or "",
            })

    def _note_slow(self, seconds: float, name: str, platform: str) -> None:
        if len(self.slowest) < self.MAX_SLOWEST:
            self.slowest.append((seconds, name, platform))
            self.slowest.sort(reverse=True)
        elif seconds > self.slowest[-1][0]:
            self.slowest[-1] = (seconds, name, platform)
            self.slowest.sort(reverse=True)

    # -- derived numbers ---------------------------------------------------

    @property
    def failures_count(self) -> int:
        return sum(self.status[s] for s in FAILURE_STATUSES)

    @property
    def attempted(self) -> int:
        """Suites that were actually built (not filtered out or skipped)."""
        return self.total - sum(self.status[s] for s in NOT_ATTEMPTED_STATUSES)

    @property
    def build_success_rate(self) -> float:
        return 100.0 * (self.attempted - self.failures_count) / self.attempted \
            if self.attempted else 0.0

    def failing_platforms(self) -> list[dict]:
        rows = []
        for platform, c in self.platforms.items():
            fails = sum(c[s] for s in FAILURE_STATUSES)
            if not fails:
                continue
            attempted = c["total"] - sum(c[s] for s in NOT_ATTEMPTED_STATUSES)
            rows.append({
                "platform": platform,
                "arch": self.platform_arch.get(platform, ""),
                "total": c["total"],
                "attempted": attempted,
                "failures": fails,
                "error": c["error"],
                "failed": c["failed"],
                "rate": (100.0 * fails / attempted) if attempted else 0.0,
            })
        rows.sort(key=lambda r: (-r["failures"], -r["rate"], r["platform"]))
        return rows

    def failing_tests(self) -> list[dict]:
        rows = []
        for name, c in self.tests.items():
            fails = sum(c[s] for s in FAILURE_STATUSES)
            if not fails:
                continue
            rows.append({
                "name": name,
                "path": self.test_path.get(name, ""),
                "total": c["total"],
                "failures": fails,
                "error": c["error"],
                "failed": c["failed"],
                "platforms": self.test_fail_platforms.get(name, []),
                "truncated": fails > len(self.test_fail_platforms.get(name, [])),
            })
        rows.sort(key=lambda r: (-r["failures"], r["name"]))
        return rows

    def reason_rows(self) -> list[dict]:
        return [
            {"reason": reason, "count": count,
             "tests": len(self.reason_tests.get(reason, ()))}
            for reason, count in self.reasons.most_common()
        ]

    def key_rows(self, table: dict[str, Counter], label: str) -> list[dict]:
        rows = []
        for key, c in table.items():
            fails = sum(c[s] for s in FAILURE_STATUSES)
            attempted = c["total"] - sum(c[s] for s in NOT_ATTEMPTED_STATUSES)
            rows.append({
                label: key,
                "total": c["total"],
                "attempted": attempted,
                "failures": fails,
                "not_run": c["not run"],
                "passed": c["passed"],
                "filtered": c["filtered"] + c["skipped"],
                "rate": (100.0 * fails / attempted) if attempted else 0.0,
            })
        rows.sort(key=lambda r: (-r["failures"], -r["total"]))
        return rows


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# CI job statistics
# ---------------------------------------------------------------------------

def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def job_rows(jobs: list[dict]) -> list[dict]:
    rows = []
    for j in jobs:
        start, end = parse_dt(j.get("started_at")), parse_dt(j.get("completed_at"))
        duration = (end - start).total_seconds() if start and end else 0.0
        rows.append({
            "name": j.get("name") or "",
            "conclusion": j.get("conclusion") or j.get("status") or "unknown",
            "duration": duration,
            "url": j.get("html_url") or "",
            "runner": j.get("runner_group_name") or "",
        })
    return rows


def run_duration_seconds(run: dict) -> float:
    start = parse_dt(run.get("run_started_at") or run.get("created_at"))
    end = parse_dt(run.get("updated_at"))
    return (end - start).total_seconds() if start and end else 0.0


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def fmt_int(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds or 0)
    if seconds <= 0:
        return "–"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def fmt_dt(value: str | None) -> str:
    dt = parse_dt(value)
    if not dt:
        return "–"
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def status_badge(status: str, count: int | None = None) -> str:
    color = STATUS_COLOR.get(status, "#6e7781")
    text = esc(status) if count is None else f"{esc(status)}&nbsp;{fmt_int(count)}"
    return (f'<span class="badge" style="background:{color}1f;color:{color};'
            f'border:1px solid {color}55">{text}</span>')


def conclusion_badge(conclusion: str) -> str:
    color = {
        "success": "#2da44e", "failure": "#cf222e", "cancelled": "#6e7781",
        "skipped": "#6e7781", "timed_out": "#bf8700", "startup_failure": "#cf222e",
    }.get(conclusion, "#6e7781")
    return (f'<span class="badge" style="background:{color}1f;color:{color};'
            f'border:1px solid {color}55">{esc(conclusion)}</span>')


def pct_bar(pct: float, color: str = "#0969da") -> str:
    width = max(0.0, min(100.0, pct))
    return (f'<div class="bar-wrap"><div class="bar-track">'
            f'<div class="bar" style="width:{width:.2f}%;background:{color}"></div>'
            f'</div><span class="bar-label">{pct:.1f}%</span></div>')


def table(headers: list[str], rows: list[str], table_id: str = "",
          filterable: bool = True, empty: str = "Nothing to report.") -> str:
    if not rows:
        return f'<p class="empty">{esc(empty)}</p>'
    head = "".join(f"<th>{h}</th>" for h in headers)
    filt = ""
    if filterable:
        filt = ("<tr class=\"filter-row\">" + "".join(
            '<th><input type="text" placeholder="filter…" aria-label="Filter column"></th>'
            for _ in headers) + "</tr>")
    cls = "data" + (" filterable" if filterable else "")
    tid = f' id="{table_id}"' if table_id else ""
    return (f'<div class="tbl-wrap"><table class="{cls}"{tid}>'
            f'<thead><tr>{head}</tr>{filt}</thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


CSS = """
:root{--bg:#f6f8fa;--panel:#fff;--border:#d0d7de;--text:#24292f;--muted:#57606a;
      --head:#eaeef2;--accent:#0969da}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
     font-size:14px;color:var(--text);background:var(--bg);padding:0 0 60px}
a{color:var(--accent)}
.topnav{position:sticky;top:0;z-index:20;background:#24292f;color:#fff;
        padding:10px 24px;display:flex;flex-wrap:wrap;gap:16px;align-items:center}
.topnav a{color:#d0d7de;text-decoration:none;font-size:.85em}
.topnav a:hover{color:#fff;text-decoration:underline}
.nav-brand{font-weight:700;margin-right:8px}
main{padding:24px;max-width:1600px;margin:0 auto}
h1{font-size:1.6em;margin-bottom:4px}
h2{font-size:1.15em;margin:32px 0 10px;border-bottom:1px solid var(--border);
   padding-bottom:6px;scroll-margin-top:60px}
h3{font-size:.95em;margin:18px 0 8px;color:var(--muted)}
.meta{color:var(--muted);font-size:.85em;margin-bottom:18px;line-height:1.7}
.hint{color:var(--muted);font-size:.82em;margin:-4px 0 10px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;
      padding:14px 18px;min-width:150px;flex:1 1 150px}
.card-value{font-size:1.7em;font-weight:700;line-height:1.15}
.card-label{color:var(--muted);font-size:.8em;margin-top:4px}
.card.bad .card-value{color:#cf222e}
.card.good .card-value{color:#2da44e}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;
       padding:16px 18px;margin-bottom:16px}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;font-size:.88em}
.kv dt{color:var(--muted)}
.kv dd{font-weight:500;word-break:break-word}
.tbl-wrap{overflow-x:auto;margin-bottom:8px;border:1px solid var(--border);
          border-radius:8px;background:var(--panel);max-height:720px;overflow-y:auto}
table.data{width:100%;border-collapse:collapse}
table.data thead tr{background:var(--head)}
table.data thead th{position:sticky;top:0;background:var(--head);z-index:1;
                    cursor:pointer;user-select:none}
table.data tr.filter-row th{top:33px;padding:3px 6px}
table.data tr.filter-row input{width:100%;font:inherit;font-size:.85em;padding:3px 6px;
                               border:1px solid var(--border);border-radius:4px;
                               background:#fff;cursor:text}
th,td{padding:7px 12px;text-align:left;border-bottom:1px solid var(--border);
      white-space:nowrap;vertical-align:top}
td.wrap{white-space:normal;min-width:280px}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:#f0f3f6}
th.sort-asc::after{content:" \\2191"}
th.sort-desc::after{content:" \\2193"}
.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:1px 8px;border-radius:12px;font-size:.78em;
       font-weight:600;white-space:nowrap}
.bar-wrap{display:flex;align-items:center;gap:8px;min-width:130px}
.bar-track{flex:1;height:8px;background:var(--head);border-radius:4px;overflow:hidden}
.bar{height:8px;border-radius:4px}
.bar-label{font-size:.78em;color:var(--muted);min-width:44px;text-align:right}
.stack{display:flex;height:26px;border-radius:6px;overflow:hidden;
       border:1px solid var(--border);margin-bottom:8px}
.stack div{height:100%}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:.82em;color:var(--muted)}
.legend span.dot{display:inline-block;width:10px;height:10px;border-radius:3px;
                 margin-right:5px;vertical-align:middle}
.empty{color:var(--muted);font-size:.88em;padding:10px 0 18px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}
details.log summary{cursor:pointer;color:var(--accent);font-size:.82em}
details.log pre{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;
                border:1px solid var(--border);border-radius:6px;padding:8px;
                margin-top:6px;font-size:.78em;max-width:900px;max-height:260px;
                overflow:auto}
.chart-wrap{position:relative;height:360px;background:var(--panel);
            border:1px solid var(--border);border-radius:8px;padding:12px;
            margin-bottom:12px}
.toggles{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:10px;font-size:.8em}
.toggles label{cursor:pointer}
"""

FILTER_JS = """
(function(){
  document.querySelectorAll('table.filterable').forEach(function(tbl){
    var inputs=Array.from(tbl.querySelectorAll('tr.filter-row input'));
    var headers=Array.from(tbl.querySelectorAll('thead tr:first-child th'));
    var sortCol=-1,sortAsc=true;
    function applyFilter(){
      Array.from(tbl.querySelectorAll('tbody tr')).forEach(function(row){
        var show=true;
        inputs.forEach(function(inp,i){
          var v=inp.value.trim().toLowerCase();
          if(!v)return;
          var c=row.cells[i];
          if(!c||c.textContent.toLowerCase().indexOf(v)===-1)show=false;
        });
        row.style.display=show?'':'none';
      });
    }
    function num(s){var n=parseFloat(s.replace(/[^0-9.eE+-]/g,''));return isNaN(n)?null:n;}
    function applySort(){
      if(sortCol<0)return;
      var body=tbl.querySelector('tbody');
      var rows=Array.from(body.querySelectorAll('tr'));
      rows.sort(function(a,b){
        var av=(a.cells[sortCol]||{}).textContent||'';
        var bv=(b.cells[sortCol]||{}).textContent||'';
        var an=num(av),bn=num(bv);
        var cmp=(an!==null&&bn!==null)?an-bn:av.trim().localeCompare(bv.trim());
        return sortAsc?cmp:-cmp;
      });
      rows.forEach(function(r){body.appendChild(r);});
    }
    inputs.forEach(function(inp){
      inp.addEventListener('input',applyFilter);
      inp.addEventListener('click',function(e){e.stopPropagation();});
    });
    headers.forEach(function(th,i){
      th.addEventListener('click',function(){
        if(sortCol===i){sortAsc=!sortAsc;}else{sortCol=i;sortAsc=true;}
        headers.forEach(function(h){h.classList.remove('sort-asc','sort-desc');});
        th.classList.add(sortAsc?'sort-asc':'sort-desc');
        applySort();
      });
    });
  });
})();
"""


# ---------------------------------------------------------------------------
# Trend history
# ---------------------------------------------------------------------------

TREND_METRICS = [
    ("failures",         "Build failures",     "#cf222e", True),
    ("platforms_failing", "Platforms failing", "#a40e26", True),
    ("tests_failing",    "Tests failing",      "#bf8700", True),
    ("jobs_failed",      "CI jobs failed",     "#d4a72c", True),
    ("attempted",        "Suites built",       "#0969da", False),
    ("total",            "Suites total",       "#2c3e50", False),
    ("not_run",          "Built, not run",     "#6e7781", False),
    ("filtered_skipped", "Filtered / skipped", "#9a6700", False),
    ("platforms",        "Platforms covered",  "#1f883d", False),
    ("build_hours",      "Build CPU hours",    "#8250df", False),
    ("run_minutes",      "Run wall time (min)", "#bc4c00", False),
]


def build_snapshot(agg: Aggregate, run: dict, jobs: list[dict],
                   generated: str) -> dict:
    env = agg.environment or {}
    jrows = job_rows(jobs)
    return {
        "generated": generated,
        "run_id": run.get("id"),
        "run_date": run.get("run_started_at") or run.get("created_at"),
        "run_url": run.get("html_url", ""),
        "zephyr_version": env.get("zephyr_version", ""),
        "commit": (run.get("head_sha") or "")[:12],
        "total": agg.total,
        "attempted": agg.attempted,
        "failures": agg.failures_count,
        "error": agg.status["error"],
        "failed": agg.status["failed"],
        "passed": agg.status["passed"],
        "not_run": agg.status["not run"],
        "filtered_skipped": agg.status["filtered"] + agg.status["skipped"],
        "platforms": len(agg.platforms),
        "platforms_failing": sum(
            1 for c in agg.platforms.values()
            if sum(c[s] for s in FAILURE_STATUSES)),
        "tests": len(agg.tests),
        "tests_failing": sum(
            1 for c in agg.tests.values()
            if sum(c[s] for s in FAILURE_STATUSES)),
        "build_hours": round(agg.build_time_total / 3600.0, 1),
        "run_minutes": round(run_duration_seconds(run) / 60.0, 1),
        "jobs_failed": sum(1 for j in jrows if j["conclusion"] == "failure"),
        "jobs": len(jrows),
        "conclusion": run.get("conclusion", ""),
    }


def load_history(path: str | None) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log(f"WARNING: could not read history {path}: {exc}", True)
        return []
    snaps = data.get("snapshots", data) if isinstance(data, dict) else data
    return snaps if isinstance(snaps, list) else []


def merge_history(history: list[dict], snapshot: dict) -> list[dict]:
    """Return history with *snapshot* added, replacing any entry for the run."""
    merged = [s for s in history if s.get("run_id") != snapshot.get("run_id")]
    merged.append(snapshot)
    merged.sort(key=lambda s: str(s.get("run_date") or s.get("generated") or ""))
    return merged


def save_history(path: str | None, snapshots: list[dict]) -> None:
    if not path:
        return
    try:
        with open(path, "w") as fh:
            json.dump(snapshots, fh, indent=1, default=str)
        log(f"History written to {path} ({len(snapshots)} runs)", True)
    except OSError as exc:
        log(f"WARNING: could not write history {path}: {exc}", True)


def _delta(current, prev, lower_is_better: bool = True) -> str:
    if prev is None or current is None:
        return ""
    try:
        diff = float(current) - float(prev)
    except (TypeError, ValueError):
        return ""
    if abs(diff) < 1e-9:
        return '<span class="d-flat">&nbsp;=</span>'
    good = diff < 0 if lower_is_better else diff > 0
    color = "#2da44e" if good else "#cf222e"
    arrow = "▼" if diff < 0 else "▲"
    label = f"{abs(diff):,.0f}" if abs(diff) >= 1 else f"{abs(diff):.1f}"
    return (f'<span style="color:{color};font-size:.78em;margin-left:5px">'
            f'{arrow}&nbsp;{label}</span>')


def trend_chart_html() -> str:
    toggles = "".join(
        f'<label><input type="checkbox" data-metric="{key}"'
        f'{" checked" if on else ""} style="accent-color:{color};margin-right:4px">'
        f'<span style="color:{color}">{esc(label)}</span></label>'
        for key, label, color, on in TREND_METRICS
    )
    return (
        '<h2 id="trend">Trend Across Weekly Runs</h2>\n'
        '<p class="hint">One point per saved run. Toggle series below; '
        'volume metrics start hidden because they dwarf the failure counts.</p>\n'
        f'<div class="toggles">{toggles}</div>\n'
        '<div class="chart-wrap"><canvas id="trend-chart"></canvas></div>\n'
    )


def trend_chart_js() -> str:
    metrics = json.dumps([
        {"key": k, "label": l, "color": c, "on": on}
        for k, l, c, on in TREND_METRICS
    ])
    return """
if (HISTORY.length >= 2 && document.getElementById('trend-chart')) {
  const METRICS = __METRICS__;
  const labels = HISTORY.map(r => String(r.run_date || r.generated || '').slice(0, 10));
  const datasets = METRICS.map(m => ({
    label: m.label,
    data: HISTORY.map(r => (r[m.key] != null ? r[m.key] : null)),
    borderColor: m.color,
    backgroundColor: m.color + '33',
    borderWidth: 2, tension: 0.3, pointRadius: 3, hidden: !m.on,
  }));
  const chart = new Chart(document.getElementById('trend-chart').getContext('2d'), {
    type: 'line',
    data: { labels: labels, datasets: datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { maxRotation: 45, font: { size: 10 } } },
                y: { beginAtZero: true } },
    },
  });
  document.querySelectorAll('.toggles input[data-metric]').forEach(function(cb){
    cb.addEventListener('change', function(){
      const i = METRICS.findIndex(m => m.key === cb.dataset.metric);
      if (i >= 0) { chart.setDatasetVisibility(i, cb.checked); chart.update(); }
    });
  });
}
""".replace("__METRICS__", metrics)


TREND_COLUMNS = [
    ("Run date",     "run_date",          None),
    ("Zephyr",       "zephyr_version",    None),
    ("Suites built", "attempted",         None),
    ("Failures",     "failures",          True),
    ("Platforms failing", "platforms_failing", True),
    ("Tests failing", "tests_failing",    True),
    ("Built, not run", "not_run",         None),
    ("CI jobs failed", "jobs_failed",     True),
    ("Wall time (min)", "run_minutes",    True),
]


def trend_table_html(history: list[dict], limit: int = 10) -> str:
    if len(history) < 2:
        return ('<p class="empty">The trend table appears once two or more runs '
                'have been recorded in the history file.</p>')
    head = "".join(f"<th>{esc(c[0])}</th>" for c in TREND_COLUMNS)
    rows = []
    first = max(0, len(history) - limit) if limit else 0
    for i in range(len(history) - 1, first - 1, -1):
        snap = history[i]
        prev = history[i - 1] if i > 0 else None
        cells = []
        for _, key, lower_better in TREND_COLUMNS:
            val = snap.get(key, "")
            if key == "run_date":
                text = esc(fmt_dt(val).replace(" UTC", ""))
                url = snap.get("run_url")
                cells.append(f'<td><a href="{esc(url)}">{text}</a></td>'
                             if url else f"<td>{text}</td>")
                continue
            if lower_better is None:
                cells.append(f'<td class="num">{fmt_int(val) if isinstance(val, (int, float)) else esc(val)}</td>')
            else:
                d = _delta(val, prev.get(key) if prev else None, lower_better)
                cells.append(f'<td class="num">{fmt_int(val)}{d}</td>')
        rows.append(f"<tr>{''.join(cells)}</tr>")
    return (f'<div class="tbl-wrap"><table class="data">'
            f'<thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody>'
            f'</table></div>')


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _cards(agg: Aggregate, run: dict, jrows: list[dict]) -> str:
    failed_jobs = sum(1 for j in jrows if j["conclusion"] == "failure")
    platforms_failing = sum(
        1 for c in agg.platforms.values() if sum(c[s] for s in FAILURE_STATUSES))
    tests_failing = sum(
        1 for c in agg.tests.values() if sum(c[s] for s in FAILURE_STATUSES))
    cards = [
        (fmt_int(agg.total), "Test Instances", ""),
        (fmt_int(agg.attempted), "Built", ""),
        (fmt_int(agg.failures_count), "Build Failures",
         "bad" if agg.failures_count else "good"),
        (f"{agg.build_success_rate:.2f}%", "Build Success Rate",
         "good" if agg.build_success_rate >= 99.9 else ""),
        (fmt_int(platforms_failing), "Platforms Failing",
         "bad" if platforms_failing else "good"),
        (fmt_int(tests_failing), "Tests Failing",
         "bad" if tests_failing else "good"),
        (fmt_int(len(agg.platforms)), "Platforms Covered", ""),
        (fmt_int(len(agg.tests)), "Distinct Tests", ""),
        (fmt_duration(run_duration_seconds(run)), "Run Wall Time", ""),
        (f"{agg.build_time_total / 3600:,.0f}h", "Build CPU Time", ""),
        (f"{failed_jobs}/{len(jrows)}", "CI Jobs Failed",
         "bad" if failed_jobs else "good"),
    ]
    return '<div class="cards">' + "".join(
        f'<div class="card {cls}"><div class="card-value">{v}</div>'
        f'<div class="card-label">{esc(l)}</div></div>'
        for v, l, cls in cards) + "</div>"


def _run_panel(agg: Aggregate, run: dict, jrows: list[dict], repo: str,
               workflow: str, n_artifacts: int) -> str:
    env = agg.environment or {}
    opts = env.get("options") or {}
    sha = run.get("head_sha") or ""
    concl = Counter(j["conclusion"] for j in jrows)
    concl_html = " ".join(f"{conclusion_badge(c)}&nbsp;{fmt_int(n)}"
                          for c, n in concl.most_common()) or "–"
    opt_bits = []
    for key, label in (("build_only", "build only"), ("all", "all platforms"),
                       ("report_filtered", "report filtered"),
                       ("retry_failed", "retries"),
                       ("timeout_multiplier", "timeout x"),
                       ("test_config", "config"), ("jobs", "jobs/runner")):
        if key in opts:
            opt_bits.append(f"{label}: <b>{esc(opts[key])}</b>")
    items = []
    if run.get("id"):
        items += [
            ("Workflow", f'<a href="{esc(run.get("html_url", ""))}">{esc(workflow)} '
                         f'#{esc(run.get("run_number", ""))}</a> '
                         f'(run {esc(run["id"])}, attempt '
                         f'{esc(run.get("run_attempt", 1))})'),
            ("Conclusion", conclusion_badge(run.get("conclusion") or "unknown")),
            ("Triggered by", f'{esc(run.get("event", ""))} on '
                             f'<b>{esc(run.get("head_branch", ""))}</b>'),
        ]
    if sha:
        items.append(
            ("Commit", f'<a href="https://github.com/{esc(repo)}/commit/{esc(sha)}">'
                       f'<span class="mono">{esc(sha[:12])}</span></a> — '
                       f'{esc(run.get("display_title", ""))}'))
    items += [
        ("Zephyr version", f'<span class="mono">{esc(env.get("zephyr_version", "–"))}</span>'),
        ("Toolchain", esc(env.get("toolchain", "–"))),
        ("Commit date", fmt_dt(env.get("commit_date"))),
        ("Twister run date", fmt_dt(env.get("run_date"))),
    ]
    if run.get("id"):
        items += [
            ("CI started", fmt_dt(run.get("run_started_at") or run.get("created_at"))),
            ("CI finished", fmt_dt(run.get("updated_at"))),
            ("Wall time", fmt_duration(run_duration_seconds(run))),
            ("CI jobs", concl_html),
        ]
    items += [
        ("Result artifacts", f"{fmt_int(n_artifacts)} parsed, "
                             f"{fmt_int(len(agg.subsets))} twister subsets"),
        ("Twister options", ", ".join(opt_bits) or "–"),
    ]
    rows = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in items)
    return f'<div class="panel"><dl class="kv">{rows}</dl></div>'


def _status_section(agg: Aggregate) -> str:
    total = max(1, agg.total)
    segments, legend = [], []
    for status in SUITE_STATUSES:
        count = agg.status.get(status, 0)
        if not count:
            continue
        pct = 100.0 * count / total
        color = STATUS_COLOR[status]
        segments.append(
            f'<div style="width:{pct:.3f}%;background:{color}" '
            f'title="{esc(status)}: {fmt_int(count)} ({pct:.2f}%)"></div>')
        legend.append(f'<span><span class="dot" style="background:{color}"></span>'
                      f'{esc(status)} — {fmt_int(count)} ({pct:.2f}%)</span>')
    rows = []
    for status in SUITE_STATUSES:
        count = agg.status.get(status, 0)
        cases = agg.case_status.get(status, 0)
        rows.append(
            f"<tr><td>{status_badge(status)}</td>"
            f'<td class="num">{fmt_int(count)}</td>'
            f'<td class="num">{100.0 * count / total:.2f}%</td>'
            f'<td class="num">{fmt_int(cases)}</td>'
            f'<td class="wrap">{esc(STATUS_DESC.get(status, ""))}</td></tr>')
    status_rows = "".join(rows)
    return (
        '<h2 id="status">Result Breakdown</h2>\n'
        f'<div class="stack">{"".join(segments)}</div>\n'
        f'<div class="legend">{"".join(legend)}</div>\n'
        '<p class="hint">This is a build-only run of the whole tree, so most '
        'instances end as <i>not run</i> (built, never executed) or '
        '<i>filtered</i> (not applicable to the platform). Build failures are '
        'the <i>error</i> and <i>failed</i> rows.</p>'
        f'<div class="tbl-wrap"><table class="data"><thead><tr>'
        f"<th>Status</th><th>Instances</th><th>Share</th><th>Test cases</th>"
        f"<th>Meaning</th></tr></thead><tbody>{status_rows}</tbody></table></div>"
    )


def _platform_section(agg: Aggregate, limit: int) -> str:
    rows_data = agg.failing_platforms()
    rows = []
    for r in rows_data[:limit]:
        rows.append(
            f'<tr><td class="mono">{esc(r["platform"])}</td>'
            f'<td>{esc(r["arch"])}</td>'
            f'<td class="num">{fmt_int(r["failures"])}</td>'
            f'<td class="num">{fmt_int(r["error"])}</td>'
            f'<td class="num">{fmt_int(r["failed"])}</td>'
            f'<td class="num">{fmt_int(r["attempted"])}</td>'
            f'<td>{pct_bar(r["rate"], "#cf222e")}</td></tr>')
    note = ""
    if len(rows_data) > limit:
        note = (f'<p class="hint">Showing the worst {limit} of '
                f'{len(rows_data)} failing platforms.</p>')
    return (
        '<h2 id="platforms">Platforms With Failures</h2>\n'
        f'<p class="hint">{fmt_int(len(rows_data))} of '
        f'{fmt_int(len(agg.platforms))} platforms had at least one build '
        'failure. Click a header to sort, type in a box to filter.</p>\n'
        + table(["Platform", "Arch", "Failures", "Error", "Failed",
                 "Built", "Failure rate"], rows,
                empty="No platform reported a build failure.")
        + note)


def _test_section(agg: Aggregate, limit: int) -> str:
    rows_data = agg.failing_tests()
    rows = []
    for r in rows_data[:limit]:
        plats = ", ".join(r["platforms"])
        if r["truncated"]:
            plats += ", …"
        rows.append(
            f'<tr><td class="mono">{esc(r["name"])}</td>'
            f'<td class="mono">{esc(r["path"])}</td>'
            f'<td class="num">{fmt_int(r["failures"])}</td>'
            f'<td class="num">{fmt_int(r["error"])}</td>'
            f'<td class="num">{fmt_int(r["failed"])}</td>'
            f'<td class="num">{fmt_int(r["total"])}</td>'
            f'<td class="wrap mono">{esc(plats)}</td></tr>')
    note = ""
    if len(rows_data) > limit:
        note = (f'<p class="hint">Showing the worst {limit} of '
                f'{len(rows_data)} failing tests.</p>')
    return (
        '<h2 id="tests">Tests With Failures</h2>\n'
        f'<p class="hint">{fmt_int(len(rows_data))} of '
        f'{fmt_int(len(agg.tests))} distinct test suites failed on at least one '
        'platform. "Instances" is how many platform variants of the test ran.</p>\n'
        + table(["Test", "Path", "Failures", "Error", "Failed", "Instances",
                 "Failing platforms"], rows,
                empty="No test reported a build failure.")
        + note)


def _reason_section(agg: Aggregate, limit: int) -> str:
    rows_data = agg.reason_rows()
    total = max(1, agg.failures_count)
    rows = [
        f'<tr><td class="wrap mono">{esc(r["reason"])}</td>'
        f'<td class="num">{fmt_int(r["count"])}</td>'
        f'<td class="num">{fmt_int(r["tests"])}</td>'
        f'<td>{pct_bar(100.0 * r["count"] / total, "#bf8700")}</td></tr>'
        for r in rows_data[:limit]
    ]
    return (
        '<h2 id="reasons">Failure Reasons</h2>\n'
        '<p class="hint">Reasons as reported by twister, with paths and '
        'addresses folded so similar failures group together.</p>\n'
        + table(["Reason", "Occurrences", "Distinct tests", "Share of failures"],
                rows, empty="No failures to group."))


def _details_section(agg: Aggregate, limit: int) -> str:
    failures = sorted(agg.failures,
                      key=lambda f: (f["platform"], f["name"]))
    rows = []
    for f in failures[:limit]:
        excerpt = ""
        if f["excerpt"]:
            excerpt = ('<details class="log"><summary>log</summary>'
                       f'<pre>{esc(f["excerpt"])}</pre></details>')
        rows.append(
            f'<tr><td class="mono">{esc(f["platform"])}</td>'
            f'<td class="mono">{esc(f["name"])}</td>'
            f'<td>{status_badge(f["status"])}</td>'
            f'<td class="wrap mono">{esc(f["raw_reason"] or f["reason"])}'
            f'{excerpt}</td>'
            f'<td class="num">{f["build_time"]:.0f}s</td>'
            f'<td class="num">{f["retries"]}</td></tr>')
    note = ""
    if len(failures) > limit:
        note = (f'<p class="hint">Showing {limit} of {fmt_int(len(failures))} '
                'failures; raise --max-failures for the rest.</p>')
    return (
        '<h2 id="details">Failure Details</h2>\n'
        '<p class="hint">Every failing test instance, with the tail of its '
        'build log. Filter by platform or test to narrow it down.</p>\n'
        + table(["Platform", "Test", "Status", "Reason", "Build", "Retries"],
                rows, empty="No failing test instances.")
        + note)


def _breakdown_section(agg: Aggregate) -> str:
    def rows_for(data: dict, label: str) -> str:
        rows = []
        for r in agg.key_rows(data, label):
            rows.append(
                f'<tr><td class="mono">{esc(r[label])}</td>'
                f'<td class="num">{fmt_int(r["total"])}</td>'
                f'<td class="num">{fmt_int(r["attempted"])}</td>'
                f'<td class="num">{fmt_int(r["failures"])}</td>'
                f'<td class="num">{fmt_int(r["not_run"])}</td>'
                f'<td class="num">{fmt_int(r["filtered"])}</td>'
                f'<td>{pct_bar(r["rate"], "#cf222e")}</td></tr>')
        return table([label.title(), "Instances", "Built", "Failures",
                      "Not run", "Filtered/skipped", "Failure rate"], rows)

    return (
        '<h2 id="arch">By Architecture and Toolchain</h2>\n'
        + rows_for(agg.archs, "arch")
        + '<h3>Toolchains</h3>'
        + rows_for(agg.toolchains, "toolchain"))


def _timing_section(agg: Aggregate, limit: int) -> str:
    avg = agg.build_time_total / agg.build_time_count if agg.build_time_count else 0
    slow_rows = [
        f'<tr><td class="mono">{esc(name)}</td>'
        f'<td class="mono">{esc(platform)}</td>'
        f'<td class="num">{secs:,.1f}s</td></tr>'
        for secs, name, platform in agg.slowest
    ]
    plat_rows_data = sorted(
        ((p, c["build_seconds"], c["total"]) for p, c in agg.platforms.items()),
        key=lambda t: -t[1])[:limit]
    plat_rows = [
        f'<tr><td class="mono">{esc(p)}</td>'
        f'<td class="num">{secs / 3600:,.2f}h</td>'
        f'<td class="num">{fmt_int(total)}</td>'
        f'<td class="num">{secs / total if total else 0:,.1f}s</td></tr>'
        for p, secs, total in plat_rows_data
    ]
    return (
        '<h2 id="timing">Build Time</h2>\n'
        f'<p class="hint">{fmt_int(agg.build_time_count)} timed builds, '
        f'{agg.build_time_total / 3600:,.1f} CPU hours in total, '
        f'{avg:,.1f}s on average. {fmt_int(agg.suites_retried)} instances were '
        f'retried ({fmt_int(agg.retries_total)} retries).</p>\n'
        '<h3>Slowest single builds</h3>'
        + table(["Test", "Platform", "Build time"], slow_rows, filterable=False)
        + f'<h3>Platforms by total build time (top {limit})</h3>'
        + table(["Platform", "Build time", "Instances", "Average"], plat_rows))


def _jobs_section(jrows: list[dict], limit: int) -> str:
    failed = [j for j in jrows if j["conclusion"] not in ("success", "skipped")]
    failed.sort(key=lambda j: j["name"])
    failed_rows = [
        f'<tr><td class="mono"><a href="{esc(j["url"])}">{esc(j["name"])}</a></td>'
        f'<td>{conclusion_badge(j["conclusion"])}</td>'
        f'<td class="num">{fmt_duration(j["duration"])}</td></tr>'
        for j in failed
    ]
    slow = sorted(jrows, key=lambda j: -j["duration"])[:limit]
    slow_rows = [
        f'<tr><td class="mono"><a href="{esc(j["url"])}">{esc(j["name"])}</a></td>'
        f'<td>{conclusion_badge(j["conclusion"])}</td>'
        f'<td class="num">{fmt_duration(j["duration"])}</td></tr>'
        for j in slow
    ]
    if not jrows:
        return ('<h2 id="jobs">CI Jobs</h2>'
                '<p class="empty">Job data was not available for this run.</p>')
    total_min = sum(j["duration"] for j in jrows) / 60.0
    return (
        '<h2 id="jobs">CI Jobs</h2>\n'
        f'<p class="hint">{fmt_int(len(jrows))} jobs, '
        f'{total_min / 60:,.1f} machine hours, '
        f'{fmt_int(len(failed))} not successful.</p>\n'
        '<h3>Jobs that did not succeed</h3>'
        + table(["Job", "Conclusion", "Duration"], failed_rows,
                empty="Every job succeeded.")
        + f'<h3>Longest jobs (top {limit})</h3>'
        + table(["Job", "Conclusion", "Duration"], slow_rows, filterable=False))


def _all_platforms_section(agg: Aggregate) -> str:
    rows = []
    for r in agg.key_rows(agg.platforms, "platform"):
        rows.append(
            f'<tr><td class="mono">{esc(r["platform"])}</td>'
            f'<td>{esc(agg.platform_arch.get(r["platform"], ""))}</td>'
            f'<td class="num">{fmt_int(r["total"])}</td>'
            f'<td class="num">{fmt_int(r["attempted"])}</td>'
            f'<td class="num">{fmt_int(r["failures"])}</td>'
            f'<td class="num">{fmt_int(r["not_run"])}</td>'
            f'<td class="num">{fmt_int(r["passed"])}</td>'
            f'<td class="num">{fmt_int(r["filtered"])}</td></tr>')
    return (
        '<h2 id="all-platforms">All Platforms</h2>\n'
        '<p class="hint">Every platform seen in the run, sorted by failures '
        'then size. Sortable and filterable.</p>\n'
        + table(["Platform", "Arch", "Instances", "Built", "Failures",
                 "Not run", "Passed", "Filtered/skipped"], rows))


NAV = [
    ("#summary", "Summary"), ("#run", "Run"), ("#status", "Results"),
    ("#trend", "Trend"), ("#platforms", "Platforms"), ("#tests", "Tests"),
    ("#reasons", "Reasons"), ("#details", "Failures"), ("#arch", "Arch"),
    ("#timing", "Build time"), ("#jobs", "CI jobs"),
    ("#all-platforms", "All platforms"),
]


def render_html(agg: Aggregate, run: dict, jobs: list[dict], repo: str,
                workflow: str, generated: str, history: list[dict],
                n_artifacts: int, title: str, max_rows: int,
                max_failures: int) -> str:
    jrows = job_rows(jobs)
    env = agg.environment or {}
    nav = "".join(f'<a href="{href}">{esc(label)}</a>' for href, label in NAV)

    has_trend = len(history) >= 2
    trend = (trend_chart_html() + trend_table_html(history)) if has_trend else (
        '<h2 id="trend">Trend Across Weekly Runs</h2>'
        '<p class="empty">Pass --history FILE to record one snapshot per run; '
        'the chart and table appear from the second run onwards.</p>')

    body = "\n".join([
        _cards(agg, run, jrows),
        '<h2 id="run">Run Details</h2>',
        _run_panel(agg, run, jrows, repo, workflow, n_artifacts),
        _status_section(agg),
        trend,
        _platform_section(agg, max_rows),
        _test_section(agg, max_rows),
        _reason_section(agg, max_rows),
        _details_section(agg, max_failures),
        _breakdown_section(agg),
        _timing_section(agg, max_rows),
        _jobs_section(jrows, 25),
        _all_platforms_section(agg),
    ])

    scripts = [f"const HISTORY = {json.dumps(history, default=str)};"]
    chart_cdn = ""
    if has_trend:
        chart_cdn = ('<script src="https://cdn.jsdelivr.net/npm/chart.js@4/'
                     'dist/chart.umd.min.js"></script>')
        scripts.append(trend_chart_js())
    scripts.append(FILTER_JS)

    meta = (
        f'Repository <a href="https://github.com/{esc(repo)}">{esc(repo)}</a> '
        f'&nbsp;|&nbsp; workflow <a href="{esc(run.get("html_url", ""))}">'
        f'{esc(workflow)}</a> ({esc(run.get("event", ""))}) '
        f'&nbsp;|&nbsp; Zephyr <span class="mono">'
        f'{esc(env.get("zephyr_version", "unknown"))}</span><br>'
        f'Run started {fmt_dt(run.get("run_started_at") or run.get("created_at"))} '
        f'&nbsp;|&nbsp; report generated {esc(generated)}'
    )

    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{esc(title)}</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body>\n"
        f'<nav class="topnav"><span class="nav-brand">Weekly Build</span>{nav}</nav>\n'
        f'<main>\n<h1 id="summary">{esc(title)}</h1>\n'
        f'<p class="meta">{meta}</p>\n'
        f"{body}\n</main>\n"
        f"{chart_cdn}\n<script>\n" + "\n".join(scripts) + "\n</script>\n"
        "</body>\n</html>\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=DEFAULT_REPO,
                   help=f"owner/name to read runs from (default: {DEFAULT_REPO})")
    p.add_argument("--workflow", default=DEFAULT_WORKFLOW,
                   help=f"workflow file name (default: {DEFAULT_WORKFLOW})")
    p.add_argument("--event", default=DEFAULT_EVENT,
                   help=f"run trigger to select (default: {DEFAULT_EVENT})")
    p.add_argument("--branch", default="main",
                   help="branch filter for run selection (default: main)")
    p.add_argument("--run-id", type=int, default=None,
                   help="report on this run instead of the most recent one")
    p.add_argument("--artifact-pattern", default=DEFAULT_PATTERN,
                   help="regex matching the result artifacts to download")
    p.add_argument("--artifacts-dir", nargs="*", default=None, metavar="PATH",
                   help="use already-downloaded artifacts (directories, "
                        "twister.json files or zips) instead of the API")
    p.add_argument("--output", "-o", default="weekly_build.html",
                   help="HTML output path (default: weekly_build.html)")
    p.add_argument("--json", dest="json_out", default=None,
                   help="also write the run snapshot as JSON to this path")
    p.add_argument("--history", default=None,
                   help="JSON file used to persist one snapshot per run")
    p.add_argument("--cache-dir", default=None,
                   help="directory to cache downloaded artifact zips in")
    p.add_argument("--jobs", "-j", type=int, default=8,
                   help="parallel artifact downloads (default: 8)")
    p.add_argument("--max-artifacts", type=int, default=0,
                   help="stop after this many artifacts (0 = all; for testing)")
    p.add_argument("--max-rows", type=int, default=300,
                   help="row cap for the ranked tables (default: 300)")
    p.add_argument("--max-failures", type=int, default=2000,
                   help="row cap for the failure detail table (default: 2000)")
    p.add_argument("--title", default="Zephyr Weekly Build CI Dashboard",
                   help="report title")
    p.add_argument("--token", default=None,
                   help="GitHub token (default: $GITHUB_TOKEN, $GH_TOKEN or gh CLI)")
    p.add_argument("--verbose", "-v", action="store_true", help="progress output")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    agg = Aggregate()
    started = time.time()

    if args.artifacts_dir:
        run = {"id": args.run_id or 0, "conclusion": "", "event": args.event,
               "head_branch": args.branch}
        jobs: list[dict] = []
        sources = 0
        for source, doc in iter_local_results(args.artifacts_dir):
            n = agg.add_document(source, doc)
            sources += 1
            log(f"  {source}: {n} test instances", args.verbose)
        n_artifacts = sources
    else:
        token = resolve_token(args.token)
        if not token:
            log("WARNING: no GitHub token found; the API will rate-limit quickly "
                "and private artifacts will not download.", True)
        gh = GitHub(token, args.verbose)
        run = find_run(gh, args.repo, args.workflow, args.event, args.branch,
                       args.run_id, args.verbose)
        log(f"Run {run['id']} ({run.get('conclusion')}) started "
            f"{run.get('run_started_at')}", True)
        jobs = fetch_jobs(gh, args.repo, run["id"], args.verbose)
        artifacts = select_artifacts(gh, args.repo, run["id"],
                                     args.artifact_pattern, args.verbose)
        if args.max_artifacts:
            artifacts = artifacts[:args.max_artifacts]
        if not artifacts:
            raise SystemExit(
                f"No artifacts on run {run['id']} match "
                f"{args.artifact_pattern!r} (they may have expired)")
        cache = Path(args.cache_dir) if args.cache_dir else None
        log(f"Downloading {len(artifacts)} artifacts with {args.jobs} workers", True)
        for source, doc in iter_remote_results(gh, artifacts, args.jobs, cache,
                                               run["id"], args.verbose):
            agg.add_document(source, doc)
        n_artifacts = len(artifacts)

    if not agg.total:
        raise SystemExit("No test instances were parsed; nothing to report.")

    log(f"Parsed {agg.total:,} test instances from {n_artifacts} artifacts "
        f"in {time.time() - started:.0f}s", True)
    log(f"  {agg.failures_count:,} failures across "
        f"{len(agg.platforms):,} platforms", True)

    snapshot = build_snapshot(agg, run, jobs, generated)
    history = merge_history(load_history(args.history), snapshot)

    report = render_html(agg, run, jobs, args.repo, args.workflow, generated,
                         history, n_artifacts, args.title, args.max_rows,
                         args.max_failures)
    Path(args.output).write_text(report, encoding="utf-8")
    log(f"Wrote {args.output} ({len(report) / 1024:.0f} KB)", True)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(snapshot, indent=1, default=str), encoding="utf-8")
        log(f"Wrote {args.json_out}", True)

    save_history(args.history, history)
    return 0


if __name__ == "__main__":
    sys.exit(main())
