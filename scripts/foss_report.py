#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright The Zephyr Project Contributors
# SPDX-License-Identifier: Apache-2.0
"""
FOSSology scan results analyzer.

Reads the artifacts produced by a FOSSology CI run from a given directory
(default: spdx/) and writes a comprehensive license / copyright / compliance
report to stdout (plain text) and, optionally, to a Markdown file.

Artifacts expected in the input directory:
  sbom_spdx.json   – SPDX 2.3 SBOM produced by FOSSology
  licenses.txt     – FOSSology non-allowlisted-license report
  copyrights.txt   – FOSSology copyright-violation report
  keywords.txt     – FOSSology keyword-violation report

Usage:
  python3 scripts/foss_report.py [--spdx-dir DIR] [--output FILE] [--json FILE]
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pct(part: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{100.0 * part / total:.1f}%"


def _bar(count: int, total: int, width: int = 30) -> str:
    filled = int(width * count / total) if total else 0
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _is_spdx_ref(lic: str) -> bool:
    return lic.startswith("LicenseRef-")


def _dir_of(filename: str) -> str:
    """Return the top-level directory component of a file path."""
    parts = Path(filename).parts
    return parts[0] if parts else "(root)"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_spdx(path: Path) -> dict:
    """Load and return the SPDX JSON document."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def parse_violation_file(path: Path) -> dict:
    """
    Parse a FOSSology plain-text violation report (licenses.txt / copyrights.txt
    / keywords.txt).

    Returns a dict:
        {
          "summary_line": str,          # first non-blank line
          "violations": [               # list of dicts
              { "file": str, "findings": [ str, ... ] }
          ]
        }
    """
    result = {"summary_line": "", "violations": []}
    if not path.exists():
        return result

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return result

    result["summary_line"] = lines[0].strip()

    current_file = None
    current_findings = []

    for line in lines[1:]:
        file_match = re.match(r"^File:\s+(.+)$", line)
        lic_match = re.match(r"^\s+(.+)\s+at lines?\s+(.+)$", line)
        alt_match = re.match(r"^Licenses?:$", line)
        copyright_match = re.match(r"^\s+(.+)$", line)

        if file_match:
            if current_file is not None:
                result["violations"].append(
                    {"file": current_file, "findings": current_findings}
                )
            current_file = file_match.group(1).strip()
            current_findings = []
        elif lic_match and current_file:
            current_findings.append(lic_match.group(0).strip())
        elif alt_match or (copyright_match and current_file
                           and not line.strip().startswith("File:")):
            stripped = line.strip()
            if stripped and not stripped.startswith("License"):
                current_findings.append(stripped)

    if current_file is not None:
        result["violations"].append(
            {"file": current_file, "findings": current_findings}
        )

    return result


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(spdx: dict) -> dict:
    """Derive all metrics from the SPDX document."""
    files = spdx.get("files", [])
    packages = spdx.get("packages", [])
    extracted_infos = spdx.get("hasExtractedLicensingInfos", [])

    total = len(files)

    # ---- license counters -------------------------------------------------
    lic_counter: Counter = Counter()
    multi_lic_files: list = []
    no_lic_files: list = []
    spdx_ref_files: list = []

    for f in files:
        lics = f.get("licenseInfoInFiles", [])
        lics = [l for l in lics if l not in ("NOASSERTION", "NONE")]
        if not lics:
            no_lic_files.append(f["fileName"])
        elif len(lics) > 1:
            multi_lic_files.append((f["fileName"], lics))
        for l in lics:
            lic_counter[l] += 1
        if any(_is_spdx_ref(l) for l in lics):
            spdx_ref_files.append((f["fileName"], [l for l in lics if _is_spdx_ref(l)]))

    # ---- copyright analysis -----------------------------------------------
    copyright_counter: Counter = Counter()
    no_copyright_files: list = []

    for f in files:
        ct = f.get("copyrightText", "NOASSERTION")
        if ct in ("NOASSERTION", "NONE", ""):
            no_copyright_files.append(f["fileName"])
        else:
            copyright_counter[ct] += 1

    # normalise copyright holders: strip year ranges, lower-case, etc.
    holder_counter: Counter = Counter()
    for raw_ct, cnt in copyright_counter.items():
        # strip common prefixes
        cleaned = re.sub(
            r"(copyright\s+(\(c\)\s+)?|\(c\)\s+)",
            "",
            raw_ct,
            flags=re.IGNORECASE,
        ).strip()
        # strip year ranges like "2020", "2020-2024", "2020, 2021"
        cleaned = re.sub(r"\b\d{4}([-,]\s*\d{4})*\b", "", cleaned).strip(" ,.-")
        holder_counter[cleaned] += cnt

    # ---- directory breakdown ----------------------------------------------
    dir_lic: dict = defaultdict(Counter)
    dir_count: Counter = Counter()

    for f in files:
        top = _dir_of(f["fileName"])
        dir_count[top] += 1
        for l in f.get("licenseInfoInFiles", []):
            if l not in ("NOASSERTION", "NONE"):
                dir_lic[top][l] += 1

    # ---- concluded vs detected mismatch -----------------------------------
    concluded_diff: list = []
    for f in files:
        concluded = f.get("licenseConcluded", "NOASSERTION")
        detected = f.get("licenseInfoInFiles", [])
        if concluded not in ("NOASSERTION", "NONE") and detected:
            if concluded not in detected:
                concluded_diff.append(
                    (f["fileName"], concluded, detected)
                )

    # ---- custom / extracted license map -----------------------------------
    custom_lic_map = {
        ei["licenseId"]: ei["name"] for ei in extracted_infos
    }

    return {
        "total_files": total,
        "total_packages": len(packages),
        "packages": packages,
        "lic_counter": lic_counter,
        "multi_lic_files": multi_lic_files,
        "no_lic_files": no_lic_files,
        "spdx_ref_files": spdx_ref_files,
        "copyright_counter": copyright_counter,
        "holder_counter": holder_counter,
        "no_copyright_files": no_copyright_files,
        "dir_lic": dir_lic,
        "dir_count": dir_count,
        "concluded_diff": concluded_diff,
        "custom_lic_map": custom_lic_map,
        "spdx_meta": {
            "spdx_version": spdx.get("spdxVersion", ""),
            "data_license": spdx.get("dataLicense", ""),
            "created": spdx.get("creationInfo", {}).get("created", ""),
            "creators": spdx.get("creationInfo", {}).get("creators", []),
            "doc_name": spdx.get("name", ""),
            "doc_namespace": spdx.get("documentNamespace", ""),
        },
    }


# ---------------------------------------------------------------------------
# Report rendering helpers
# ---------------------------------------------------------------------------

SEP_THICK = "=" * 80
SEP_THIN = "-" * 80
SEP_DASH = "- " * 40


def _section(title: str) -> str:
    return f"\n{SEP_THICK}\n  {title}\n{SEP_THICK}\n"


def _subsection(title: str) -> str:
    return f"\n{SEP_THIN}\n  {title}\n{SEP_THIN}"


# ---------------------------------------------------------------------------
# Plain-text report
# ---------------------------------------------------------------------------

def render_text(metrics: dict, lic_viol: dict, cp_viol: dict, kw_viol: dict) -> str:
    lines = []
    a = lines.append

    def section(t):
        a(_section(t))

    def subsection(t):
        a(_subsection(t))

    # ---- header -----------------------------------------------------------
    a(SEP_THICK)
    a("  FOSSology Scan Analysis Report")
    a(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    a(SEP_THICK)

    # ---- SPDX document metadata ------------------------------------------
    section("1. SPDX DOCUMENT METADATA")
    m = metrics["spdx_meta"]
    a(f"  Document name   : {m['doc_name']}")
    a(f"  SPDX version    : {m['spdx_version']}")
    a(f"  Data license    : {m['data_license']}")
    a(f"  Created         : {m['created']}")
    for c in m["creators"]:
        a(f"  Creator         : {c}")
    a(f"  Namespace       : {m['doc_namespace']}")

    # ---- packages ---------------------------------------------------------
    section("2. PACKAGES")
    for pkg in metrics["packages"]:
        a(f"  Name            : {pkg.get('name', '')}")
        a(f"  SPDX ID         : {pkg.get('SPDXID', '')}")
        a(f"  Download URL    : {pkg.get('downloadLocation', '')}")
        a(f"  Originator      : {pkg.get('originator', '')}")
        a(f"  Release date    : {pkg.get('releaseDate', '')}")
        vcode = pkg.get("packageVerificationCode", {}).get("packageVerificationCodeValue", "")
        a(f"  Verification    : {vcode}")
        lics = pkg.get("licenseInfoFromFiles", [])
        a(f"  Declared licenses ({len(lics)}):")
        for l in sorted(lics):
            a(f"    - {l}")
        a("")

    # ---- executive summary ------------------------------------------------
    section("3. EXECUTIVE SUMMARY")
    total = metrics["total_files"]
    lic_counter = metrics["lic_counter"]
    no_lic = metrics["no_lic_files"]
    no_cp = metrics["no_copyright_files"]

    a(f"  Total files analyzed           : {total:>8,}")
    a(f"  Distinct SPDX license IDs      : {len(lic_counter):>8,}")
    a(f"  Files with identified license  : {total - len(no_lic):>8,}  "
      f"({_pct(total - len(no_lic), total)})")
    a(f"  Files without license info     : {len(no_lic):>8,}  "
      f"({_pct(len(no_lic), total)})")
    a(f"  Files with identified copyright: {total - len(no_cp):>8,}  "
      f"({_pct(total - len(no_cp), total)})")
    a(f"  Files without copyright info   : {len(no_cp):>8,}  "
      f"({_pct(len(no_cp), total)})")
    a(f"  Files with multiple licenses   : {len(metrics['multi_lic_files']):>8,}  "
      f"({_pct(len(metrics['multi_lic_files']), total)})")
    a(f"  Files with custom LicenseRef   : {len(metrics['spdx_ref_files']):>8,}  "
      f"({_pct(len(metrics['spdx_ref_files']), total)})")
    a(f"  Non-allowlisted license files  : {len(lic_viol['violations']):>8,}")
    a(f"  Copyright violations           : {len(cp_viol['violations']):>8,}")
    a(f"  Keyword violations             : {len(kw_viol['violations']):>8,}")

    # ---- license distribution ---------------------------------------------
    section("4. LICENSE DISTRIBUTION")
    a(f"  {'License':<45} {'Files':>7}  {'%':>6}  {'Bar':>32}")
    a("  " + "-" * 95)
    for lic, cnt in lic_counter.most_common():
        display = lic
        if lic in metrics["custom_lic_map"]:
            display = f"{lic}  [{metrics['custom_lic_map'][lic]}]"
        a(f"  {display:<45} {cnt:>7,}  {_pct(cnt, total):>6}  "
          f"{_bar(cnt, total, 28):>30}")

    # ---- custom / non-SPDX licenses --------------------------------------
    section("5. CUSTOM / NON-SPDX LICENSES (LicenseRef-*)")
    if metrics["custom_lic_map"]:
        a(f"  {'License ID':<45}  {'Short name'}")
        a("  " + "-" * 60)
        for lid, name in metrics["custom_lic_map"].items():
            a(f"  {lid:<45}  {name}")
    else:
        a("  None found.")

    a("")
    a("  Files carrying custom license references:")
    if metrics["spdx_ref_files"]:
        for fname, lics in sorted(metrics["spdx_ref_files"]):
            a(f"    {fname}")
            for l in lics:
                name = metrics["custom_lic_map"].get(l, "")
                a(f"      -> {l}  [{name}]")
    else:
        a("  None.")

    # ---- copyright holders -----------------------------------------------
    section("6. COPYRIGHT HOLDERS")
    holder_counter = metrics["holder_counter"]
    a(f"  Distinct copyright holders: {len(holder_counter):,}")
    a(f"  Distinct copyright strings: {len(metrics['copyright_counter']):,}")
    a("")
    a(f"  {'Normalized holder':<55} {'Files':>7}")
    a("  " + "-" * 65)
    for holder, cnt in holder_counter.most_common(50):
        a(f"  {holder:<55} {cnt:>7,}")
    if len(holder_counter) > 50:
        a(f"  ... and {len(holder_counter) - 50} more holders.")

    # ---- directory breakdown ---------------------------------------------
    section("7. DIRECTORY-LEVEL LICENSE BREAKDOWN")
    a(f"  {'Directory':<35} {'Files':>7}  {'Primary license(s)'}")
    a("  " + "-" * 80)
    for d, count in sorted(metrics["dir_count"].items(), key=lambda x: -x[1]):
        lic_summary = ", ".join(
            f"{l}({c})"
            for l, c in metrics["dir_lic"][d].most_common(3)
        )
        a(f"  {d:<35} {count:>7,}  {lic_summary}")

    # ---- files with multiple licenses ------------------------------------
    section("8. FILES WITH MULTIPLE LICENSES")
    if metrics["multi_lic_files"]:
        for fname, lics in sorted(metrics["multi_lic_files"]):
            a(f"  {fname}")
            a(f"    Licenses: {', '.join(lics)}")
    else:
        a("  None found.")

    # ---- files without license -------------------------------------------
    section("9. FILES WITHOUT LICENSE INFORMATION")
    if metrics["no_lic_files"]:
        a(f"  ({len(metrics['no_lic_files'])} files)")
        for fname in sorted(metrics["no_lic_files"]):
            a(f"  {fname}")
    else:
        a("  All files have license information.")

    # ---- files without copyright -----------------------------------------
    section("10. FILES WITHOUT COPYRIGHT INFORMATION")
    no_cp_list = metrics["no_copyright_files"]
    if no_cp_list:
        a(f"  ({len(no_cp_list)} files)")
        for fname in sorted(no_cp_list):
            a(f"  {fname}")
    else:
        a("  All files have copyright information.")

    # ---- concluded vs detected mismatch ----------------------------------
    section("11. LICENSE CONCLUDED vs. DETECTED MISMATCH")
    diff = metrics["concluded_diff"]
    if diff:
        a(f"  ({len(diff)} files where 'licenseConcluded' differs from 'licenseInfoInFiles')")
        for fname, concluded, detected in sorted(diff):
            a(f"  {fname}")
            a(f"    Concluded : {concluded}")
            a(f"    Detected  : {', '.join(detected)}")
    else:
        a("  No mismatches found (or all concluded licenses are NOASSERTION).")

    # ---- FOSSology violation reports ------------------------------------
    section("12. FOSSOLOGY NON-ALLOWLISTED LICENSE REPORT")
    a(f"  Summary: {lic_viol['summary_line']}")
    if lic_viol["violations"]:
        a(f"  Total flagged files: {len(lic_viol['violations'])}")
        a("")
        for v in lic_viol["violations"]:
            a(f"  File: {v['file']}")
            for finding in v["findings"]:
                a(f"    {finding}")
    else:
        a("  No non-allowlisted license violations found.")

    section("13. FOSSOLOGY COPYRIGHT VIOLATION REPORT")
    a(f"  Summary: {cp_viol['summary_line']}")
    if cp_viol["violations"]:
        for v in cp_viol["violations"]:
            a(f"  File: {v['file']}")
            for finding in v["findings"]:
                a(f"    {finding}")
    else:
        a("  No copyright violations found.")

    section("14. FOSSOLOGY KEYWORD VIOLATION REPORT")
    a(f"  Summary: {kw_viol['summary_line']}")
    if kw_viol["violations"]:
        for v in kw_viol["violations"]:
            a(f"  File: {v['file']}")
            for finding in v["findings"]:
                a(f"    {finding}")
    else:
        a("  No keyword violations found.")

    # ---- compliance findings summary ------------------------------------
    section("15. COMPLIANCE FINDINGS SUMMARY")
    copyleft = {
        "GPL-1.0-only", "GPL-1.0-or-later",
        "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0-only", "GPL-3.0-or-later",
        "LGPL-2.0-only", "LGPL-2.0-or-later",
        "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0-only", "LGPL-3.0-or-later",
        "AGPL-3.0-only", "AGPL-3.0-or-later",
        "MPL-1.1", "MPL-2.0",
    }

    found_copyleft = {l: c for l, c in lic_counter.items() if l in copyleft}
    found_custom = {l: c for l, c in lic_counter.items() if _is_spdx_ref(l)}

    a("  Copyleft licenses detected:")
    if found_copyleft:
        for l, c in sorted(found_copyleft.items()):
            a(f"    {l:<40} {c:>5} file(s) — REVIEW REQUIRED")
    else:
        a("    None detected.")

    a("")
    a("  Custom / unresolved license references (LicenseRef-*):")
    if found_custom:
        for l, c in sorted(found_custom.items()):
            name = metrics["custom_lic_map"].get(l, "")
            a(f"    {l:<45} {c:>5} file(s)  [{name}] — MANUAL REVIEW REQUIRED")
    else:
        a("    None detected.")

    a("")
    a("  Non-allowlisted files (from FOSSology CI report):")
    if lic_viol["violations"]:
        a(f"    {len(lic_viol['violations'])} file(s) — SEE SECTION 12")
    else:
        a("    None.")

    a("")
    a("  Files missing license information:")
    if metrics["no_lic_files"]:
        a(f"    {len(metrics['no_lic_files'])} file(s) — SEE SECTION 9")
    else:
        a("    None.")

    a("")
    a(SEP_THICK)
    a("  End of report")
    a(SEP_THICK)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def render_markdown(metrics: dict, lic_viol: dict, cp_viol: dict, kw_viol: dict) -> str:
    lines = []
    a = lines.append

    a("# FOSSology Scan Analysis Report")
    a("")
    a(f"> Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    a("")

    # metadata
    m = metrics["spdx_meta"]
    a("## 1. SPDX Document Metadata")
    a("")
    a(f"| Field | Value |")
    a(f"|---|---|")
    a(f"| Document name | {m['doc_name']} |")
    a(f"| SPDX version | {m['spdx_version']} |")
    a(f"| Data license | {m['data_license']} |")
    a(f"| Created | {m['created']} |")
    for c in m["creators"]:
        a(f"| Creator | {c} |")
    a(f"| Namespace | {m['doc_namespace']} |")
    a("")

    # packages
    a("## 2. Packages")
    a("")
    for pkg in metrics["packages"]:
        a(f"### {pkg.get('name', '')}")
        a("")
        a(f"| Field | Value |")
        a(f"|---|---|")
        a(f"| SPDX ID | `{pkg.get('SPDXID', '')}` |")
        a(f"| Download URL | {pkg.get('downloadLocation', '')} |")
        a(f"| Originator | {pkg.get('originator', '')} |")
        a(f"| Release date | {pkg.get('releaseDate', '')} |")
        vcode = pkg.get("packageVerificationCode", {}).get("packageVerificationCodeValue", "")
        a(f"| Verification code | `{vcode}` |")
        a("")
        lics = pkg.get("licenseInfoFromFiles", [])
        a(f"**Declared licenses** ({len(lics)}):")
        a("")
        for l in sorted(lics):
            a(f"- `{l}`")
        a("")

    # executive summary
    total = metrics["total_files"]
    lic_counter = metrics["lic_counter"]
    no_lic = metrics["no_lic_files"]
    no_cp = metrics["no_copyright_files"]

    a("## 3. Executive Summary")
    a("")
    a("| Metric | Count | % |")
    a("|---|---:|---:|")
    a(f"| Total files analyzed | {total:,} | 100% |")
    a(f"| Distinct SPDX license IDs | {len(lic_counter):,} | — |")
    a(f"| Files with identified license | {total - len(no_lic):,} | {_pct(total - len(no_lic), total)} |")
    a(f"| Files without license info | {len(no_lic):,} | {_pct(len(no_lic), total)} |")
    a(f"| Files with identified copyright | {total - len(no_cp):,} | {_pct(total - len(no_cp), total)} |")
    a(f"| Files without copyright info | {len(no_cp):,} | {_pct(len(no_cp), total)} |")
    a(f"| Files with multiple licenses | {len(metrics['multi_lic_files']):,} | {_pct(len(metrics['multi_lic_files']), total)} |")
    a(f"| Files with custom LicenseRef | {len(metrics['spdx_ref_files']):,} | {_pct(len(metrics['spdx_ref_files']), total)} |")
    a(f"| Non-allowlisted license files | {len(lic_viol['violations']):,} | — |")
    a(f"| Copyright violations | {len(cp_viol['violations']):,} | — |")
    a(f"| Keyword violations | {len(kw_viol['violations']):,} | — |")
    a("")

    # license distribution
    a("## 4. License Distribution")
    a("")
    a("| License | Files | % |")
    a("|---|---:|---:|")
    for lic, cnt in lic_counter.most_common():
        display = lic
        if lic in metrics["custom_lic_map"]:
            display = f"`{lic}` ({metrics['custom_lic_map'][lic]})"
        else:
            display = f"`{lic}`"
        a(f"| {display} | {cnt:,} | {_pct(cnt, total)} |")
    a("")

    # custom licenses
    a("## 5. Custom / Non-SPDX Licenses")
    a("")
    if metrics["custom_lic_map"]:
        a("| License ID | Short name |")
        a("|---|---|")
        for lid, name in metrics["custom_lic_map"].items():
            a(f"| `{lid}` | {name} |")
    else:
        a("None found.")
    a("")
    a("### Files with custom license references")
    a("")
    if metrics["spdx_ref_files"]:
        for fname, lics in sorted(metrics["spdx_ref_files"]):
            name_str = ", ".join(
                f"`{l}` [{metrics['custom_lic_map'].get(l, '')}]" for l in lics
            )
            a(f"- `{fname}` — {name_str}")
    else:
        a("None.")
    a("")

    # copyright holders
    a("## 6. Copyright Holders (top 50)")
    a("")
    holder_counter = metrics["holder_counter"]
    a(f"Distinct holders: **{len(holder_counter):,}**  "
      f"| Distinct copyright strings: **{len(metrics['copyright_counter']):,}**")
    a("")
    a("| Normalized holder | Files |")
    a("|---|---:|")
    for holder, cnt in holder_counter.most_common(50):
        a(f"| {holder} | {cnt:,} |")
    if len(holder_counter) > 50:
        a(f"| *(and {len(holder_counter) - 50} more)* | — |")
    a("")

    # directory breakdown
    a("## 7. Directory-Level License Breakdown")
    a("")
    a("| Directory | Files | Primary license(s) |")
    a("|---|---:|---|")
    for d, count in sorted(metrics["dir_count"].items(), key=lambda x: -x[1]):
        lic_summary = ", ".join(
            f"`{l}`({c})"
            for l, c in metrics["dir_lic"][d].most_common(3)
        )
        a(f"| `{d}` | {count:,} | {lic_summary} |")
    a("")

    # multi-license files
    a("## 8. Files with Multiple Licenses")
    a("")
    if metrics["multi_lic_files"]:
        a("| File | Licenses |")
        a("|---|---|")
        for fname, lics in sorted(metrics["multi_lic_files"]):
            a(f"| `{fname}` | {', '.join(f'`{l}`' for l in lics)} |")
    else:
        a("None found.")
    a("")

    # missing license
    a("## 9. Files Without License Information")
    a("")
    if metrics["no_lic_files"]:
        for fname in sorted(metrics["no_lic_files"]):
            a(f"- `{fname}`")
    else:
        a("All files have license information.")
    a("")

    # missing copyright
    a("## 10. Files Without Copyright Information")
    a("")
    if metrics["no_copyright_files"]:
        for fname in sorted(metrics["no_copyright_files"]):
            a(f"- `{fname}`")
    else:
        a("All files have copyright information.")
    a("")

    # concluded vs detected
    a("## 11. License Concluded vs. Detected Mismatch")
    a("")
    diff = metrics["concluded_diff"]
    if diff:
        a("| File | Concluded | Detected |")
        a("|---|---|---|")
        for fname, concluded, detected in sorted(diff):
            a(f"| `{fname}` | `{concluded}` | {', '.join(f'`{l}`' for l in detected)} |")
    else:
        a("No mismatches found.")
    a("")

    # violation reports
    a("## 12. FOSSology Non-Allowlisted License Report")
    a("")
    a(f"> {lic_viol['summary_line']}")
    a("")
    if lic_viol["violations"]:
        a(f"**Total flagged files:** {len(lic_viol['violations'])}")
        a("")
        for v in lic_viol["violations"]:
            a(f"- **`{v['file']}`**")
            for finding in v["findings"]:
                a(f"  - {finding}")
    else:
        a("No non-allowlisted license violations found.")
    a("")

    a("## 13. FOSSology Copyright Violation Report")
    a("")
    a(f"> {cp_viol['summary_line']}")
    a("")
    if cp_viol["violations"]:
        for v in cp_viol["violations"]:
            a(f"- **`{v['file']}`**")
            for finding in v["findings"]:
                a(f"  - {finding}")
    else:
        a("No copyright violations found.")
    a("")

    a("## 14. FOSSology Keyword Violation Report")
    a("")
    a(f"> {kw_viol['summary_line']}")
    a("")
    if kw_viol["violations"]:
        for v in kw_viol["violations"]:
            a(f"- **`{v['file']}`**")
            for finding in v["findings"]:
                a(f"  - {finding}")
    else:
        a("No keyword violations found.")
    a("")

    # compliance
    a("## 15. Compliance Findings Summary")
    a("")
    copyleft = {
        "GPL-1.0-only", "GPL-1.0-or-later",
        "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0-only", "GPL-3.0-or-later",
        "LGPL-2.0-only", "LGPL-2.0-or-later",
        "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0-only", "LGPL-3.0-or-later",
        "AGPL-3.0-only", "AGPL-3.0-or-later",
        "MPL-1.1", "MPL-2.0",
    }

    found_copyleft = {l: c for l, c in lic_counter.items() if l in copyleft}
    found_custom = {l: c for l, c in lic_counter.items() if _is_spdx_ref(l)}

    a("### Copyleft Licenses")
    a("")
    if found_copyleft:
        a("| License | Files | Action |")
        a("|---|---:|---|")
        for l, c in sorted(found_copyleft.items()):
            a(f"| `{l}` | {c:,} | **REVIEW REQUIRED** |")
    else:
        a("No copyleft licenses detected.")
    a("")

    a("### Custom / Unresolved Licenses")
    a("")
    if found_custom:
        a("| License ID | Short name | Files | Action |")
        a("|---|---|---:|---|")
        for l, c in sorted(found_custom.items()):
            name = metrics["custom_lic_map"].get(l, "")
            a(f"| `{l}` | {name} | {c:,} | **MANUAL REVIEW REQUIRED** |")
    else:
        a("No custom license references detected.")
    a("")

    a("### Non-Allowlisted Files")
    a("")
    if lic_viol["violations"]:
        a(f"{len(lic_viol['violations'])} file(s) — see [Section 12](#12-fossology-non-allowlisted-license-report).")
    else:
        a("None.")
    a("")

    a("### Files Missing License Information")
    a("")
    if metrics["no_lic_files"]:
        a(f"{len(metrics['no_lic_files'])} file(s) — see [Section 9](#9-files-without-license-information).")
    else:
        a("None.")
    a("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

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


def _h(text: str) -> str:
    """HTML-escape a string."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _lic_badge(lic: str) -> str:
    """Return a coloured <span> badge for a license identifier."""
    if lic in _COPYLEFT_SPDX:
        cls = "badge-copyleft"
    elif _is_spdx_ref(lic):
        cls = "badge-custom"
    elif lic in ("NOASSERTION", "NONE"):
        cls = "badge-none"
    else:
        cls = "badge-permissive"
    return f'<span class="badge {cls}">{_h(lic)}</span>'


def _svg_pie(lic_counter: Counter, total: int) -> str:
    """Build an inline SVG donut chart for the top-10 licenses."""
    palette = [
        "#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
        "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
    ]
    items = lic_counter.most_common(10)
    other = total - sum(c for _, c in items)
    if other > 0:
        items.append(("Other", other))

    cx, cy, r_out, r_in = 160, 160, 130, 70
    import math

    def arc_path(start_deg: float, end_deg: float, color: str, label: str, pct: str) -> str:
        start = math.radians(start_deg - 90)
        end = math.radians(end_deg - 90)
        x1 = cx + r_out * math.cos(start)
        y1 = cy + r_out * math.sin(start)
        x2 = cx + r_out * math.cos(end)
        y2 = cy + r_out * math.sin(end)
        ix1 = cx + r_in * math.cos(end)
        iy1 = cy + r_in * math.sin(end)
        ix2 = cx + r_in * math.cos(start)
        iy2 = cy + r_in * math.sin(start)
        large = 1 if (end_deg - start_deg) > 180 else 0
        d = (f"M {x1:.2f},{y1:.2f} "
             f"A {r_out},{r_out} 0 {large},1 {x2:.2f},{y2:.2f} "
             f"L {ix1:.2f},{iy1:.2f} "
             f"A {r_in},{r_in} 0 {large},0 {ix2:.2f},{iy2:.2f} Z")
        mid_angle = math.radians((start_deg + end_deg) / 2 - 90)
        lx = cx + (r_in + (r_out - r_in) * 0.5) * math.cos(mid_angle)
        ly = cy + (r_in + (r_out - r_in) * 0.5) * math.sin(mid_angle)
        tip = f"{_h(label)}: {pct}"
        return (f'<path d="{d}" fill="{color}" stroke="#fff" stroke-width="2">'
                f'<title>{tip}</title></path>')

    paths = []
    legend_items = []
    angle = 0.0
    for i, (lic, cnt) in enumerate(items):
        color = palette[i % len(palette)]
        slice_deg = 360.0 * cnt / total if total else 0
        pct_str = _pct(cnt, total)
        paths.append(arc_path(angle, angle + slice_deg, color, lic, pct_str))
        legend_items.append(
            f'<li><span class="dot" style="background:{color}"></span>'
            f'{_h(lic)} <em>({pct_str})</em></li>'
        )
        angle += slice_deg

    svg = (
        f'<svg viewBox="0 0 320 320" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:320px;height:320px">'
        + "".join(paths)
        + f'<text x="{cx}" y="{cy - 8}" text-anchor="middle" '
        f'font-size="14" font-weight="bold" fill="#333">{total:,}</text>'
        + f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" '
        f'font-size="11" fill="#666">files</text>'
        + "</svg>"
    )
    legend = '<ul class="pie-legend">\n' + "\n".join(legend_items) + "\n</ul>"
    return (
        '<div class="chart-wrap">'
        + svg
        + legend
        + "</div>"
    )


def _bar_svg(count: int, total: int, color: str = "#4e79a7") -> str:
    """Inline SVG horizontal bar for a table cell."""
    w = int(200 * count / total) if total else 0
    return (
        f'<svg width="200" height="14" style="vertical-align:middle">'
        f'<rect x="0" y="2" width="{w}" height="10" rx="2" fill="{color}"/>'
        f'<rect x="0" y="2" width="200" height="10" rx="2" '
        f'fill="none" stroke="#ddd" stroke-width="1"/>'
        f"</svg>"
    )


_HTML_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px;
  color: #222;
  background: #f5f6fa;
  display: flex;
}
/* ---- sidebar ---- */
#sidebar {
  width: 240px;
  min-width: 240px;
  background: #1e2a3a;
  color: #cdd6e0;
  height: 100vh;
  position: sticky;
  top: 0;
  overflow-y: auto;
  padding: 20px 0;
  flex-shrink: 0;
}
#sidebar h2 { font-size: 13px; color: #7a9abf; padding: 12px 18px 4px; text-transform: uppercase; letter-spacing: .06em; }
#sidebar ul { list-style: none; }
#sidebar ul li a {
  display: block;
  padding: 5px 18px;
  color: #cdd6e0;
  text-decoration: none;
  font-size: 12.5px;
  border-left: 3px solid transparent;
  transition: background .15s;
}
#sidebar ul li a:hover, #sidebar ul li a.active {
  background: #2a3f58;
  border-left-color: #4e79a7;
  color: #fff;
}
/* ---- main content ---- */
#content {
  flex: 1;
  padding: 32px 40px;
  max-width: 1200px;
  overflow-x: auto;
}
/* ---- header ---- */
.page-header {
  background: linear-gradient(135deg, #1e2a3a 0%, #2a4a72 100%);
  color: #fff;
  border-radius: 10px;
  padding: 28px 32px;
  margin-bottom: 32px;
}
.page-header h1 { font-size: 24px; font-weight: 700; }
.page-header p  { color: #a8c4e0; font-size: 13px; margin-top: 6px; }
/* ---- sections ---- */
.section {
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
  margin-bottom: 28px;
  overflow: hidden;
}
.section-header {
  background: #f0f4f9;
  border-bottom: 1px solid #dde3ec;
  padding: 14px 20px;
  cursor: pointer;
  user-select: none;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.section-header h2 { font-size: 15px; font-weight: 600; color: #1e2a3a; }
.section-header .toggle { font-size: 18px; color: #7a9abf; line-height: 1; }
.section-body  { padding: 20px; }
.section-body.collapsed { display: none; }
/* ---- cards (summary) ---- */
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 14px;
  margin-bottom: 10px;
}
.card {
  background: #f8fafd;
  border: 1px solid #dde3ec;
  border-radius: 8px;
  padding: 14px 16px;
  text-align: center;
}
.card .card-value { font-size: 28px; font-weight: 700; color: #1e2a3a; }
.card .card-value.warn { color: #e05c2e; }
.card .card-value.ok   { color: #2e8b57; }
.card .card-label { font-size: 11px; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: .04em; }
/* ---- tables ---- */
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
  background: #f0f4f9;
  color: #1e2a3a;
  font-weight: 600;
  padding: 8px 12px;
  text-align: left;
  border-bottom: 2px solid #dde3ec;
  white-space: nowrap;
}
td { padding: 7px 12px; border-bottom: 1px solid #eef0f4; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8fafd; }
td.num, th.num { text-align: right; }
td.mono { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; word-break: break-all; }
/* ---- search box ---- */
.search-wrap { margin-bottom: 10px; }
.search-wrap input {
  width: 100%;
  max-width: 420px;
  padding: 7px 12px;
  border: 1px solid #ccc;
  border-radius: 6px;
  font-size: 13px;
  outline: none;
  transition: border-color .2s;
}
.search-wrap input:focus { border-color: #4e79a7; }
/* ---- badges ---- */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11.5px;
  font-weight: 600;
  font-family: 'SFMono-Regular', Consolas, monospace;
  white-space: nowrap;
}
.badge-permissive { background: #d4edda; color: #155724; }
.badge-copyleft   { background: #f8d7da; color: #721c24; }
.badge-custom     { background: #fff3cd; color: #856404; }
.badge-none       { background: #e2e3e5; color: #383d41; }
/* ---- compliance status ---- */
.status-ok       { color: #2e8b57; font-weight: 600; }
.status-warn     { color: #e05c2e; font-weight: 600; }
.status-review   { color: #856404; font-weight: 600; }
/* ---- chart ---- */
.chart-wrap { display: flex; align-items: flex-start; gap: 24px; flex-wrap: wrap; }
.pie-legend { list-style: none; padding-top: 8px; }
.pie-legend li { font-size: 12.5px; margin-bottom: 5px; display: flex; align-items: center; gap: 7px; }
.dot { display: inline-block; width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
/* ---- violation list ---- */
.viol-list { list-style: none; }
.viol-list > li { margin-bottom: 8px; }
.viol-file { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px;
             background: #f8fafd; border: 1px solid #dde3ec; border-radius: 4px;
             padding: 3px 8px; word-break: break-all; }
.viol-findings { list-style: disc; margin-left: 24px; margin-top: 3px; }
.viol-findings li { font-size: 12px; color: #555; }
/* ---- metadata dl ---- */
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; font-size: 13px; }
dt.meta-key { font-weight: 600; color: #1e2a3a; white-space: nowrap; }
dd.meta-val { color: #444; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; word-break: break-all; }
/* ---- pkg card ---- */
.pkg-card { border: 1px solid #dde3ec; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: #fafbfd; }
.pkg-card h3 { font-size: 15px; color: #1e2a3a; margin-bottom: 10px; }
.pkg-lic-list { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 8px; }
/* ---- scrollable table wrapper ---- */
.table-scroll { overflow-x: auto; }
@media (max-width: 860px) {
  #sidebar { display: none; }
  #content { padding: 20px 16px; }
}
"""

_HTML_JS = """
document.addEventListener('DOMContentLoaded', function() {
  /* collapsible sections */
  document.querySelectorAll('.section-header').forEach(function(hdr) {
    hdr.addEventListener('click', function() {
      var body = hdr.nextElementSibling;
      var tog  = hdr.querySelector('.toggle');
      body.classList.toggle('collapsed');
      tog.textContent = body.classList.contains('collapsed') ? '+' : '\u2212';
    });
  });

  /* per-table search */
  document.querySelectorAll('.search-wrap input').forEach(function(inp) {
    var tbl = inp.closest('.search-wrap').nextElementSibling;
    inp.addEventListener('input', function() {
      var q = inp.value.toLowerCase();
      tbl.querySelectorAll('tbody tr').forEach(function(row) {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  });

  /* sidebar active link on scroll */
  var sections = document.querySelectorAll('.section[id]');
  var links    = document.querySelectorAll('#sidebar a');
  window.addEventListener('scroll', function() {
    var scrollY = window.pageYOffset + 80;
    sections.forEach(function(sec) {
      var top = sec.offsetTop;
      var bot = top + sec.offsetHeight;
      if (scrollY >= top && scrollY < bot) {
        links.forEach(function(a) { a.classList.remove('active'); });
        var a = document.querySelector('#sidebar a[href="#' + sec.id + '"]');
        if (a) a.classList.add('active');
      }
    });
  }, { passive: true });
});
"""


def render_html(metrics: dict, lic_viol: dict, cp_viol: dict, kw_viol: dict) -> str:  # noqa: C901
    """Render a self-contained HTML compliance report."""
    lines = []
    a = lines.append
    total = metrics["total_files"]
    lic_counter = metrics["lic_counter"]
    no_lic = metrics["no_lic_files"]
    no_cp = metrics["no_copyright_files"]
    m = metrics["spdx_meta"]
    copyleft = _COPYLEFT_SPDX
    found_copyleft = {l: c for l, c in lic_counter.items() if l in copyleft}
    found_custom = {l: c for l, c in lic_counter.items() if _is_spdx_ref(l)}
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ---- nav items ----------------------------------------------------
    nav_items = [
        ("s1",  "1. SPDX Metadata"),
        ("s2",  "2. Packages"),
        ("s3",  "3. Executive Summary"),
        ("s4",  "4. License Distribution"),
        ("s5",  "5. Custom Licenses"),
        ("s6",  "6. Copyright Holders"),
        ("s7",  "7. Directory Breakdown"),
        ("s8",  "8. Multi-License Files"),
        ("s9",  "9. No License Info"),
        ("s10", "10. No Copyright Info"),
        ("s11", "11. Concluded vs Detected"),
        ("s12", "12. Non-Allowlisted Licenses"),
        ("s13", "13. Copyright Violations"),
        ("s14", "14. Keyword Violations"),
        ("s15", "15. Compliance Summary"),
    ]

    # ---- document head ------------------------------------------------
    a("<!DOCTYPE html>")
    a('<html lang="en">')
    a("<head>")
    a('<meta charset="UTF-8">')
    a('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    a("<title>FOSSology Scan Report</title>")
    a(f"<style>{_HTML_CSS}</style>")
    a("</head>")
    a("<body>")

    # ---- sidebar ------------------------------------------------------
    a('<nav id="sidebar">')
    a('<h2>Sections</h2>')
    a("<ul>")
    for sid, label in nav_items:
        a(f'<li><a href="#{sid}">{_h(label)}</a></li>')
    a("</ul>")
    a("</nav>")

    # ---- main content -------------------------------------------------
    a('<main id="content">')
    a('<div class="page-header">')
    a("<h1>FOSSology Scan Analysis Report</h1>")
    a(f'<p>Generated: {generated} &nbsp;&bull;&nbsp; '
      f'Document: <strong>{_h(m["doc_name"])}</strong> &nbsp;&bull;&nbsp; '
      f'SPDX {_h(m["spdx_version"])}</p>')
    a("</div>")

    # helper: open a section
    def sec_open(sid: str, title: str) -> None:
        a(f'<div class="section" id="{sid}">')
        a(f'<div class="section-header"><h2>{_h(title)}</h2>'
          f'<span class="toggle">&minus;</span></div>')
        a('<div class="section-body">')

    def sec_close() -> None:
        a("</div></div>")

    # ---- S1: SPDX metadata --------------------------------------------
    sec_open("s1", "1. SPDX Document Metadata")
    a('<dl class="meta">')
    for key, val in [
        ("Document name",  m["doc_name"]),
        ("SPDX version",   m["spdx_version"]),
        ("Data license",   m["data_license"]),
        ("Created",        m["created"]),
        ("Namespace",      m["doc_namespace"]),
    ]:
        a(f'<dt class="meta-key">{_h(key)}</dt><dd class="meta-val">{_h(val)}</dd>')
    for c in m["creators"]:
        a(f'<dt class="meta-key">Creator</dt><dd class="meta-val">{_h(c)}</dd>')
    a("</dl>")
    sec_close()

    # ---- S2: Packages -------------------------------------------------
    sec_open("s2", "2. Packages")
    for pkg in metrics["packages"]:
        vcode = pkg.get("packageVerificationCode", {}).get("packageVerificationCodeValue", "")
        a(f'<div class="pkg-card">')
        a(f'<h3>{_h(pkg.get("name", ""))}</h3>')
        a('<dl class="meta">')
        for key, val in [
            ("SPDX ID",        pkg.get("SPDXID", "")),
            ("Download URL",   pkg.get("downloadLocation", "")),
            ("Originator",     pkg.get("originator", "")),
            ("Release date",   pkg.get("releaseDate", "")),
            ("Verification",   vcode),
        ]:
            a(f'<dt class="meta-key">{_h(key)}</dt><dd class="meta-val">{_h(val)}</dd>')
        a("</dl>")
        lics = sorted(pkg.get("licenseInfoFromFiles", []))
        a(f'<p style="margin-top:10px;font-weight:600;font-size:13px;">Declared licenses ({len(lics)}):</p>')
        a('<div class="pkg-lic-list">')
        for l in lics:
            a(_lic_badge(l))
        a("</div>")
        a("</div>")
    sec_close()

    # ---- S3: Executive summary ----------------------------------------
    sec_open("s3", "3. Executive Summary")
    cards = [
        (f"{total:,}",                                   "Total files",            False),
        (f"{len(lic_counter):,}",                        "Distinct licenses",      False),
        (f"{total - len(no_lic):,}",                     "Files with license",     False),
        (str(len(no_lic)) if no_lic else "0",           "No license info",        bool(no_lic)),
        (f"{total - len(no_cp):,}",                      "Files with copyright",   False),
        (str(len(no_cp)) if no_cp else "0",             "No copyright info",      bool(no_cp)),
        (f"{len(metrics['multi_lic_files']):,}",         "Multi-license files",    False),
        (str(len(lic_viol["violations"])),               "Non-allowlisted",        bool(lic_viol["violations"])),
        (str(len(cp_viol["violations"])),                "Copyright violations",   bool(cp_viol["violations"])),
        (str(len(kw_viol["violations"])),                "Keyword violations",     bool(kw_viol["violations"])),
    ]
    a('<div class="card-grid">')
    for val, label, is_warn in cards:
        cls = " warn" if is_warn else ""
        a(f'<div class="card"><div class="card-value{cls}">{_h(val)}</div>'
          f'<div class="card-label">{_h(label)}</div></div>')
    a("</div>")
    sec_close()

    # ---- S4: License distribution -------------------------------------
    sec_open("s4", "4. License Distribution")
    a(_svg_pie(lic_counter, total))
    a('<div class="table-scroll" style="margin-top:20px">')
    a('<div class="search-wrap"><input type="search" placeholder="Filter licenses..."></div>')
    a("<table><thead><tr>")
    a("<th>License</th><th class=\"num\">Files</th><th class=\"num\">%</th><th>Distribution</th>")
    a("</tr></thead><tbody>")
    palette_colors = [
        "#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
        "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
    ]
    for i, (lic, cnt) in enumerate(lic_counter.most_common()):
        color = palette_colors[i % len(palette_colors)]
        bar = _bar_svg(cnt, total, color)
        a(f"<tr><td>{_lic_badge(lic)}</td>"
          f"<td class=\"num\">{cnt:,}</td>"
          f"<td class=\"num\">{_pct(cnt, total)}</td>"
          f"<td>{bar}</td></tr>")
    a("</tbody></table>")
    a("</div>")
    sec_close()

    # ---- S5: Custom licenses ------------------------------------------
    sec_open("s5", "5. Custom / Non-SPDX Licenses (LicenseRef-*)")
    if metrics["custom_lic_map"]:
        a("<table><thead><tr><th>License ID</th><th>Short name</th></tr></thead><tbody>")
        for lid, name in metrics["custom_lic_map"].items():
            a(f"<tr><td>{_lic_badge(lid)}</td><td>{_h(name)}</td></tr>")
        a("</tbody></table>")
    else:
        a("<p>None found.</p>")
    a('<h3 style="margin-top:18px;margin-bottom:8px;font-size:13px;">Files carrying custom license references</h3>')
    if metrics["spdx_ref_files"]:
        a('<ul class="viol-list">')
        for fname, lics in sorted(metrics["spdx_ref_files"]):
            badges = " ".join(
                _lic_badge(l) + f" [{_h(metrics['custom_lic_map'].get(l, ''))}]"
                for l in lics
            )
            a(f'<li><span class="viol-file">{_h(fname)}</span>'
              f'<ul class="viol-findings"><li>{badges}</li></ul></li>')
        a("</ul>")
    else:
        a("<p>None.</p>")
    sec_close()

    # ---- S6: Copyright holders ----------------------------------------
    sec_open("s6", "6. Copyright Holders (top 50)")
    holder_counter = metrics["holder_counter"]
    a(f'<p style="margin-bottom:12px">Distinct holders: '
      f'<strong>{len(holder_counter):,}</strong> &nbsp;&nbsp; '
      f'Distinct copyright strings: '
      f'<strong>{len(metrics["copyright_counter"]):,}</strong></p>')
    a('<div class="search-wrap"><input type="search" placeholder="Filter holders..."></div>')
    a("<table><thead><tr><th>Normalized holder</th><th class=\"num\">Files</th></tr></thead><tbody>")
    for holder, cnt in holder_counter.most_common(50):
        a(f"<tr><td>{_h(holder)}</td><td class=\"num\">{cnt:,}</td></tr>")
    if len(holder_counter) > 50:
        a(f"<tr><td><em>... and {len(holder_counter) - 50} more holders</em></td><td></td></tr>")
    a("</tbody></table>")
    sec_close()

    # ---- S7: Directory breakdown --------------------------------------
    sec_open("s7", "7. Directory-Level License Breakdown")
    a('<div class="search-wrap"><input type="search" placeholder="Filter directories..."></div>')
    a('<div class="table-scroll">')
    a("<table><thead><tr><th>Directory</th><th class=\"num\">Files</th>"
      "<th>Primary license(s)</th></tr></thead><tbody>")
    for d, count in sorted(metrics["dir_count"].items(), key=lambda x: -x[1]):
        lic_summary = " ".join(
            f"{_lic_badge(l)}<small>({c})</small>"
            for l, c in metrics["dir_lic"][d].most_common(3)
        )
        a(f'<tr><td class="mono">{_h(d)}</td>'
          f'<td class="num">{count:,}</td>'
          f'<td>{lic_summary}</td></tr>')
    a("</tbody></table></div>")
    sec_close()

    # ---- S8: Multi-license files --------------------------------------
    sec_open("s8", "8. Files with Multiple Licenses")
    if metrics["multi_lic_files"]:
        a('<div class="search-wrap"><input type="search" placeholder="Filter files..."></div>')
        a('<div class="table-scroll">')
        a("<table><thead><tr><th>File</th><th>Licenses</th></tr></thead><tbody>")
        for fname, lics in sorted(metrics["multi_lic_files"]):
            badges = " ".join(_lic_badge(l) for l in lics)
            a(f'<tr><td class="mono">{_h(fname)}</td><td>{badges}</td></tr>')
        a("</tbody></table></div>")
    else:
        a("<p>None found.</p>")
    sec_close()

    # ---- S9: No license -----------------------------------------------
    sec_open("s9", "9. Files Without License Information")
    if metrics["no_lic_files"]:
        a('<div class="search-wrap"><input type="search" placeholder="Filter files..."></div>')
        a("<table><thead><tr><th>File</th></tr></thead><tbody>")
        for fname in sorted(metrics["no_lic_files"]):
            a(f'<tr><td class="mono">{_h(fname)}</td></tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">All files have license information.</p>')
    sec_close()

    # ---- S10: No copyright --------------------------------------------
    sec_open("s10", "10. Files Without Copyright Information")
    if metrics["no_copyright_files"]:
        a('<div class="search-wrap"><input type="search" placeholder="Filter files..."></div>')
        a("<table><thead><tr><th>File</th></tr></thead><tbody>")
        for fname in sorted(metrics["no_copyright_files"]):
            a(f'<tr><td class="mono">{_h(fname)}</td></tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">All files have copyright information.</p>')
    sec_close()

    # ---- S11: Concluded vs detected -----------------------------------
    sec_open("s11", "11. License Concluded vs. Detected Mismatch")
    diff = metrics["concluded_diff"]
    if diff:
        a('<div class="search-wrap"><input type="search" placeholder="Filter..."></div>')
        a('<div class="table-scroll">')
        a("<table><thead><tr><th>File</th><th>Concluded</th><th>Detected</th></tr></thead><tbody>")
        for fname, concluded, detected in sorted(diff):
            det_badges = " ".join(_lic_badge(l) for l in detected)
            a(f'<tr><td class="mono">{_h(fname)}</td>'
              f'<td>{_lic_badge(concluded)}</td>'
              f'<td>{det_badges}</td></tr>')
        a("</tbody></table></div>")
    else:
        a('<p class="status-ok">No mismatches found.</p>')
    sec_close()

    # ---- S12: Non-allowlisted -----------------------------------------
    sec_open("s12", "12. FOSSology Non-Allowlisted License Report")
    a(f'<p style="margin-bottom:12px"><em>{_h(lic_viol["summary_line"])}</em></p>')
    if lic_viol["violations"]:
        a(f'<p style="margin-bottom:10px">Total flagged files: '
          f'<strong class="status-warn">{len(lic_viol["violations"]):,}</strong></p>')
        a('<div class="search-wrap"><input type="search" placeholder="Filter files..."></div>')
        a('<ul class="viol-list">')
        for v in lic_viol["violations"]:
            a(f'<li><span class="viol-file">{_h(v["file"])}</span>')
            if v["findings"]:
                a('<ul class="viol-findings">')
                for finding in v["findings"]:
                    a(f"<li>{_h(finding)}</li>")
                a("</ul>")
            a("</li>")
        a("</ul>")
    else:
        a('<p class="status-ok">No non-allowlisted license violations found.</p>')
    sec_close()

    # ---- S13: Copyright violations ------------------------------------
    sec_open("s13", "13. FOSSology Copyright Violation Report")
    a(f'<p style="margin-bottom:12px"><em>{_h(cp_viol["summary_line"])}</em></p>')
    if cp_viol["violations"]:
        a('<ul class="viol-list">')
        for v in cp_viol["violations"]:
            a(f'<li><span class="viol-file">{_h(v["file"])}</span>')
            if v["findings"]:
                a('<ul class="viol-findings">')
                for finding in v["findings"]:
                    a(f"<li>{_h(finding)}</li>")
                a("</ul>")
            a("</li>")
        a("</ul>")
    else:
        a('<p class="status-ok">No copyright violations found.</p>')
    sec_close()

    # ---- S14: Keyword violations --------------------------------------
    sec_open("s14", "14. FOSSology Keyword Violation Report")
    a(f'<p style="margin-bottom:12px"><em>{_h(kw_viol["summary_line"])}</em></p>')
    if kw_viol["violations"]:
        a('<ul class="viol-list">')
        for v in kw_viol["violations"]:
            a(f'<li><span class="viol-file">{_h(v["file"])}</span>')
            if v["findings"]:
                a('<ul class="viol-findings">')
                for finding in v["findings"]:
                    a(f"<li>{_h(finding)}</li>")
                a("</ul>")
            a("</li>")
        a("</ul>")
    else:
        a('<p class="status-ok">No keyword violations found.</p>')
    sec_close()

    # ---- S15: Compliance summary --------------------------------------
    sec_open("s15", "15. Compliance Findings Summary")

    a('<h3 style="font-size:14px;margin-bottom:8px">Copyleft Licenses</h3>')
    if found_copyleft:
        a("<table><thead><tr><th>License</th><th class=\"num\">Files</th>"
          "<th>Action</th></tr></thead><tbody>")
        for l, c in sorted(found_copyleft.items()):
            a(f'<tr><td>{_lic_badge(l)}</td><td class="num">{c:,}</td>'
              f'<td class="status-warn">REVIEW REQUIRED</td></tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">No copyleft licenses detected.</p>')

    a('<h3 style="font-size:14px;margin-top:18px;margin-bottom:8px">Custom / Unresolved Licenses</h3>')
    if found_custom:
        a("<table><thead><tr><th>License ID</th><th>Short name</th>"
          "<th class=\"num\">Files</th><th>Action</th></tr></thead><tbody>")
        for l, c in sorted(found_custom.items()):
            name = metrics["custom_lic_map"].get(l, "")
            a(f'<tr><td>{_lic_badge(l)}</td><td>{_h(name)}</td>'
              f'<td class="num">{c:,}</td>'
              f'<td class="status-review">MANUAL REVIEW REQUIRED</td></tr>')
        a("</tbody></table>")
    else:
        a('<p class="status-ok">No custom license references detected.</p>')

    a('<h3 style="font-size:14px;margin-top:18px;margin-bottom:8px">Non-Allowlisted Files</h3>')
    if lic_viol["violations"]:
        a(f'<p class="status-warn">{len(lic_viol["violations"]):,} file(s) &mdash; '
          f'<a href="#s12">see Section 12</a>.</p>')
    else:
        a('<p class="status-ok">None.</p>')

    a('<h3 style="font-size:14px;margin-top:18px;margin-bottom:8px">Files Missing License Information</h3>')
    if metrics["no_lic_files"]:
        a(f'<p class="status-warn">{len(metrics["no_lic_files"]):,} file(s) &mdash; '
          f'<a href="#s9">see Section 9</a>.</p>')
    else:
        a('<p class="status-ok">None.</p>')

    sec_close()

    # ---- close document -----------------------------------------------
    a("</main>")
    a(f"<script>{_HTML_JS}</script>")
    a("</body>")
    a("</html>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON summary export
# ---------------------------------------------------------------------------

def build_json_summary(metrics: dict, lic_viol: dict, cp_viol: dict, kw_viol: dict) -> dict:
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "spdx_metadata": metrics["spdx_meta"],
        "packages": [
            {
                "name": p.get("name"),
                "spdx_id": p.get("SPDXID"),
                "download_location": p.get("downloadLocation"),
                "originator": p.get("originator"),
                "release_date": p.get("releaseDate"),
                "declared_licenses": p.get("licenseInfoFromFiles", []),
            }
            for p in metrics["packages"]
        ],
        "summary": {
            "total_files": metrics["total_files"],
            "distinct_licenses": len(metrics["lic_counter"]),
            "files_with_license": metrics["total_files"] - len(metrics["no_lic_files"]),
            "files_without_license": len(metrics["no_lic_files"]),
            "files_with_copyright": metrics["total_files"] - len(metrics["no_copyright_files"]),
            "files_without_copyright": len(metrics["no_copyright_files"]),
            "files_with_multiple_licenses": len(metrics["multi_lic_files"]),
            "files_with_custom_licenseref": len(metrics["spdx_ref_files"]),
            "non_allowlisted_files": len(lic_viol["violations"]),
            "copyright_violations": len(cp_viol["violations"]),
            "keyword_violations": len(kw_viol["violations"]),
        },
        "license_distribution": dict(metrics["lic_counter"].most_common()),
        "custom_licenses": metrics["custom_lic_map"],
        "top_copyright_holders": dict(metrics["holder_counter"].most_common(20)),
        "directory_breakdown": {
            d: {
                "total_files": metrics["dir_count"][d],
                "licenses": dict(metrics["dir_lic"][d]),
            }
            for d in metrics["dir_count"]
        },
        "multi_license_files": [
            {"file": f, "licenses": lics}
            for f, lics in metrics["multi_lic_files"]
        ],
        "files_without_license": metrics["no_lic_files"],
        "files_without_copyright": metrics["no_copyright_files"],
        "concluded_vs_detected_mismatch": [
            {"file": f, "concluded": c, "detected": d}
            for f, c, d in metrics["concluded_diff"]
        ],
        "non_allowlisted_violations": lic_viol["violations"],
        "copyright_violation_detail": cp_viol["violations"],
        "keyword_violation_detail": kw_viol["violations"],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze FOSSology scan results and produce a compliance report."
    )
    parser.add_argument(
        "--spdx-dir",
        default="spdx",
        metavar="DIR",
        help="Directory containing FOSSology scan artifacts (default: spdx/)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write Markdown report to FILE (default: print plain-text to stdout)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        dest="json_output",
        help="Write machine-readable JSON summary to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        dest="html_output",
        help="Write self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--no-text",
        action="store_true",
        help="Suppress plain-text output to stdout",
    )
    args = parser.parse_args()

    spdx_dir = Path(args.spdx_dir)
    if not spdx_dir.is_dir():
        print(f"ERROR: directory '{spdx_dir}' not found.", file=sys.stderr)
        return 1

    spdx_file = spdx_dir / "sbom_spdx.json"
    if not spdx_file.exists():
        print(f"ERROR: '{spdx_file}' not found.", file=sys.stderr)
        return 1

    print(f"Loading {spdx_file} ...", file=sys.stderr)
    spdx = parse_spdx(spdx_file)

    print("Parsing violation reports ...", file=sys.stderr)
    lic_viol = parse_violation_file(spdx_dir / "licenses.txt")
    cp_viol = parse_violation_file(spdx_dir / "copyrights.txt")
    kw_viol = parse_violation_file(spdx_dir / "keywords.txt")

    print("Analyzing ...", file=sys.stderr)
    metrics = analyze(spdx)

    if not args.no_text:
        text_report = render_text(metrics, lic_viol, cp_viol, kw_viol)
        print(text_report)

    if args.output:
        md_report = render_markdown(metrics, lic_viol, cp_viol, kw_viol)
        out_path = Path(args.output)
        out_path.write_text(md_report, encoding="utf-8")
        print(f"Markdown report written to: {out_path}", file=sys.stderr)

    if args.json_output:
        summary = build_json_summary(metrics, lic_viol, cp_viol, kw_viol)
        json_path = Path(args.json_output)
        json_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"JSON summary written to: {json_path}", file=sys.stderr)

    if args.html_output:
        html_report = render_html(metrics, lic_viol, cp_viol, kw_viol)
        html_path = Path(args.html_output)
        html_path.write_text(html_report, encoding="utf-8")
        print(f"HTML report written to: {html_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
