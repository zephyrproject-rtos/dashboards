#!/usr/bin/env python3
# Copyright (c) 2026 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0
"""Analyse Zephyr test metadata (tests.yaml) and generate an HTML dashboard.

Walks a Zephyr tree, parses every test descriptor with the same merge
semantics twister uses, then applies a catalogue of rules that flag misuse and
misconfiguration: excessive timeouts, tests that can never execute, scope that
has been narrowed to a single platform, sprawling filters and platform lists,
piles of overlays and Kconfig tweaks, and so on.

Usage:
    ./test_metadata_report.py --root ~/zephyrproject/zephyr \\
        --output test_metadata_report.html
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install PyYAML")

# ---------------------------------------------------------------------------
# Twister semantics (mirrored from scripts/pylib/twister/twisterlib)
# ---------------------------------------------------------------------------

TEST_FILENAMES = ("tests.yaml", "testcase.yaml", "sample.yaml")

# Keys twister accepts in a scenario, with the type used when merging `common`
# into a scenario. Anything outside this set is a schema violation.
VALID_KEYS: dict[str, str] = {
    "tags": "set", "type": "str", "extra_args": "list", "extra_configs": "list",
    "conf_files": "list", "extra_conf_files": "list",
    "extra_overlay_confs": "list", "extra_dtc_overlay_files": "list",
    "required_applications": "list", "required_snippets": "list",
    "build": "bool", "build_only": "bool", "build_on_all": "bool",
    "skip": "bool", "slow": "bool", "timeout": "int", "min_ram": "int",
    "modules": "list", "depends_on": "set", "min_flash": "int",
    "arch_allow": "set", "arch_exclude": "set", "vendor_allow": "set",
    "vendor_exclude": "set", "extra_sections": "list",
    "integration_platforms": "list", "integration_toolchains": "list",
    "ignore_faults": "bool", "ignore_qemu_crash": "bool", "testcases": "list",
    "platform_type": "list", "platform_exclude": "set", "platform_allow": "set",
    "platform_key": "list", "simulation_exclude": "list",
    "toolchain_exclude": "set", "toolchain_allow": "set", "filter": "str",
    "levels": "list", "harness": "str", "harness_config": "map",
    "sidecar": "str", "sidecar_config": "map", "seed": "int",
    "sysbuild": "bool", "expect_reboot": "bool",
}

DEFAULTS = {
    "timeout": 60, "min_ram": 16, "min_flash": 32, "harness": "test",
    "type": "integration", "build_only": False, "build": True, "skip": False,
    "slow": False, "sysbuild": False, "build_on_all": False,
    "ignore_faults": False, "ignore_qemu_crash": False,
}

PYTEST_HARNESSES = {"pytest", "shell", "power", "display_capture"}
SUPPORTED_HARNESSES = {
    "console", "ztest", "test", "gtest", "robot", "ctest", "bsim", "script",
} | PYTEST_HARNESSES

# Fields twister pulls back out of extra_args; setting them there is deprecated.
DEPRECATED_EXTRA_ARGS = ("CONF_FILE", "OVERLAY_CONFIG", "DTC_OVERLAY_FILE")

# Pseudo-platforms that have no board.yml of their own.
PSEUDO_PLATFORMS = {"unit_testing"}

# ---------------------------------------------------------------------------
# Thresholds — every rule that needs a number takes it from here.
# Defaults are calibrated against the upstream tree (roughly the p95-p99 of
# each distribution), so a flagged test really is an outlier.
# ---------------------------------------------------------------------------

TH = {
    "timeout_warn": 600,          # 10 min
    "timeout_high": 1800,         # 30 min
    "filter_terms": 6,            # boolean terms in a filter expression
    "filter_len": 200,            # characters
    "platform_allow": 10,
    "platform_exclude": 8,
    "extra_configs": 8,
    "extra_args": 6,
    "depends_on": 5,
    "scenarios": 20,              # scenarios in one tests.yaml
    "pinned_scenarios": 5,        # single-platform scenarios in one file
    "overlay_files": 20,          # .overlay/.conf files owned by one app
    "board_dirs": 15,             # entries under the app's boards/
    "min_ram": 256,               # KB
}

# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------

SEVERITIES = ("high", "medium", "low")
SEV_WEIGHT = {"high": 5, "medium": 2, "low": 1}

CATEGORIES = ("Correctness", "Runtime cost", "Scope", "Complexity", "Hygiene")

# id -> (severity, category, title, explanation)
RULES: dict[str, tuple[str, str, str, str]] = {
    # --- Correctness: the metadata does not do what its author intended -----
    "placeholder-harness": (
        "high", "Correctness", "Harness is a placeholder",
        "The harness is TBD, none or empty — a stub that was never filled in. "
        "The scenario is built but never executed."),
    "unrunnable-harness": (
        "medium", "Correctness", "Harness is not implemented by twister",
        "The harness name is outside twister's supported set, so the scenario "
        "is built but never executed. Common for hardware-in-the-loop tests, "
        "but it means the metadata claims coverage that CI never exercises."),
    "build-only-with-harness": (
        "high", "Correctness", "build_only with a runtime harness",
        "build_only skips execution, so the runtime harness and its "
        "harness_config are dead configuration."),
    "timeout-on-build-only": (
        "medium", "Correctness", "timeout set on a build_only scenario",
        "Nothing is executed, so the timeout is never applied."),
    "unknown-platform": (
        "high", "Correctness", "References an unknown board",
        "A platform named in platform_allow/platform_exclude/"
        "integration_platforms does not match any board in the tree — likely a "
        "typo or a board that was renamed or removed."),
    "integration-not-allowed": (
        "high", "Correctness", "integration_platforms outside platform_allow",
        "The platform is filtered out by platform_allow, so it never runs in "
        "integration mode."),
    "unknown-key": (
        "high", "Correctness", "Unknown metadata key",
        "The key is not part of the twister testsuite schema and is ignored."),
    "allow-and-exclude": (
        "medium", "Correctness", "allow and exclude list on the same axis",
        "An allow list already restricts the set; the matching exclude list is "
        "redundant and easy to read the wrong way round."),
    "deprecated-extra-args": (
        "medium", "Correctness", "CONF_FILE/OVERLAY_CONFIG in extra_args",
        "Deprecated by twister. Use extra_conf_files, extra_overlay_confs or "
        "extra_dtc_overlay_files instead."),
    "config-in-extra-args": (
        "medium", "Correctness", "Kconfig set through extra_args",
        "Passing -DCONFIG_* through extra_args bypasses extra_configs, so the "
        "setting is invisible to filtering and to config-based reporting."),
    "skipped": (
        "medium", "Correctness", "Scenario is permanently skipped",
        "skip: true means the scenario never runs anywhere. Either fix it or "
        "delete it."),

    # --- Runtime cost -------------------------------------------------------
    "timeout-high": (
        "high", "Runtime cost", "Very long timeout",
        f"timeout is at or above {TH['timeout_high']}s. A test this slow "
        "dominates CI wall-clock and usually hides a loop that should be "
        "bounded or split."),
    "timeout-warn": (
        "medium", "Runtime cost", "Long timeout",
        f"timeout is at or above {TH['timeout_warn']}s, well above the 60s "
        "default."),
    "slow": (
        "low", "Runtime cost", "Marked slow",
        "Only runs when twister is invoked with --enable-slow, so it is "
        "effectively absent from most CI runs."),
    "no-integration-platforms": (
        "medium", "Runtime cost", "Unbounded scope, no integration_platforms",
        "The scenario has no platform or arch restriction and names no "
        "integration platforms, so it is built for every board in scope."),

    # --- Scope: the test is narrower than it looks --------------------------
    "single-platform": (
        "low", "Scope", "Pinned to a single platform",
        "platform_allow names exactly one board, so the scenario provides no "
        "cross-platform coverage."),
    "build-only": (
        "low", "Scope", "Build-only scenario",
        "The scenario is compiled but never executed, so it verifies nothing "
        "about behaviour."),
    "large-platform-allow": (
        "medium", "Scope", "Large platform_allow list",
        f"{TH['platform_allow']}+ boards enumerated by hand. Such lists rot: "
        "prefer a filter, arch_allow, or platform_type."),
    "large-platform-exclude": (
        "medium", "Scope", "Large platform_exclude list",
        f"{TH['platform_exclude']}+ boards excluded one by one, usually a sign "
        "of an unfixed portability problem."),
    "high-min-ram": (
        "low", "Scope", "High min_ram requirement",
        f"min_ram at or above {TH['min_ram']}KB silently drops most boards."),
    "masks-failures": (
        "medium", "Scope", "Failures are ignored",
        "ignore_faults / ignore_qemu_crash suppress real failures, so the "
        "scenario can pass while the device faults."),

    # --- Complexity ---------------------------------------------------------
    "complex-filter": (
        "medium", "Complexity", "Complex filter expression",
        f"{TH['filter_terms']}+ boolean terms. Long filters are expensive to "
        "evaluate and nearly impossible to review."),
    "many-extra-configs": (
        "medium", "Complexity", "Many extra_configs",
        f"{TH['extra_configs']}+ Kconfig overrides. Consider a dedicated "
        "prj.conf fragment or splitting the scenario."),
    "many-extra-args": (
        "low", "Complexity", "Many extra_args",
        f"{TH['extra_args']}+ CMake arguments passed to the build."),
    "many-depends-on": (
        "low", "Complexity", "Long depends_on list",
        f"{TH['depends_on']}+ required hardware features; the scenario will "
        "rarely match a board."),
    "many-scenarios": (
        "medium", "Complexity", "Many scenarios in one file",
        f"{TH['scenarios']}+ scenarios in a single descriptor. Consider "
        "splitting the application."),
    "many-pinned-scenarios": (
        "medium", "Complexity", "Many platform-specific scenarios",
        f"{TH['pinned_scenarios']}+ scenarios in the file are pinned to one "
        "board each, which is board bring-up dressed up as a test suite."),
    "many-overlays": (
        "medium", "Complexity", "Many overlay and conf files",
        f"{TH['overlay_files']}+ .overlay/.conf files belong to this "
        "application."),
    "many-board-dirs": (
        "low", "Complexity", "Large boards/ directory",
        f"{TH['board_dirs']}+ per-board files, which means per-board "
        "maintenance every time the test changes."),

    # --- Hygiene ------------------------------------------------------------
    "no-tags": (
        "low", "Hygiene", "No tags",
        "Without tags the scenario cannot be selected or excluded by tag, and "
        "is invisible to subsystem-level reporting."),
    "empty-scenario": (
        "low", "Hygiene", "Scenario carries no metadata",
        "The scenario body is empty and `common` supplies nothing either."),
}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def find_descriptors(root: Path) -> list[Path]:
    """Return every test descriptor under root, skipping VCS and build dirs."""
    out: list[Path] = []
    skip = {".git", "build", "twister-out", "__pycache__", ".venv"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in skip and not d.startswith("twister-out")]
        for name in TEST_FILENAMES:
            if name in filenames:
                out.append(Path(dirpath) / name)
    return sorted(out)


def boards_root_for(root: Path) -> Path | None:
    """Find the tree that owns the board definitions for `root`.

    Scanning a sub-directory (say tests/kernel) still needs the full board
    list, so walk up to the enclosing Zephyr tree when `root` has no boards/
    of its own.
    """
    for candidate in [root, *root.parents]:
        if (candidate / "boards").is_dir() and (candidate / "Kconfig.zephyr").exists():
            return candidate
    return root if (root / "boards").is_dir() else None


def load_boards(root: Path) -> set[str]:
    """Collect board names from every board.yml in the tree."""
    names: set[str] = set(PSEUDO_PLATFORMS)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "build")]
        if "board.yml" not in filenames:
            continue
        try:
            data = yaml.safe_load((Path(dirpath) / "board.yml").read_text()) or {}
        except (OSError, yaml.YAMLError):
            continue
        board = data.get("board")
        if isinstance(board, dict) and board.get("name"):
            names.add(str(board["name"]))
        for entry in data.get("boards") or []:
            if isinstance(entry, dict) and entry.get("name"):
                names.add(str(entry["name"]))
    return names


def _as_list(value) -> list[str]:
    """Normalise a scalar-or-list metadata value to a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _extract_args(arg_list) -> tuple[dict[str, list[str]], list[str]]:
    """Split CONF_FILE/OVERLAY_CONFIG/DTC_OVERLAY_FILE out of extra_args."""
    extracted: dict[str, list[str]] = {f: [] for f in DEPRECATED_EXTRA_ARGS}
    other: list[str] = []
    args = arg_list.strip().split() if isinstance(arg_list, str) else list(arg_list or [])
    for field in args:
        name, sep, val = str(field).partition("=")
        if sep and name in extracted:
            extracted[name].append(val.strip("'\""))
        else:
            other.append(str(field))
    return extracted, other


def merge_scenario(common: dict, scenario: dict) -> tuple[dict, dict, dict]:
    """Merge `common` into one scenario the way TwisterConfigParser does.

    Returns (merged, explicit, extracted) where `explicit` is the set of keys
    the YAML actually set — as opposed to the ones defaulted in below — and
    `extracted` holds the deprecated fields pulled out of extra_args.
    """
    merged: dict = {}
    extracted_common: dict[str, list[str]] = {}
    extracted_scenario: dict[str, list[str]] = {}

    for key, value in common.items():
        if key == "extra_args":
            extracted_common, merged[key] = _extract_args(value)
        else:
            merged[key] = list(value) if isinstance(value, list) else value

    for key, value in scenario.items():
        if key == "extra_args":
            extracted_scenario, value = _extract_args(value)
        if key not in merged:
            merged[key] = value
            continue
        if key == "filter":
            merged[key] = f"({merged[key]}) and ({value})"
        elif key in ("extra_conf_files", "extra_overlay_confs",
                     "extra_dtc_overlay_files"):
            pass  # recombined below, in order
        elif isinstance(merged[key], str) and isinstance(value, list):
            merged[key] = [merged[key]] + value
        elif isinstance(merged[key], list) and isinstance(value, str):
            merged[key] = merged[key] + [value]
        elif isinstance(merged[key], list) and isinstance(value, list):
            merged[key] = merged[key] + value
        elif isinstance(merged[key], str) and isinstance(value, str):
            merged[key] = value if VALID_KEYS.get(key) == "str" else [merged[key], value]
        else:
            merged[key] = value

    for key in ("extra_conf_files", "extra_overlay_confs",
                "extra_dtc_overlay_files"):
        merged[key] = _as_list(common.get(key)) + _as_list(scenario.get(key))
    merged["extra_overlay_confs"] = (
        extracted_common.get("OVERLAY_CONFIG", [])
        + merged["extra_overlay_confs"]
        + extracted_scenario.get("OVERLAY_CONFIG", []))
    merged["extra_dtc_overlay_files"] = (
        extracted_common.get("DTC_OVERLAY_FILE", [])
        + merged["extra_dtc_overlay_files"]
        + extracted_scenario.get("DTC_OVERLAY_FILE", []))
    merged["conf_files"] = (extracted_common.get("CONF_FILE", [])
                            + extracted_scenario.get("CONF_FILE", []))

    explicit = set(merged)
    for key, default in DEFAULTS.items():
        merged.setdefault(key, default)
    return merged, explicit, (extracted_common, extracted_scenario)


def count_app_files(app_dir: Path, nested: set[Path]) -> dict:
    """Count overlay/conf/board files owned by an application.

    Sub-directories holding their own descriptor belong to another
    application and are not counted here.
    """
    overlays = confs = board_files = 0
    for dirpath, dirnames, filenames in os.walk(app_dir):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames
                       if d not in ("build", ".git", "__pycache__")
                       and (here / d) not in nested]
        in_boards = "boards" in here.relative_to(app_dir).parts
        for name in filenames:
            if name.endswith(".overlay"):
                overlays += 1
            elif name.endswith(".conf"):
                confs += 1
            else:
                continue
            if in_boards:
                board_files += 1
    return {"overlays": overlays, "confs": confs, "board_files": board_files}


_FILTER_TOKEN = re.compile(r"\b(and|or|not|in)\b", re.IGNORECASE)


def filter_terms(expr: str) -> int:
    """Rough term count for a filter expression: operators plus one."""
    return len(_FILTER_TOKEN.findall(expr)) + 1


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

class Finding:
    __slots__ = ("rule", "app", "scenario", "detail")

    def __init__(self, rule: str, app: str, scenario: str | None, detail: str):
        self.rule = rule
        self.app = app
        self.scenario = scenario
        self.detail = detail


def check_scenario(app: str, name: str, raw: dict, common: dict, merged: dict,
                   explicit: set[str], extracted: tuple[dict, dict],
                   boards: set[str], findings: list[Finding]) -> None:
    """Apply every per-scenario rule."""
    add = lambda rule, detail: findings.append(Finding(rule, app, name, detail))

    # -- schema ------------------------------------------------------------
    for key in raw:
        if key not in VALID_KEYS:
            add("unknown-key", key)

    # -- harness and execution --------------------------------------------
    harness = str(merged.get("harness") or "").strip()
    build_only = bool(merged.get("build_only"))
    runnable_harness = harness in SUPPORTED_HARNESSES
    if not runnable_harness:
        if harness.lower() in ("", "tbd", "none", "n/a"):
            add("placeholder-harness", f"harness: {harness or '(empty)'}")
        else:
            add("unrunnable-harness", f"harness: {harness}")
    # bsim images are built by twister and executed by the bsim runner, so
    # build_only + harness: bsim (and its timeout) is the intended idiom.
    deferred = harness in ("test", "ztest", "bsim")
    if build_only and runnable_harness and not deferred:
        add("build-only-with-harness", f"harness: {harness}")
    if build_only and not deferred and "timeout" in explicit:
        add("timeout-on-build-only", f"timeout: {merged['timeout']}s")
    if build_only:
        add("build-only", "")
    if merged.get("skip"):
        add("skipped", "")
    if merged.get("slow"):
        add("slow", "")
    if merged.get("ignore_faults") or merged.get("ignore_qemu_crash"):
        flags = [k for k in ("ignore_faults", "ignore_qemu_crash") if merged.get(k)]
        add("masks-failures", ", ".join(flags))

    # -- timeout -----------------------------------------------------------
    timeout = merged.get("timeout", DEFAULTS["timeout"])
    if isinstance(timeout, int) and not build_only:
        if timeout >= TH["timeout_high"]:
            add("timeout-high", f"{timeout}s ({timeout / 60:.0f} min)")
        elif timeout >= TH["timeout_warn"]:
            add("timeout-warn", f"{timeout}s ({timeout / 60:.0f} min)")

    # -- platform scope ----------------------------------------------------
    allow = _as_list(merged.get("platform_allow"))
    exclude = _as_list(merged.get("platform_exclude"))
    integration = _as_list(merged.get("integration_platforms"))
    arch_allow = _as_list(merged.get("arch_allow"))

    if boards is not None:
        for platform in set(allow) | set(exclude) | set(integration):
            if platform.split("/")[0].split("@")[0] not in boards:
                add("unknown-platform", platform)
    if allow:
        stray = [p for p in integration if p not in allow]
        if stray:
            add("integration-not-allowed", ", ".join(sorted(stray)[:5]))
    if len(allow) == 1 and merged.get("type") != "unit":
        add("single-platform", allow[0])
    if len(allow) >= TH["platform_allow"]:
        add("large-platform-allow", f"{len(allow)} boards")
    if len(exclude) >= TH["platform_exclude"]:
        add("large-platform-exclude", f"{len(exclude)} boards")
    for axis in ("platform", "arch", "toolchain", "vendor"):
        if merged.get(f"{axis}_allow") and merged.get(f"{axis}_exclude"):
            add("allow-and-exclude", axis)
    if not allow and not arch_allow and not integration and not build_only \
            and merged.get("type") != "unit":
        add("no-integration-platforms", "")

    min_ram = merged.get("min_ram", DEFAULTS["min_ram"])
    if isinstance(min_ram, int) and min_ram >= TH["min_ram"]:
        add("high-min-ram", f"{min_ram}KB")

    # -- complexity --------------------------------------------------------
    expr = merged.get("filter")
    if isinstance(expr, str) and expr.strip():
        terms = filter_terms(expr)
        if terms >= TH["filter_terms"] or len(expr) >= TH["filter_len"]:
            add("complex-filter", f"{terms} terms, {len(expr)} chars")

    configs = _as_list(merged.get("extra_configs"))
    if len(configs) >= TH["extra_configs"]:
        add("many-extra-configs", f"{len(configs)} entries")
    args = _as_list(merged.get("extra_args"))
    if len(args) >= TH["extra_args"]:
        add("many-extra-args", f"{len(args)} entries")
    inline = [a for a in args if re.match(r"-?D?CONFIG_[A-Z0-9_]+=", a)]
    if inline:
        add("config-in-extra-args", ", ".join(inline[:3]))
    depends = _as_list(merged.get("depends_on"))
    if len(depends) >= TH["depends_on"]:
        add("many-depends-on", ", ".join(sorted(depends)[:6]))

    for block in extracted:  # common first, then scenario
        used = [f for f in DEPRECATED_EXTRA_ARGS if block.get(f)]
        if used:
            add("deprecated-extra-args", ", ".join(used))
            break

    # -- hygiene -----------------------------------------------------------
    if not _as_list(merged.get("tags")):
        add("no-tags", "")
    if not raw and not common:
        add("empty-scenario", "")


def check_application(app: str, scenarios: dict, files: dict,
                      pinned: int, findings: list[Finding]) -> None:
    """Apply every per-application rule."""
    add = lambda rule, detail: findings.append(Finding(rule, app, None, detail))

    if len(scenarios) >= TH["scenarios"]:
        add("many-scenarios", f"{len(scenarios)} scenarios")
    if pinned >= TH["pinned_scenarios"]:
        add("many-pinned-scenarios",
            f"{pinned} of {len(scenarios)} pinned to one board")
    total = files["overlays"] + files["confs"]
    if total >= TH["overlay_files"]:
        add("many-overlays",
            f"{files['overlays']} .overlay + {files['confs']} .conf")
    if files["board_files"] >= TH["board_dirs"]:
        add("many-board-dirs", f"{files['board_files']} files under boards/")


# ---------------------------------------------------------------------------
# Analysis driver
# ---------------------------------------------------------------------------

def area_of(rel: str) -> str:
    """Group applications by their top two path components."""
    parts = Path(rel).parts
    return "/".join(parts[:2]) if len(parts) > 2 else (parts[0] if parts else "?")


def analyse(root: Path, boards_root: Path | None, verbose: bool) -> dict:
    descriptors = find_descriptors(root)
    if not descriptors:
        sys.exit(f"No test descriptors found under {root}")
    if verbose:
        print(f"Found {len(descriptors)} descriptors", file=sys.stderr)

    boards = load_boards(boards_root) if boards_root else set(PSEUDO_PLATFORMS)
    # Without a credible board list every platform name looks unknown, so the
    # rule is switched off rather than fired thousands of times.
    known_boards = len(boards) > len(PSEUDO_PLATFORMS)
    if verbose:
        if known_boards:
            print(f"Known boards: {len(boards)} (from {boards_root})",
                  file=sys.stderr)
        else:
            print("No board definitions found — skipping the unknown-platform "
                  "check. Pass --boards-root to enable it.", file=sys.stderr)

    app_dirs = {p.parent for p in descriptors}
    # For each application, the immediate sub-directories that belong to a
    # *different* application; count_app_files stops descending into those.
    nested_of: dict[Path, set[Path]] = defaultdict(set)
    for d in app_dirs:
        for parent in d.parents:
            if parent in app_dirs:
                nested_of[parent].add(d)
                break
    findings: list[Finding] = []
    apps: list[dict] = []
    parse_errors: list[dict] = []

    timeouts: list[int] = []
    harness_counts: Counter = Counter()
    tag_counts: Counter = Counter()
    scenario_total = 0

    for path in descriptors:
        rel = str(path.relative_to(root))
        app = str(path.parent.relative_to(root)) or "."
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError) as exc:
            parse_errors.append({"file": rel, "error": str(exc)})
            continue
        if not isinstance(data, dict):
            parse_errors.append({"file": rel, "error": "not a mapping"})
            continue

        common = data.get("common") or {}
        scenarios = data.get("tests") or {}
        if not isinstance(scenarios, dict):
            parse_errors.append({"file": rel, "error": "'tests' is not a mapping"})
            continue

        files = count_app_files(path.parent, nested_of[path.parent])

        before = len(findings)
        pinned = 0
        for name, body in scenarios.items():
            raw = body if isinstance(body, dict) else {}
            merged, explicit, extracted = merge_scenario(common, raw)
            scenario_total += 1
            timeouts.append(merged.get("timeout", DEFAULTS["timeout"]))
            harness_counts[str(merged.get("harness") or "test")] += 1
            for tag in _as_list(merged.get("tags")):
                tag_counts[tag] += 1
            if len(_as_list(merged.get("platform_allow"))) == 1:
                pinned += 1
            check_scenario(app, name, raw, common, merged, explicit,
                           extracted, boards if known_boards else None,
                           findings)

        check_application(app, scenarios, files, pinned, findings)

        app_findings = findings[before:]
        counts: Counter = Counter(RULES[f.rule][0] for f in app_findings)
        apps.append({
            "app": app,
            "file": rel,
            "area": area_of(rel),
            "scenarios": len(scenarios),
            "pinned": pinned,
            "overlays": files["overlays"],
            "confs": files["confs"],
            "board_files": files["board_files"],
            "findings": len(app_findings),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "score": sum(SEV_WEIGHT[RULES[f.rule][0]] for f in app_findings),
        })

    return {
        "root": str(root),
        "apps": apps,
        "findings": findings,
        "parse_errors": parse_errors,
        "n_files": len(descriptors),
        "n_scenarios": scenario_total,
        "n_boards": len(boards) if known_boards else 0,
        "timeouts": timeouts,
        "harness": harness_counts,
        "tags": tag_counts,
    }


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

TIMEOUT_BUCKETS = [
    ("< 60s", lambda t: t < 60),
    ("60s (default)", lambda t: t == 60),
    ("≤ 120s", lambda t: 60 < t <= 120),
    ("≤ 300s", lambda t: 120 < t <= 300),
    ("≤ 600s", lambda t: 300 < t <= 600),
    ("≤ 1200s", lambda t: 600 < t <= 1200),
    ("≤ 1800s", lambda t: 1200 < t <= 1800),
    ("≤ 3600s", lambda t: 1800 < t <= 3600),
    ("> 3600s", lambda t: t > 3600),
]

SEV_COLOR = {"high": "#f85149", "medium": "#d29922", "low": "#58a6ff"}
CAT_COLOR = {
    "Correctness": "#f85149", "Runtime cost": "#db6d28", "Scope": "#d29922",
    "Complexity": "#a371f7", "Hygiene": "#58a6ff",
}


def render_html(res: dict, generated: str, top: int) -> str:
    findings: list[Finding] = res["findings"]
    apps: list[dict] = res["apps"]

    by_rule = Counter(f.rule for f in findings)
    by_sev = Counter(RULES[f.rule][0] for f in findings)
    by_cat = Counter(RULES[f.rule][1] for f in findings)
    area_of_app = {a["app"]: a["area"] for a in apps}
    by_area = Counter(area_of_app.get(f.app, "?") for f in findings)

    timeouts = res["timeouts"]
    timeout_labels = [label for label, _ in TIMEOUT_BUCKETS]
    timeout_data = [sum(1 for t in timeouts if isinstance(t, int) and pred(t))
                    for _, pred in TIMEOUT_BUCKETS]

    # Rule catalogue, ordered by severity then hit count.
    rule_rows = []
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for rule in sorted(RULES, key=lambda r: (order[RULES[r][0]], -by_rule[r])):
        sev, cat, title, desc = RULES[rule]
        hits = by_rule[rule]
        rule_rows.append(
            f'<tr class="{"zero" if not hits else ""}">'
            f'<td><span class="sev {sev}">{sev}</span></td>'
            f'<td><code>{html.escape(rule)}</code></td>'
            f'<td>{html.escape(cat)}</td>'
            f'<td><b>{html.escape(title)}</b><div class="desc">'
            f'{html.escape(desc)}</div></td>'
            f'<td class="num">{hits}</td></tr>')

    # Client-side data. Applications are keyed by index to keep the blob small.
    app_index = {a["app"]: i for i, a in enumerate(apps)}
    findings_js = [
        [app_index[f.app], f.rule, f.scenario or "", f.detail]
        for f in findings
    ]
    apps_js = [[a["app"], a["file"], a["area"], a["scenarios"], a["score"],
                a["high"], a["medium"], a["low"], a["overlays"], a["confs"],
                a["board_files"], a["pinned"]] for a in apps]
    rules_js = {r: {"sev": v[0], "cat": v[1], "title": v[2]}
                for r, v in RULES.items()}

    flagged = sum(1 for a in apps if a["findings"])
    errors_html = ""
    if res["parse_errors"]:
        rows = "\n".join(
            f'<tr><td><code>{html.escape(e["file"])}</code></td>'
            f'<td>{html.escape(e["error"][:200])}</td></tr>'
            for e in res["parse_errors"])
        errors_html = (
            '<div class="card"><h2>Files that failed to parse '
            f'({len(res["parse_errors"])})</h2>'
            f'<table><thead><tr><th>File</th><th>Error</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')

    top_harness = res["harness"].most_common(12)

    return _TEMPLATE.format(
        root=html.escape(res["root"]),
        generated=html.escape(generated),
        n_files=res["n_files"],
        n_scenarios=res["n_scenarios"],
        n_apps=len(apps),
        n_flagged=flagged,
        pct_flagged=f"{100 * flagged / len(apps):.0f}" if apps else "0",
        n_findings=len(findings),
        n_high=by_sev.get("high", 0),
        n_medium=by_sev.get("medium", 0),
        n_low=by_sev.get("low", 0),
        boards_note=(f'{res["n_boards"]} boards' if res["n_boards"]
                     else "board validation off (no boards/ found)"),
        rule_rows="\n".join(rule_rows),
        errors_html=errors_html,
        top=top,
        sev_json=json.dumps([by_sev.get(s, 0) for s in SEVERITIES]),
        sev_labels_json=json.dumps(list(SEVERITIES)),
        sev_colors_json=json.dumps([SEV_COLOR[s] for s in SEVERITIES]),
        cat_labels_json=json.dumps([c for c in CATEGORIES if by_cat.get(c)]),
        cat_data_json=json.dumps([by_cat[c] for c in CATEGORIES if by_cat.get(c)]),
        cat_colors_json=json.dumps([CAT_COLOR[c] for c in CATEGORIES
                                    if by_cat.get(c)]),
        rule_labels_json=json.dumps([r for r, _ in by_rule.most_common(15)]),
        rule_data_json=json.dumps([n for _, n in by_rule.most_common(15)]),
        rule_colors_json=json.dumps([SEV_COLOR[RULES[r][0]]
                                     for r, _ in by_rule.most_common(15)]),
        area_labels_json=json.dumps([a for a, _ in by_area.most_common(15)]),
        area_data_json=json.dumps([n for _, n in by_area.most_common(15)]),
        timeout_labels_json=json.dumps(timeout_labels),
        timeout_data_json=json.dumps(timeout_data),
        harness_labels_json=json.dumps([h for h, _ in top_harness]),
        harness_data_json=json.dumps([n for _, n in top_harness]),
        harness_colors_json=json.dumps(
            ["#3fb950" if h in SUPPORTED_HARNESSES else "#f85149"
             for h, _ in top_harness]),
        areas_json=json.dumps(sorted({a["area"] for a in apps})),
        apps_json=json.dumps(apps_js, separators=(",", ":")),
        findings_json=json.dumps(findings_js, separators=(",", ":")),
        rules_json=json.dumps(rules_js, separators=(",", ":")),
    )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zephyr Test Metadata Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:#0d1117; --card:#161b22; --border:#30363d; --fg:#e6edf3;
    --muted:#8b949e; --accent:#58a6ff;
    --high:#f85149; --medium:#d29922; --low:#58a6ff;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    font-size:14px; }}
  header {{ padding:20px 28px; border-bottom:1px solid var(--border); }}
  h1 {{ margin:0 0 4px; font-size:1.3rem; }}
  .sub {{ color:var(--muted); font-size:.85rem; }}
  main {{ padding:20px 28px; max-width:1400px; margin:0 auto; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat {{ background:var(--card); border:1px solid var(--border);
    border-radius:8px; padding:14px 18px; min-width:140px; }}
  .stat .v {{ font-size:1.6rem; font-weight:700; }}
  .stat .l {{ color:var(--muted); font-size:.78rem; text-transform:uppercase;
    letter-spacing:.04em; }}
  .stat.high .v {{ color:var(--high); }}
  .stat.medium .v {{ color:var(--medium); }}
  .stat.low .v {{ color:var(--low); }}
  .card {{ background:var(--card); border:1px solid var(--border);
    border-radius:8px; padding:16px 18px; margin-bottom:24px; }}
  .card h2 {{ margin:0 0 4px; font-size:1rem; }}
  .card .hint {{ color:var(--muted); font-size:.8rem; margin-bottom:12px; }}
  .chart-wrap {{ position:relative; height:300px; }}
  .row {{ display:flex; gap:24px; flex-wrap:wrap; }}
  .row > .card {{ flex:1; min-width:340px; }}
  table {{ border-collapse:collapse; width:100%; font-size:.85rem; }}
  th,td {{ padding:7px 10px; border-bottom:1px solid var(--border);
    text-align:left; vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; }}
  th.sortable {{ cursor:pointer; user-select:none; }}
  th.sortable:hover {{ color:var(--fg); }}
  td.num,th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size:.82rem; color:#a5d6ff; }}
  .desc {{ color:var(--muted); font-size:.78rem; margin-top:2px;
    max-width:60ch; }}
  .sev {{ display:inline-block; padding:1px 8px; border-radius:10px;
    font-size:.72rem; font-weight:600; text-transform:uppercase;
    letter-spacing:.03em; }}
  .sev.high {{ background:rgba(248,81,73,.18); color:var(--high); }}
  .sev.medium {{ background:rgba(210,153,34,.18); color:var(--medium); }}
  .sev.low {{ background:rgba(88,166,255,.18); color:var(--low); }}
  tr.zero {{ opacity:.4; }}
  .controls {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    margin-bottom:16px; }}
  .controls label {{ color:var(--muted); font-size:.85rem; }}
  .controls select, .controls input {{ background:#0d1117; color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px;
    font-size:.85rem; }}
  .controls input {{ min-width:260px; }}
  .controls button {{ background:var(--card); color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:6px 12px;
    cursor:pointer; font-size:.85rem; }}
  .controls button:hover {{ border-color:var(--accent); color:var(--accent); }}
  .pager {{ display:flex; gap:8px; align-items:center; margin-top:12px;
    color:var(--muted); font-size:.82rem; }}
  .pager button {{ background:var(--card); color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:4px 10px;
    cursor:pointer; }}
  .pager button:disabled {{ opacity:.35; cursor:default; }}
  .bar {{ height:6px; border-radius:3px; background:#21262d; overflow:hidden;
    min-width:80px; display:flex; }}
  .bar i {{ display:block; height:100%; }}
  .app-row {{ cursor:pointer; }}
  .app-row:hover td {{ background:#1c2128; }}
  .detail td {{ background:#0d1117; padding:0 10px 10px 30px; }}
  .detail ul {{ margin:6px 0; padding-left:16px; }}
  .detail li {{ margin:3px 0; color:var(--muted); }}
  .detail li b {{ color:var(--fg); font-weight:600; }}
  .empty {{ color:var(--muted); padding:20px; text-align:center; }}
</style>
</head>
<body>
<header>
  <h1>Zephyr Test Metadata Report</h1>
  <div class="sub">{root} &nbsp;·&nbsp; {n_files} descriptors ·
    {n_scenarios} scenarios · {boards_note} &nbsp;·&nbsp;
    generated {generated}</div>
</header>
<main>

<div class="cards">
  <div class="stat"><div class="v">{n_apps}</div><div class="l">Test apps</div></div>
  <div class="stat"><div class="v">{n_scenarios}</div><div class="l">Scenarios</div></div>
  <div class="stat"><div class="v">{n_findings}</div><div class="l">Findings</div></div>
  <div class="stat high"><div class="v">{n_high}</div><div class="l">High</div></div>
  <div class="stat medium"><div class="v">{n_medium}</div><div class="l">Medium</div></div>
  <div class="stat low"><div class="v">{n_low}</div><div class="l">Low</div></div>
  <div class="stat"><div class="v">{pct_flagged}%</div><div class="l">Apps flagged</div></div>
</div>

<div class="row">
  <div class="card">
    <h2>Findings by category</h2>
    <div class="hint">What kind of problem the metadata has.</div>
    <div class="chart-wrap"><canvas id="catChart"></canvas></div>
  </div>
  <div class="card">
    <h2>Most frequent rules</h2>
    <div class="hint">Bar colour is the rule's severity.</div>
    <div class="chart-wrap"><canvas id="ruleChart"></canvas></div>
  </div>
</div>

<div class="row">
  <div class="card">
    <h2>Timeout distribution</h2>
    <div class="hint">Effective timeout per scenario after merging
      <code>common</code>; the twister default is 60s.</div>
    <div class="chart-wrap"><canvas id="timeoutChart"></canvas></div>
  </div>
  <div class="card">
    <h2>Harnesses in use</h2>
    <div class="hint">Red bars are names twister does not implement — those
      scenarios can never be executed.</div>
    <div class="chart-wrap"><canvas id="harnessChart"></canvas></div>
  </div>
</div>

<div class="card">
  <h2>Findings by area</h2>
  <div class="hint">Top-level test areas ranked by number of findings.</div>
  <div class="chart-wrap"><canvas id="areaChart"></canvas></div>
</div>

<div class="card">
  <h2>Test applications needing attention</h2>
  <div class="hint">Ranked by weighted score (high&nbsp;=&nbsp;5,
    medium&nbsp;=&nbsp;2, low&nbsp;=&nbsp;1). Click a row for its findings.</div>
  <div class="controls">
    <input id="appSearch" placeholder="Filter by path…" oninput="renderApps()">
    <label for="appArea">Area</label>
    <select id="appArea" onchange="renderApps()"></select>
    <label for="appSev">Minimum severity</label>
    <select id="appSev" onchange="renderApps()">
      <option value="any">any</option>
      <option value="high">high only</option>
      <option value="medium">medium and up</option>
    </select>
    <button onclick="resetApps()">Reset</button>
  </div>
  <table id="appTable">
    <thead><tr>
      <th class="sortable" onclick="sortApps(0)">Application</th>
      <th class="num sortable" onclick="sortApps(3)">Scen</th>
      <th class="num sortable" onclick="sortApps(11)">Pinned</th>
      <th class="num sortable" onclick="sortApps(8)">Overlays</th>
      <th class="num sortable" onclick="sortApps(9)">Confs</th>
      <th class="num sortable" onclick="sortApps(5)">High</th>
      <th class="num sortable" onclick="sortApps(6)">Med</th>
      <th class="num sortable" onclick="sortApps(7)">Low</th>
      <th class="num sortable" onclick="sortApps(4)">Score</th>
      <th style="width:120px">Mix</th>
    </tr></thead>
    <tbody id="appBody"></tbody>
  </table>
  <div class="pager">
    <button id="appPrev" onclick="pageApps(-1)">Prev</button>
    <span id="appInfo"></span>
    <button id="appNext" onclick="pageApps(1)">Next</button>
  </div>
</div>

<div class="card">
  <h2>All findings</h2>
  <div class="hint">Every rule hit, filterable. Search matches the application
    path, the scenario name and the detail.</div>
  <div class="controls">
    <input id="fSearch" placeholder="Search path, rule, scenario…"
      oninput="renderFindings()">
    <label for="fRule">Rule</label>
    <select id="fRule" onchange="renderFindings()"></select>
    <label for="fSev">Severity</label>
    <select id="fSev" onchange="renderFindings()">
      <option value="">all</option><option>high</option>
      <option>medium</option><option>low</option>
    </select>
    <label for="fArea">Area</label>
    <select id="fArea" onchange="renderFindings()"></select>
    <button onclick="resetFindings()">Reset</button>
  </div>
  <table>
    <thead><tr>
      <th>Sev</th><th>Rule</th><th>Application</th><th>Scenario</th>
      <th>Detail</th>
    </tr></thead>
    <tbody id="fBody"></tbody>
  </table>
  <div class="pager">
    <button id="fPrev" onclick="pageFindings(-1)">Prev</button>
    <span id="fInfo"></span>
    <button id="fNext" onclick="pageFindings(1)">Next</button>
  </div>
</div>

<div class="card">
  <h2>Rule catalogue</h2>
  <div class="hint">Rules that matched nothing are dimmed.</div>
  <table>
    <thead><tr><th>Sev</th><th>Rule</th><th>Category</th>
      <th>What it means</th><th class="num">Hits</th></tr></thead>
    <tbody>{rule_rows}</tbody>
  </table>
</div>

{errors_html}

</main>
<script>
const APPS = {apps_json};
const FINDINGS = {findings_json};
const RULES = {rules_json};
const AREAS = {areas_json};
const PAGE = {top};

// APPS columns: 0 app, 1 file, 2 area, 3 scenarios, 4 score, 5 high,
// 6 medium, 7 low, 8 overlays, 9 confs, 10 board files, 11 pinned
const byApp = new Map();
FINDINGS.forEach(f => {{
  if (!byApp.has(f[0])) byApp.set(f[0], []);
  byApp.get(f[0]).push(f);
}});

const esc = s => String(s).replace(/[&<>"]/g,
  c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}})[c]);

// ---- charts ---------------------------------------------------------------
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = '-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif';

new Chart(document.getElementById('catChart'), {{
  type: 'doughnut',
  data: {{ labels: {cat_labels_json},
    datasets: [{{ data: {cat_data_json}, backgroundColor: {cat_colors_json},
      borderColor: '#161b22', borderWidth: 2 }}] }},
  options: {{ maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'right' }} }} }}
}});

new Chart(document.getElementById('ruleChart'), {{
  type: 'bar',
  data: {{ labels: {rule_labels_json},
    datasets: [{{ data: {rule_data_json}, backgroundColor: {rule_colors_json} }}] }},
  options: {{ indexAxis: 'y', maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ ticks: {{ font: {{ size: 10 }} }} }} }} }}
}});

new Chart(document.getElementById('timeoutChart'), {{
  type: 'bar',
  data: {{ labels: {timeout_labels_json},
    datasets: [{{ data: {timeout_data_json}, backgroundColor: '#58a6ff' }}] }},
  options: {{ maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ type: 'logarithmic' }} }} }}
}});

new Chart(document.getElementById('harnessChart'), {{
  type: 'bar',
  data: {{ labels: {harness_labels_json},
    datasets: [{{ data: {harness_data_json},
      backgroundColor: {harness_colors_json} }}] }},
  options: {{ maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }} }}
}});

new Chart(document.getElementById('areaChart'), {{
  type: 'bar',
  data: {{ labels: {area_labels_json},
    datasets: [{{ data: {area_data_json}, backgroundColor: '#a371f7' }}] }},
  options: {{ maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }} }}
}});

// ---- applications table ---------------------------------------------------
let appSort = 4, appDesc = true, appPage = 0, appOpen = new Set();

function appFiltered() {{
  const q = document.getElementById('appSearch').value.toLowerCase();
  const area = document.getElementById('appArea').value;
  const sev = document.getElementById('appSev').value;
  return APPS.map((a, i) => [a, i]).filter(([a]) => {{
    if (!a[4]) return false;
    if (q && !a[0].toLowerCase().includes(q)) return false;
    if (area && a[2] !== area) return false;
    if (sev === 'high' && !a[5]) return false;
    if (sev === 'medium' && !a[5] && !a[6]) return false;
    return true;
  }}).sort((x, y) => {{
    const u = x[0][appSort], v = y[0][appSort];
    const c = typeof u === 'string' ? u.localeCompare(v) : u - v;
    return appDesc ? -c : c;
  }});
}}

function mixBar(a) {{
  const t = a[5] * 5 + a[6] * 2 + a[7] || 1;
  const seg = (n, w, c) => n
    ? `<i style="width:${{100 * n * w / t}}%;background:${{c}}"></i>` : '';
  return '<div class="bar">' + seg(a[5], 5, '#f85149') +
    seg(a[6], 2, '#d29922') + seg(a[7], 1, '#58a6ff') + '</div>';
}}

function renderApps(keepPage) {{
  if (!keepPage) appPage = 0;
  const rows = appFiltered();
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  if (appPage >= pages) appPage = pages - 1;
  const slice = rows.slice(appPage * PAGE, appPage * PAGE + PAGE);
  const body = document.getElementById('appBody');
  if (!slice.length) {{
    body.innerHTML = '<tr><td colspan="10" class="empty">No matching applications.</td></tr>';
  }} else {{
    body.innerHTML = slice.map(([a, i]) => {{
      const open = appOpen.has(i);
      const fs = (byApp.get(i) || []).map(f => {{
        const r = RULES[f[1]];
        const where = f[2] ? `<code>${{esc(f[2])}}</code> — ` : '';
        const det = f[3] ? ` <span style="color:#8b949e">(${{esc(f[3])}})</span>` : '';
        return `<li>${{where}}<b>${{esc(r.title)}}</b>${{det}}
          <span class="sev ${{r.sev}}">${{r.sev}}</span></li>`;
      }}).join('');
      return `<tr class="app-row" onclick="toggleApp(${{i}})">
        <td><code>${{esc(a[0])}}</code></td>
        <td class="num">${{a[3]}}</td><td class="num">${{a[11] || ''}}</td>
        <td class="num">${{a[8] || ''}}</td><td class="num">${{a[9] || ''}}</td>
        <td class="num">${{a[5] || ''}}</td><td class="num">${{a[6] || ''}}</td>
        <td class="num">${{a[7] || ''}}</td>
        <td class="num"><b>${{a[4]}}</b></td><td>${{mixBar(a)}}</td></tr>` +
        (open ? `<tr class="detail"><td colspan="10"><ul>${{fs}}</ul></td></tr>` : '');
    }}).join('');
  }}
  document.getElementById('appInfo').textContent =
    `${{rows.length}} applications · page ${{appPage + 1}} of ${{pages}}`;
  document.getElementById('appPrev').disabled = appPage === 0;
  document.getElementById('appNext').disabled = appPage >= pages - 1;
}}

function toggleApp(i) {{
  appOpen.has(i) ? appOpen.delete(i) : appOpen.add(i);
  renderApps(true);
}}
function sortApps(col) {{
  if (appSort === col) appDesc = !appDesc;
  else {{ appSort = col; appDesc = col !== 0; }}
  renderApps();
}}
function pageApps(d) {{ appPage += d; renderApps(true); }}
function resetApps() {{
  document.getElementById('appSearch').value = '';
  document.getElementById('appArea').value = '';
  document.getElementById('appSev').value = 'any';
  renderApps();
}}

// ---- findings table -------------------------------------------------------
let fPage = 0;

function fFiltered() {{
  const q = document.getElementById('fSearch').value.toLowerCase();
  const rule = document.getElementById('fRule').value;
  const sev = document.getElementById('fSev').value;
  const area = document.getElementById('fArea').value;
  return FINDINGS.filter(f => {{
    const a = APPS[f[0]];
    if (rule && f[1] !== rule) return false;
    if (sev && RULES[f[1]].sev !== sev) return false;
    if (area && a[2] !== area) return false;
    if (q && !(a[0] + ' ' + f[1] + ' ' + f[2] + ' ' + f[3])
        .toLowerCase().includes(q)) return false;
    return true;
  }});
}}

function renderFindings(keepPage) {{
  if (!keepPage) fPage = 0;
  const rows = fFiltered();
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  if (fPage >= pages) fPage = pages - 1;
  const slice = rows.slice(fPage * PAGE, fPage * PAGE + PAGE);
  const body = document.getElementById('fBody');
  body.innerHTML = slice.length ? slice.map(f => {{
    const a = APPS[f[0]], r = RULES[f[1]];
    return `<tr><td><span class="sev ${{r.sev}}">${{r.sev}}</span></td>
      <td><code>${{esc(f[1])}}</code><div class="desc">${{esc(r.title)}}</div></td>
      <td><code>${{esc(a[0])}}</code></td>
      <td>${{f[2] ? `<code>${{esc(f[2])}}</code>` : '<span style="color:#8b949e">—</span>'}}</td>
      <td>${{esc(f[3])}}</td></tr>`;
  }}).join('') : '<tr><td colspan="5" class="empty">No matching findings.</td></tr>';
  document.getElementById('fInfo').textContent =
    `${{rows.length}} findings · page ${{fPage + 1}} of ${{pages}}`;
  document.getElementById('fPrev').disabled = fPage === 0;
  document.getElementById('fNext').disabled = fPage >= pages - 1;
}}

function pageFindings(d) {{ fPage += d; renderFindings(true); }}
function resetFindings() {{
  document.getElementById('fSearch').value = '';
  document.getElementById('fRule').value = '';
  document.getElementById('fSev').value = '';
  document.getElementById('fArea').value = '';
  renderFindings();
}}

// ---- boot -----------------------------------------------------------------
const areaOpts = '<option value="">all</option>' +
  AREAS.map(a => `<option>${{esc(a)}}</option>`).join('');
document.getElementById('appArea').innerHTML = areaOpts;
document.getElementById('fArea').innerHTML = areaOpts;

const hits = {{}};
FINDINGS.forEach(f => hits[f[1]] = (hits[f[1]] || 0) + 1);
document.getElementById('fRule').innerHTML = '<option value="">all</option>' +
  Object.keys(hits).sort((a, b) => hits[b] - hits[a])
    .map(r => `<option value="${{esc(r)}}">${{esc(r)}} (${{hits[r]}})</option>`).join('');

renderApps();
renderFindings();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def default_root() -> Path:
    env = os.environ.get("ZEPHYR_BASE")
    if env:
        return Path(env)
    here = Path.cwd()
    for candidate in [here, *here.parents]:
        if (candidate / "Kconfig.zephyr").exists():
            return candidate
        if (candidate / "zephyr" / "Kconfig.zephyr").exists():
            return candidate / "zephyr"
    return here


def main() -> int:
    p = argparse.ArgumentParser(
        description="Analyse Zephyr test metadata and generate an HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  %(prog)s --root ~/zephyrproject/zephyr "
               "--output test_metadata_report.html\n")
    p.add_argument("--root", type=Path, default=None,
                   help="Zephyr tree to scan (default: $ZEPHYR_BASE or the "
                        "enclosing Zephyr workspace)")
    p.add_argument("--boards-root", type=Path, default=None,
                   help="tree to read board definitions from when validating "
                        "platform names (default: the Zephyr tree enclosing "
                        "--root)")
    p.add_argument("--output", default="test_metadata_report.html",
                   help="HTML output path (default: %(default)s)")
    p.add_argument("--json", dest="json_out",
                   help="also write the raw findings as JSON")
    p.add_argument("--top", type=int, default=50,
                   help="rows per page in the tables (default: %(default)s)")
    p.add_argument("--fail-on-high", action="store_true",
                   help="exit non-zero if any high-severity finding was found")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress progress output")
    args = p.parse_args()

    root = (args.root or default_root()).expanduser().resolve()
    if not root.is_dir():
        return print(f"Not a directory: {root}", file=sys.stderr) or 1

    boards_root = args.boards_root
    if boards_root is not None:
        boards_root = boards_root.expanduser().resolve()
    else:
        boards_root = boards_root_for(root)

    res = analyse(root, boards_root, verbose=not args.quiet)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    Path(args.output).write_text(render_html(res, generated, args.top))

    if args.json_out:
        payload = {
            "generated": generated,
            "root": str(root),
            "totals": {
                "descriptors": res["n_files"],
                "applications": len(res["apps"]),
                "scenarios": res["n_scenarios"],
                "findings": len(res["findings"]),
            },
            "rules": {r: {"severity": v[0], "category": v[1], "title": v[2],
                          "description": v[3]} for r, v in RULES.items()},
            "thresholds": TH,
            "applications": res["apps"],
            "findings": [{"rule": f.rule, "severity": RULES[f.rule][0],
                          "application": f.app, "scenario": f.scenario,
                          "detail": f.detail} for f in res["findings"]],
            "parse_errors": res["parse_errors"],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2))

    by_sev = Counter(RULES[f.rule][0] for f in res["findings"])
    if not args.quiet:
        print(f"{res['n_files']} descriptors, {res['n_scenarios']} scenarios, "
              f"{len(res['findings'])} findings "
              f"({by_sev.get('high', 0)} high, {by_sev.get('medium', 0)} medium, "
              f"{by_sev.get('low', 0)} low)")
        print(f"Wrote {args.output}")
        if args.json_out:
            print(f"Wrote {args.json_out}")

    return 1 if args.fail_on_high and by_sev.get("high") else 0


if __name__ == "__main__":
    sys.exit(main())
