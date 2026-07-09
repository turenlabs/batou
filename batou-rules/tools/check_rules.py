#!/usr/bin/env python3
"""Check Batou rule coverage and detect duplicate/overlapping rule IDs.

Scans the codebase to report:
  1. Duplicate rule IDs (same BATOU-XXX-NNN defined in multiple places)
  2. ID gaps (missing numbers in a prefix sequence)
  3. Rules per category/prefix summary
  4. Taint catalog coverage (sources/sinks/sanitizers per language)
  5. CWE coverage across rules
  6. Duplicate taint catalog entry IDs (same-file and cross-file)

The repo is a two-module workspace: regex rules live in batou-rules/rules/
and taint catalogs in batou-core/taint/languages/. The repo root is
auto-detected from the script location, so the tool works from any CWD.

Usage:
    python3 batou-rules/tools/check_rules.py              # full report
    python3 batou-rules/tools/check_rules.py --duplicates # only show duplicates
    python3 batou-rules/tools/check_rules.py --gaps       # only show ID gaps
    python3 batou-rules/tools/check_rules.py --coverage   # only show coverage summary
    python3 batou-rules/tools/check_rules.py --taint      # only show taint catalog stats
    python3 batou-rules/tools/check_rules.py --taint-dups # duplicate taint entry IDs
                                                          # (exit 1 on same-file dups)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


def find_repo_root() -> Path:
    """Locate the repo root by walking up from the script's directory.

    The root is the directory containing both module dirs (batou-core/ and
    batou-rules/) — go.work is used as a fallback marker. This keeps the
    tool runnable from the repo root, from tools/, or from anywhere else.
    """
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "batou-core").is_dir() and (candidate / "batou-rules").is_dir():
            return candidate
        if (candidate / "go.work").is_file():
            return candidate
    print(f"ERROR: cannot locate repo root above {here} "
          "(expected batou-core/ + batou-rules/ or go.work)", file=sys.stderr)
    sys.exit(2)


PROJECT_ROOT = find_repo_root()
RULES_DIR = PROJECT_ROOT / "batou-rules" / "rules"
TAINT_LANG_DIR = PROJECT_ROOT / "batou-core" / "taint" / "languages"

# Taint catalog data files: {lang}_{kind}.go with an optional suffix for
# split files (e.g. go_sinks_gitea.go). Deliberately does NOT match the
# *_types.go / *_catalog.go helpers, which contain no entry literals.
TAINT_FILE_RE = re.compile(r"^([a-z0-9]+)_(sources|sinks|sanitizers)(?:_[a-z0-9_]+)?\.go$")

# One per catalog entry: the ID field of a SourceDef/SinkDef/SanitizerDef
# struct literal. \b keeps CWEID:/AdvisoryID: from matching.
TAINT_ENTRY_ID_RE = re.compile(r'\bID:\s*"([^"]+)"')


# ---------------------------------------------------------------------------
# Rule ID scanner
# ---------------------------------------------------------------------------

def scan_rule_ids() -> dict[str, list[tuple[str, int]]]:
    """Scan all Go files for Batou rule IDs.

    Returns {rule_id: [(file_path, line_number), ...]}.
    """
    rules_dir = RULES_DIR
    pattern = re.compile(r'(BATOU-[A-Z]+-\d+)')
    rule_locations: dict[str, list[tuple[str, int]]] = defaultdict(list)

    for go_file in sorted(rules_dir.rglob("*.go")):
        if go_file.name.endswith("_test.go"):
            continue
        try:
            lines = go_file.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for i, line in enumerate(lines, 1):
            # Only match ID definitions (func ID() or comments declaring the rule)
            if 'func' in line and 'ID()' in line and 'return' in line:
                for match in pattern.finditer(line):
                    rel_path = go_file.relative_to(PROJECT_ROOT)
                    rule_locations[match.group(1)].append((str(rel_path), i))

    return dict(rule_locations)


def scan_cwe_ids(rule_ids: dict[str, list]) -> dict[str, list[str]]:
    """Scan rule files for CWE references associated with each rule.

    Returns {rule_id: [cwe_ids]}.
    """
    rules_dir = RULES_DIR
    cwe_pattern = re.compile(r'(CWE-\d+)')
    rule_cwes: dict[str, list[str]] = defaultdict(list)

    for go_file in sorted(rules_dir.rglob("*.go")):
        if go_file.name.endswith("_test.go"):
            continue
        try:
            content = go_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue

        # Find CWE references in finding structs
        for match in cwe_pattern.finditer(content):
            cwe = match.group(1)
            # Find the nearest rule ID above this CWE reference
            pos = match.start()
            preceding = content[:pos]
            rule_matches = list(re.finditer(r'(BATOU-[A-Z]+-\d+)', preceding))
            if rule_matches:
                nearest_rule = rule_matches[-1].group(1)
                if nearest_rule in rule_ids:
                    if cwe not in rule_cwes[nearest_rule]:
                        rule_cwes[nearest_rule].append(cwe)

    return dict(rule_cwes)


# ---------------------------------------------------------------------------
# Taint catalog scanner
# ---------------------------------------------------------------------------

def _iter_taint_files():
    """Yield (path, lang, kind) for every taint catalog data file."""
    if not TAINT_LANG_DIR.exists():
        return
    for go_file in sorted(TAINT_LANG_DIR.glob("*.go")):
        if go_file.name.endswith("_test.go"):
            continue
        match = TAINT_FILE_RE.match(go_file.name)
        if not match:
            continue
        yield go_file, match.group(1), match.group(2)


def scan_taint_catalogs() -> dict[str, dict[str, int]]:
    """Scan taint catalog files for entry counts per language.

    Entries are counted by their ID field, which handles both the multi-line
    and single-line struct literal styles used in the catalogs.

    Returns {language: {"sources": N, "sinks": N, "sanitizers": N}}.
    """
    stats: dict[str, dict[str, int]] = {}

    for go_file, lang, kind in _iter_taint_files():
        try:
            lines = go_file.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        count = 0
        for line in lines:
            if line.lstrip().startswith("//"):
                continue
            count += len(TAINT_ENTRY_ID_RE.findall(line))

        if lang not in stats:
            stats[lang] = {"sources": 0, "sinks": 0, "sanitizers": 0}
        stats[lang][kind] += count

    return stats


def _brace_spans(content: str) -> list[tuple[int, int]]:
    """Return (open_pos, close_pos) for every matched brace pair in Go source.

    Skips string literals (backtick raw strings, double-quoted strings, rune
    literals) and comments — catalog regex patterns routinely contain
    unbalanced braces (e.g. `\\{` or `[({]`), so naive counting misnests.
    """
    spans: list[tuple[int, int]] = []
    stack: list[int] = []
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "`":  # raw string — no escapes
            end = content.find("`", i + 1)
            i = end + 1 if end != -1 else n
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n and content[i] != quote:
                if content[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if ch == "/" and i + 1 < n and content[i + 1] == "/":
            end = content.find("\n", i)
            i = end if end != -1 else n
            continue
        if ch == "/" and i + 1 < n and content[i + 1] == "*":
            end = content.find("*/", i)
            i = end + 2 if end != -1 else n
            continue
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            spans.append((stack.pop(), i))
        i += 1
    return spans


def _innermost_span(spans: list[tuple[int, int]], pos: int) -> tuple[int, int] | None:
    """Find the innermost brace span containing pos (the entry struct literal)."""
    best = None
    for open_pos, close_pos in spans:
        if open_pos < pos < close_pos:
            if best is None or open_pos > best[0]:
                best = (open_pos, close_pos)
    return best


def scan_taint_entry_ids() -> dict[str, list[tuple[str, int, str]]]:
    """Scan taint catalogs for every entry ID.

    Returns {entry_id: [(file_name, line_number, normalized_literal), ...]}.
    The literal is the entry's full struct literal, whitespace-normalized so
    copy-paste duplicates that only differ in formatting still compare equal.
    """
    occurrences: dict[str, list[tuple[str, int, str]]] = defaultdict(list)

    for go_file, _lang, _kind in _iter_taint_files():
        try:
            content = go_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue

        spans = _brace_spans(content)
        for match in TAINT_ENTRY_ID_RE.finditer(content):
            line_start = content.rfind("\n", 0, match.start()) + 1
            if content[line_start:match.start()].lstrip().startswith("//"):
                continue
            line_num = content.count("\n", 0, match.start()) + 1
            span = _innermost_span(spans, match.start())
            literal = content[span[0]:span[1] + 1] if span else ""
            normalized = re.sub(r"\s+", " ", literal).strip()
            occurrences[match.group(1)].append((go_file.name, line_num, normalized))

    return dict(occurrences)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def find_duplicates(rule_ids: dict[str, list]) -> list[tuple[str, list]]:
    """Find rule IDs defined in multiple non-test files."""
    return [(rid, locs) for rid, locs in sorted(rule_ids.items()) if len(locs) > 1]


def find_gaps(rule_ids: dict[str, list]) -> dict[str, list[int]]:
    """Find gaps in rule ID numbering per prefix."""
    prefix_nums: dict[str, list[int]] = defaultdict(list)
    for rid in rule_ids:
        match = re.match(r'BATOU-([A-Z-]+)-(\d+)', rid)
        if match:
            prefix_nums[match.group(1)].append(int(match.group(2)))

    gaps: dict[str, list[int]] = {}
    for prefix, nums in sorted(prefix_nums.items()):
        nums_sorted = sorted(set(nums))
        if not nums_sorted:
            continue
        expected = set(range(1, max(nums_sorted) + 1))
        missing = sorted(expected - set(nums_sorted))
        if missing:
            gaps[prefix] = missing

    return gaps


def coverage_summary(rule_ids: dict[str, list]) -> dict[str, int]:
    """Count rules per prefix."""
    prefix_counts: dict[str, int] = defaultdict(int)
    for rid in rule_ids:
        match = re.match(r'BATOU-([A-Z-]+)-\d+', rid)
        if match:
            prefix_counts[match.group(1)] += 1
    return dict(sorted(prefix_counts.items()))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_duplicates(rule_ids: dict[str, list]) -> int:
    """Print duplicate rule IDs. Returns count."""
    dupes = find_duplicates(rule_ids)
    if not dupes:
        print("No duplicate rule IDs found.")
        return 0

    print(f"DUPLICATE RULE IDs ({len(dupes)} found):")
    print("-" * 60)
    for rid, locs in dupes:
        print(f"  {rid}:")
        for path, line in locs:
            print(f"    {path}:{line}")
    return len(dupes)


def print_gaps(rule_ids: dict[str, list]) -> int:
    """Print ID gaps. Returns count of prefixes with gaps."""
    gaps = find_gaps(rule_ids)
    if not gaps:
        print("No ID gaps found.")
        return 0

    print(f"ID GAPS ({len(gaps)} prefixes with gaps):")
    print("-" * 60)
    for prefix, missing in gaps.items():
        nums = ", ".join(f"{n:03d}" for n in missing[:10])
        suffix = f" ... ({len(missing)} total)" if len(missing) > 10 else ""
        print(f"  BATOU-{prefix}: missing {nums}{suffix}")
    return len(gaps)


def print_coverage(rule_ids: dict[str, list]) -> None:
    """Print coverage summary."""
    counts = coverage_summary(rule_ids)
    total = sum(counts.values())

    print(f"RULE COVERAGE ({total} total rules across {len(counts)} prefixes):")
    print("-" * 60)

    # Sort by count descending
    for prefix, count in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "#" * min(count, 40)
        print(f"  BATOU-{prefix:15s} {count:3d}  {bar}")


def print_cwe_coverage(rule_ids: dict[str, list], rule_cwes: dict[str, list[str]]) -> None:
    """Print CWE coverage summary."""
    all_cwes: dict[str, int] = defaultdict(int)
    for cwes in rule_cwes.values():
        for cwe in cwes:
            all_cwes[cwe] += 1

    if not all_cwes:
        print("No CWE references found.")
        return

    rules_with_cwe = sum(1 for cwes in rule_cwes.values() if cwes)
    total_rules = len(rule_ids)

    print(f"\nCWE COVERAGE ({len(all_cwes)} unique CWEs, {rules_with_cwe}/{total_rules} rules have CWE refs):")
    print("-" * 60)
    for cwe, count in sorted(all_cwes.items(), key=lambda x: -x[1])[:20]:
        print(f"  {cwe:10s} referenced by {count:3d} rule(s)")
    if len(all_cwes) > 20:
        print(f"  ... and {len(all_cwes) - 20} more CWEs")


def print_taint(stats: dict[str, dict[str, int]]) -> None:
    """Print taint catalog statistics."""
    if not stats:
        print("No taint catalogs found.")
        return

    total_entries = sum(
        s + k + san
        for lang_stats in stats.values()
        for s, k, san in [(lang_stats["sources"], lang_stats["sinks"], lang_stats["sanitizers"])]
    )

    print(f"\nTAINT CATALOG ({total_entries} total entries across {len(stats)} languages):")
    print("-" * 60)
    print(f"  {'Language':15s} {'Sources':>8s} {'Sinks':>8s} {'Sanitizers':>11s} {'Total':>8s}")
    print(f"  {'─' * 15} {'─' * 8} {'─' * 8} {'─' * 11} {'─' * 8}")

    for lang in sorted(stats.keys()):
        s = stats[lang]
        total = s["sources"] + s["sinks"] + s["sanitizers"]
        print(f"  {lang:15s} {s['sources']:8d} {s['sinks']:8d} {s['sanitizers']:11d} {total:8d}")


def print_taint_dups(occurrences: dict[str, list[tuple[str, int, str]]]) -> int:
    """Print duplicate taint entry IDs, same-file and cross-file separately.

    Returns the number of IDs with same-file duplicates (the caller exits
    nonzero when any exist — same-file duplicates are either copy-paste
    errors or shadowed near-variants, and both deserve a look).
    """
    same_file: list[tuple[str, str, list[int], bool]] = []  # (id, file, lines, identical)
    cross_file: list[tuple[str, list[str]]] = []            # (id, ["file:line", ...])

    for entry_id, locs in sorted(occurrences.items()):
        if len(locs) < 2:
            continue

        by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for fname, line, literal in locs:
            by_file[fname].append((line, literal))

        for fname, entries in sorted(by_file.items()):
            if len(entries) > 1:
                lines = sorted(line for line, _ in entries)
                identical = len({literal for _, literal in entries}) == 1
                same_file.append((entry_id, fname, lines, identical))

        if len(by_file) > 1:
            cross_file.append((entry_id, [f"{f}:{l}" for f, l, _ in sorted(locs)]))

    total_entries = sum(len(v) for v in occurrences.values())
    print(f"TAINT ENTRY ID DUPLICATES ({total_entries} entries, {len(occurrences)} unique IDs):")
    print("-" * 60)

    if not same_file and not cross_file:
        print("  No duplicate taint entry IDs found.")
        return 0

    identical_count = sum(1 for _, _, _, ident in same_file if ident)
    print(f"\nSAME-FILE duplicates ({len(same_file)} IDs, "
          f"{identical_count} byte-identical copy-paste):")
    for entry_id, fname, lines, identical in same_file:
        marker = "IDENTICAL copy-paste" if identical else "variant bodies"
        locs = ", ".join(f"{fname}:{l}" for l in lines)
        print(f"  {entry_id}  [{marker}]")
        print(f"    {locs}")

    print(f"\nCROSS-FILE duplicates ({len(cross_file)} IDs) — may be intentional "
          "shared-ID variants (e.g. javax/jakarta pairs):")
    for entry_id, locs in cross_file:
        print(f"  {entry_id}")
        print(f"    {', '.join(locs)}")

    return len(same_file)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Check Batou rule coverage and detect duplicates.")
    parser.add_argument("--duplicates", action="store_true", help="Only show duplicate rule IDs")
    parser.add_argument("--gaps", action="store_true", help="Only show ID gaps")
    parser.add_argument("--coverage", action="store_true", help="Only show coverage summary")
    parser.add_argument("--taint", action="store_true", help="Only show taint catalog stats")
    parser.add_argument("--taint-dups", action="store_true",
                        help="Show duplicate taint entry IDs (exits nonzero on same-file duplicates)")
    args = parser.parse_args()

    show_all = not (args.duplicates or args.gaps or args.coverage or args.taint or args.taint_dups)

    rule_ids = scan_rule_ids()
    exit_code = 0

    if show_all or args.duplicates:
        dupes = print_duplicates(rule_ids)
        if dupes > 0:
            exit_code = 1
        print()

    if show_all or args.gaps:
        print_gaps(rule_ids)
        print()

    if show_all or args.coverage:
        print_coverage(rule_ids)
        rule_cwes = scan_cwe_ids(rule_ids)
        print_cwe_coverage(rule_ids, rule_cwes)
        print()

    if show_all or args.taint:
        taint_stats = scan_taint_catalogs()
        print_taint(taint_stats)
        print()

    if show_all or args.taint_dups:
        same_file_dups = print_taint_dups(scan_taint_entry_ids())
        if same_file_dups > 0:
            exit_code = 1
        print()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
