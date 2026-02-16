#!/usr/bin/env python3
"""Check Batou rule coverage and detect duplicate/overlapping rule IDs.

Scans the codebase to report:
  1. Duplicate rule IDs (same BATOU-XXX-NNN defined in multiple places)
  2. ID gaps (missing numbers in a prefix sequence)
  3. Rules per category/prefix summary
  4. Taint catalog coverage (sources/sinks/sanitizers per language)
  5. CWE coverage across rules

Usage:
    python tools/check_rules.py              # full report
    python tools/check_rules.py --duplicates # only show duplicates
    python tools/check_rules.py --gaps       # only show ID gaps
    python tools/check_rules.py --coverage   # only show coverage summary
    python tools/check_rules.py --taint      # only show taint catalog stats
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Rule ID scanner
# ---------------------------------------------------------------------------

def scan_rule_ids() -> dict[str, list[tuple[str, int]]]:
    """Scan all Go files for Batou rule IDs.

    Returns {rule_id: [(file_path, line_number), ...]}.
    """
    rules_dir = PROJECT_ROOT / "internal" / "rules"
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
    rules_dir = PROJECT_ROOT / "internal" / "rules"
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

def scan_taint_catalogs() -> dict[str, dict[str, int]]:
    """Scan taint catalog files for entry counts per language.

    Returns {language: {"sources": N, "sinks": N, "sanitizers": N}}.
    """
    lang_dir = PROJECT_ROOT / "internal" / "taint" / "languages"
    if not lang_dir.exists():
        return {}

    stats: dict[str, dict[str, int]] = {}
    entry_pattern = re.compile(r'^\s+\{$', re.MULTILINE)

    for go_file in sorted(lang_dir.glob("*.go")):
        name = go_file.stem
        if name.endswith("_test"):
            continue

        parts = name.rsplit("_", 1)
        if len(parts) != 2:
            continue

        lang, kind = parts
        if kind not in ("sources", "sinks", "sanitizers"):
            continue

        try:
            content = go_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue

        # Count struct literal openings (lines that are just whitespace + '{')
        count = len(entry_pattern.findall(content))

        if lang not in stats:
            stats[lang] = {"sources": 0, "sinks": 0, "sanitizers": 0}
        stats[lang][kind] = count

    return stats


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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Check Batou rule coverage and detect duplicates.")
    parser.add_argument("--duplicates", action="store_true", help="Only show duplicate rule IDs")
    parser.add_argument("--gaps", action="store_true", help="Only show ID gaps")
    parser.add_argument("--coverage", action="store_true", help="Only show coverage summary")
    parser.add_argument("--taint", action="store_true", help="Only show taint catalog stats")
    args = parser.parse_args()

    show_all = not (args.duplicates or args.gaps or args.coverage or args.taint)

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

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
