#!/usr/bin/env python3
"""Taint-catalog coverage matrix.

Walks `batou-core/taint/languages/*.go`, counts source/sink/sanitizer
entries per (language × category), and prints a markdown report showing
where coverage is dense and where it's missing.

Usage:
    python tools/coverage_matrix.py           # full report to stdout
    python tools/coverage_matrix.py --gaps    # only show empty cells
    python tools/coverage_matrix.py --json    # machine-readable output
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANG_DIR = os.path.join(ROOT, "batou-core", "taint", "languages")
TYPES_FILE = os.path.join(ROOT, "batou-core", "taint", "types.go")

CATEGORY_RE = re.compile(r"Category:\s*taint\.(Snk\w+|Src\w+)")
NEUTRALIZES_RE = re.compile(r"Neutralizes:\s*\[\]taint\.SinkCategory\{([^}]*)\}")
SINK_REF_RE = re.compile(r"taint\.(Snk\w+)")
CONST_LINE_RE = re.compile(r"^\s*(Snk\w+|Src\w+)\s+\w+Category\s*=")


def parse_constants():
    """Read types.go and return (source_consts, sink_consts) in declaration order."""
    src, snk = [], []
    # batou:ignore BATOU-PYAST-004 -- dev tool; TYPES_FILE is a constant repo-local path joined from ROOT + literals
    with open(TYPES_FILE, encoding="utf-8") as f:
        for line in f:
            m = CONST_LINE_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            if name.startswith("Snk"):
                snk.append(name)
            else:
                src.append(name)
    return src, snk


def discover_languages():
    """Find languages by looking at <lang>_catalog.go files."""
    langs = set()
    for fn in os.listdir(LANG_DIR):
        if fn.endswith("_catalog.go") and fn != "catalog_coverage_test.go":
            lang = fn[: -len("_catalog.go")]
            langs.add(lang)
    return sorted(langs)


def count_categories(path):
    """Return Counter of category-constant occurrences in the file."""
    counts = defaultdict(int)
    if not os.path.exists(path):
        return counts
    # batou:ignore BATOU-PYAST-004 -- dev tool; `path` is built from LANG_DIR + lang slug discovered by listing _catalog.go files in that same dir
    with open(path, encoding="utf-8") as f:
        for line in f:
            for m in CATEGORY_RE.finditer(line):
                counts[m.group(1)] += 1
    return counts


def count_sanitizers(path):
    """Return (total_entries, Counter of neutralized sink-categories)."""
    total = 0
    neutralized = defaultdict(int)
    if not os.path.exists(path):
        return 0, neutralized
    # batou:ignore BATOU-PYAST-004 -- dev tool; `path` is built from LANG_DIR + lang slug discovered by listing _catalog.go files in that same dir
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for m in NEUTRALIZES_RE.finditer(text):
        total += 1
        for r in SINK_REF_RE.finditer(m.group(1)):
            neutralized[r.group(1)] += 1
    return total, neutralized


def build_matrix(langs, src_consts, snk_consts):
    """Return dict: {lang: {'sources': {cat:n}, 'sinks': {cat:n},
    'sanitizer_entries': n, 'neutralizes': {cat:n}}}."""
    out = {}
    for lang in langs:
        sources = count_categories(os.path.join(LANG_DIR, f"{lang}_sources.go"))
        sinks = count_categories(os.path.join(LANG_DIR, f"{lang}_sinks.go"))
        san_total, neutralizes = count_sanitizers(
            os.path.join(LANG_DIR, f"{lang}_sanitizers.go")
        )
        out[lang] = {
            "sources": {c: sources.get(c, 0) for c in src_consts},
            "sinks": {c: sinks.get(c, 0) for c in snk_consts},
            "sanitizer_entries": san_total,
            "neutralizes": {c: neutralizes.get(c, 0) for c in snk_consts},
        }
    return out


def render_md_table(rows, headers):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    lines = []
    lines.append("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |")
    lines.append("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for row in rows:
        lines.append(
            "| " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)) + " |"
        )
    return "\n".join(lines)


def gap_cell(n):
    """Format a cell value: emphasize zeros as '.' for readability."""
    return str(n) if n else "."


def render_report(matrix, src_consts, snk_consts, gaps_only=False):
    langs = sorted(matrix.keys())
    out = []
    out.append("# Taint Catalog Coverage Matrix\n")
    out.append(f"Languages: {len(langs)} | Sink categories: {len(snk_consts)} | "
               f"Source categories: {len(src_consts)}\n")

    total_src = sum(sum(matrix[l]["sources"].values()) for l in langs)
    total_snk = sum(sum(matrix[l]["sinks"].values()) for l in langs)
    total_san = sum(matrix[l]["sanitizer_entries"] for l in langs)
    out.append(f"**Catalog totals:** {total_src} sources, {total_snk} sinks, "
               f"{total_san} sanitizers ({total_src + total_snk + total_san} total entries)\n")

    out.append("## Per-language totals\n")
    rows = []
    for lang in langs:
        s = sum(matrix[lang]["sources"].values())
        k = sum(matrix[lang]["sinks"].values())
        z = matrix[lang]["sanitizer_entries"]
        rows.append([lang, s, k, z, s + k + z])
    rows.sort(key=lambda r: -r[4])
    out.append(render_md_table(rows, ["language", "sources", "sinks", "sanitizers", "total"]))
    out.append("")

    out.append("## Sinks: language x category (entry counts)\n")
    short_snk = [c.replace("Snk", "") for c in snk_consts]
    headers = ["lang"] + short_snk + ["sum"]
    rows = []
    col_totals = [0] * len(snk_consts)
    for lang in langs:
        counts = [matrix[lang]["sinks"][c] for c in snk_consts]
        row_total = sum(counts)
        if gaps_only and all(counts):
            continue
        rows.append([lang] + [gap_cell(c) for c in counts] + [row_total])
        for i, c in enumerate(counts):
            col_totals[i] += c
    rows.append(["sum"] + [str(c) for c in col_totals] + [sum(col_totals)])
    out.append(render_md_table(rows, headers))
    out.append("")

    out.append("## Sources: language x category (entry counts)\n")
    short_src = [c.replace("Src", "") for c in src_consts]
    headers = ["lang"] + short_src + ["sum"]
    rows = []
    col_totals = [0] * len(src_consts)
    for lang in langs:
        counts = [matrix[lang]["sources"][c] for c in src_consts]
        row_total = sum(counts)
        if gaps_only and all(counts):
            continue
        rows.append([lang] + [gap_cell(c) for c in counts] + [row_total])
        for i, c in enumerate(counts):
            col_totals[i] += c
    rows.append(["sum"] + [str(c) for c in col_totals] + [sum(col_totals)])
    out.append(render_md_table(rows, headers))
    out.append("")

    out.append("## Sanitizers: language x neutralized sink category\n")
    headers = ["lang"] + short_snk + ["entries"]
    rows = []
    col_totals = [0] * len(snk_consts)
    for lang in langs:
        counts = [matrix[lang]["neutralizes"][c] for c in snk_consts]
        if gaps_only and matrix[lang]["sanitizer_entries"] > 0 and all(counts):
            continue
        rows.append([lang] + [gap_cell(c) for c in counts] + [matrix[lang]["sanitizer_entries"]])
        for i, c in enumerate(counts):
            col_totals[i] += c
    rows.append(["sum"] + [str(c) for c in col_totals] + [sum(col_totals)])
    out.append(render_md_table(rows, headers))
    out.append("")

    out.append("## Top gaps (zero-entry sink cells, ranked by how many other langs have them)\n")
    gap_rows = []
    for lang in langs:
        for c in snk_consts:
            if matrix[lang]["sinks"][c] == 0:
                others_with = sum(1 for l2 in langs if matrix[l2]["sinks"][c] > 0)
                gap_rows.append((others_with, lang, c.replace("Snk", "")))
    gap_rows.sort(key=lambda r: (-r[0], r[1], r[2]))
    if gap_rows:
        rows = [[r[1], r[2], r[0]] for r in gap_rows[:40]]
        out.append(render_md_table(
            rows, ["language", "missing sink category", "# other langs that have it"]
        ))
    else:
        out.append("No zero-entry sink cells - full coverage.")
    out.append("")

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gaps", action="store_true", help="only show rows with at least one zero")
    ap.add_argument("--json", action="store_true", help="emit raw matrix as JSON")
    args = ap.parse_args()

    src_consts, snk_consts = parse_constants()
    langs = discover_languages()
    matrix = build_matrix(langs, src_consts, snk_consts)

    if args.json:
        json.dump(matrix, sys.stdout, indent=2)
        return

    print(render_report(matrix, src_consts, snk_consts, gaps_only=args.gaps))


if __name__ == "__main__":
    main()
