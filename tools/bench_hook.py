#!/usr/bin/env python3
"""End-to-end Batou hook latency benchmark (`make bench-hook`).

Batou's product thesis is write-time blocking: every agent Write costs two
full process invocations (PreToolUse + PostToolUse), each of which decodes
the hook event JSON, runs the whole scan pipeline, and loads + saves the
persistent call graph (.batou/callgraph.json). This script measures that
end-to-end wall-clock cost the way Claude Code actually pays it: it pipes a
realistic hook event JSON into a freshly built bin/batou N times and reports
p50/p95 per invocation for three scenarios:

  1. PreToolUse, cold  — no .batou/ directory (first write in a project)
  2. PreToolUse, warm  — an existing ~MB-scale .batou/callgraph.json
  3. PostToolUse, warm — same event on the hint-only path

The warm scenarios seed the call graph by feeding generated Go files through
the real hook path until callgraph.json reaches the target size. All events
share one session_id: graph.LoadGraph discards the on-disk graph when the
session id does not match, so a mismatched session would silently measure
the cold path while still paying the JSON parse.

The measured file itself is synthesized from the committed fixtures under
batou-core/testdata/fixtures/go/ (mixed vulnerable + safe seeds, ~1k LOC by
default) so the scan exercises the full pipeline, not an early-exit path.

Usage:
    python3 tools/bench_hook.py [--bin bin/batou] [--n 20] [--target-mb 1.0]
                                [--loc 1000] [--keep]

Exit codes 0 (allow) and 2 (block) from the hook both count as successful
invocations; anything else aborts the run.
"""

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = os.path.join(REPO_ROOT, "batou-core", "testdata", "fixtures")
SESSION_ID = "bench-hook-session"

# Mixed vulnerable + safe Go seeds — mirrors the corpus used by
# BenchmarkHookPipeline in batou-core/scanner/hooklatency_bench_test.go.
GO_SEEDS = [
    "go/vulnerable/command_injection.go",
    "go/safe/sqli_parameterized.go",
    "go/vulnerable/file_read_traversal.go",
    "go/safe/crypto_strong.go",
    "go/vulnerable/ldap_injection.go",
]


def split_header(content):
    """Split a Go fixture into (header, body) where header is the leading
    package/import/comment preamble. Bodies concatenated under one header
    stay parseable (duplicate funcs are a type-check error, not a parse
    error, and the scanner never type-checks)."""
    lines = content.split("\n")
    in_import = False
    i = 0
    for i, line in enumerate(lines):
        t = line.strip()
        if in_import:
            if t == ")":
                in_import = False
            continue
        if t == "":
            continue
        if t == "import (":
            in_import = True
            continue
        if t.startswith("//") or t.startswith("package ") or t.startswith("import "):
            continue
        break
    return "\n".join(lines[:i]), "\n".join(lines[i:])


def synthesize_measured_file(target_loc):
    """Build a representative ~target_loc Go file from the fixture seeds."""
    seeds = []
    for rel in GO_SEEDS:
        with open(os.path.join(FIXTURE_DIR, rel), encoding="utf-8") as f:
            seeds.append(split_header(f.read()))
    parts = [seeds[0][0], "\n"]
    loc = parts[0].count("\n") + 1
    i = 0
    while loc < target_loc:
        body = seeds[i % len(seeds)][1]
        chunk = "\n" + body + ("" if body.endswith("\n") else "\n")
        parts.append(chunk)
        loc += chunk.count("\n")
        i += 1
    return "".join(parts)


def gen_graph_seed_file(index, funcs_per_file=80):
    """Generate a Go file whose functions call each other in chains so the
    hook's call-graph update phase produces FuncNodes, edges, and taint
    caches — the realistic contents of a grown .batou/callgraph.json. The
    sink uses a parameterized query, so seeding stays finding-free."""
    out = [
        "package gen\n",
        "import (",
        '\t"database/sql"',
        '\t"net/http"',
        ")\n",
    ]
    chain = 5
    for f in range(0, funcs_per_file, chain):
        out.append(
            "func genHandler%d_%d(w http.ResponseWriter, r *http.Request, db *sql.DB) {" % (index, f)
        )
        out.append('\tv := r.URL.Query().Get("p")')
        out.append("\tgenStep%d_%d(db, v)" % (index, f + 1))
        out.append("}")
        for s in range(1, chain - 1):
            out.append("func genStep%d_%d(db *sql.DB, v string) {" % (index, f + s))
            out.append("\tgenStep%d_%d(db, v)" % (index, f + s + 1))
            out.append("}")
        out.append("func genStep%d_%d(db *sql.DB, v string) {" % (index, f + chain - 1))
        out.append('\t_, _ = db.Exec("UPDATE items SET note = $1 WHERE id = 1", v)')
        out.append("}")
    return "\n".join(out) + "\n"


def make_event(event_name, file_path, content, cwd):
    ev = {
        "session_id": SESSION_ID,
        "cwd": cwd,
        "hook_event_name": event_name,
        "tool_name": "Write",
        "tool_input": {"file_path": file_path, "content": content},
    }
    if event_name == "PostToolUse":
        ev["tool_response"] = {"filePath": file_path, "success": True}
    return json.dumps(ev).encode("utf-8")


def invoke(bin_path, payload, cwd):
    """Run one hook invocation; return (elapsed_seconds, exit_code)."""
    start = time.perf_counter()
    proc = subprocess.run(
        [bin_path],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        check=False,
    )
    elapsed = time.perf_counter() - start
    if proc.returncode not in (0, 2):
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(
            "hook invocation failed with exit code %d (expected 0 allow / 2 block)"
            % proc.returncode
        )
    return elapsed, proc.returncode


def percentile(sorted_vals, pct):
    """Nearest-rank percentile on an already-sorted list."""
    if not sorted_vals:
        return 0.0
    rank = max(1, min(len(sorted_vals), int(-(-pct * len(sorted_vals) // 100))))
    return sorted_vals[rank - 1]


def run_scenario(label, bin_path, payload, proj, n, clear_batou):
    times, blocks = [], 0
    for _ in range(n):
        if clear_batou:
            shutil.rmtree(os.path.join(proj, ".batou"), ignore_errors=True)
        elapsed, rc = invoke(bin_path, payload, proj)
        times.append(elapsed * 1000.0)
        if rc == 2:
            blocks += 1
    times.sort()
    return {
        "label": label,
        "p50": percentile(times, 50),
        "p95": percentile(times, 95),
        "min": times[0],
        "mean": statistics.fmean(times),
        "max": times[-1],
        "blocks": blocks,
        "n": n,
    }


def seed_callgraph(bin_path, proj, target_bytes, max_files=150):
    """Grow .batou/callgraph.json to ~target_bytes through the real hook
    path (one Write event per generated file)."""
    graph_path = os.path.join(proj, ".batou", "callgraph.json")
    src_dir = os.path.join(proj, "src")
    for i in range(max_files):
        size = os.path.getsize(graph_path) if os.path.exists(graph_path) else 0
        if size >= target_bytes:
            return size, i
        rel = "gen_%03d.go" % i
        content = gen_graph_seed_file(i)
        file_path = os.path.join(src_dir, rel)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        invoke(bin_path, make_event("PreToolUse", file_path, content, proj), proj)
        if i and i % 10 == 0:
            print("  seeding callgraph: %d files, %.1f KB" % (i, size / 1024.0))
    size = os.path.getsize(graph_path) if os.path.exists(graph_path) else 0
    return size, max_files


def cpu_brand():
    if platform.system() == "Darwin":
        try:
            return subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                stdout=subprocess.PIPE,
                check=False,
            ).stdout.decode().strip()
        except OSError:
            pass
    return platform.processor() or "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", default=os.path.join(REPO_ROOT, "bin", "batou"))
    ap.add_argument("--n", type=int, default=20, help="invocations per scenario")
    ap.add_argument("--target-mb", type=float, default=1.0,
                    help="target .batou/callgraph.json size for warm scenarios")
    ap.add_argument("--loc", type=int, default=1000,
                    help="approximate LOC of the measured file")
    ap.add_argument("--keep", action="store_true",
                    help="keep the temp project dir for inspection")
    args = ap.parse_args()

    bin_path = os.path.abspath(args.bin)
    if not os.path.exists(bin_path):
        raise SystemExit("binary not found at %s — run `make build` first" % bin_path)

    content = synthesize_measured_file(args.loc)
    loc = content.count("\n")

    proj = tempfile.mkdtemp(prefix="batou-bench-hook-")
    src_dir = os.path.join(proj, "src")
    os.makedirs(src_dir, exist_ok=True)
    measured_path = os.path.join(src_dir, "handler.go")
    with open(measured_path, "w", encoding="utf-8") as f:
        f.write(content)

    pre_payload = make_event("PreToolUse", measured_path, content, proj)
    post_payload = make_event("PostToolUse", measured_path, content, proj)

    version = subprocess.run(
        [bin_path, "version"], stdout=subprocess.PIPE, check=False
    ).stdout.decode().strip()
    print("batou hook latency bench")
    print("  binary : %s (version %s)" % (bin_path, version))
    print("  machine: %s / %s" % (platform.platform(), cpu_brand()))
    print("  event  : Write %s (%d LOC Go, %.1f KB payload)"
          % (os.path.relpath(measured_path, proj), loc, len(pre_payload) / 1024.0))
    print("  n      : %d invocations per scenario" % args.n)
    print()

    # Untimed warmup: pages in the binary and macOS code-sign validation so
    # the first measured invocation isn't an outlier.
    invoke(bin_path, pre_payload, proj)

    results = []

    # Scenario 1: cold — .batou/ removed before every invocation.
    results.append(run_scenario(
        "PreToolUse  cold (no .batou)", bin_path, pre_payload, proj, args.n,
        clear_batou=True,
    ))

    # Seed an ~MB-scale call graph through the real hook path.
    shutil.rmtree(os.path.join(proj, ".batou"), ignore_errors=True)
    print("  seeding callgraph to ~%.1f MB ..." % args.target_mb)
    graph_size, seed_files = seed_callgraph(
        bin_path, proj, int(args.target_mb * 1024 * 1024))
    print("  seeded: %.2f MB callgraph.json from %d generated files"
          % (graph_size / (1024.0 * 1024.0), seed_files))
    print()

    warm_label = "warm (callgraph %.2f MB)" % (graph_size / (1024.0 * 1024.0))
    results.append(run_scenario(
        "PreToolUse  " + warm_label, bin_path, pre_payload, proj, args.n,
        clear_batou=False,
    ))
    results.append(run_scenario(
        "PostToolUse " + warm_label, bin_path, post_payload, proj, args.n,
        clear_batou=False,
    ))

    hdr = "%-38s %8s %8s %8s %8s %8s %7s" % (
        "scenario", "p50 ms", "p95 ms", "min ms", "mean ms", "max ms", "blocks")
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        print("%-38s %8.1f %8.1f %8.1f %8.1f %8.1f %4d/%d" % (
            r["label"], r["p50"], r["p95"], r["min"], r["mean"], r["max"],
            r["blocks"], r["n"]))
    print()
    per_write = results[1]["p50"] + results[2]["p50"]
    print("per-Write cost, warm (PreToolUse p50 + PostToolUse p50): %.1f ms"
          % per_write)

    if args.keep:
        print("temp project kept at %s" % proj)
    else:
        shutil.rmtree(proj, ignore_errors=True)


if __name__ == "__main__":
    main()
