#!/usr/bin/env python3
"""Populate the Python CVE benchmark corpus from a manifest.

Reads tools/pycve_manifest.yaml (or a path passed on the command line) and
materialises one fixture directory per CVE under testdata/pycve-bench/:

    testdata/pycve-bench/CVE-2024-22195/
        vuln/...        # vulnerable Python sources
        safe/...        # patched Python sources
        expected.json   # CWE + metadata for the harness

Mirrors tools/fetch_gocve_fixtures.py — same two manifest modes (stage and
clone), same tiny YAML subset parser, same standard-library-only policy.

The harness in batou-core/scanner/pycve_bench_test.go does not need the
script to run — fixtures committed under testdata/pycve-bench/ are scanned
in place. This script exists so contributors can re-stage fixtures or add
new CVEs without hand-managing JSON.

Standard library only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "tools" / "pycve_manifest.yaml"
CORPUS_DIR = REPO_ROOT / "testdata" / "pycve-bench"


def _load_yaml(path: Path) -> list[dict[str, Any]]:
    """Tiny YAML subset parser: top-level list of mappings, scalar values,
    multi-line `>-` folded strings. Avoids the pyyaml dependency.

    Mirrors fetch_gocve_fixtures.py's loader so the manifest dialect stays
    consistent across the two corpora.
    """
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    folding_key: str | None = None
    folding_indent: int = 0
    folding_lines: list[str] = []

    def _flush_folding() -> None:
        nonlocal folding_key, folding_lines, current
        if folding_key is None:
            return
        text = " ".join(part.strip() for part in folding_lines if part.strip())
        assert current is not None
        current[folding_key] = text
        folding_key = None
        folding_lines = []

    text = path.read_text(encoding="utf-8")
    for raw in text.splitlines():
        if folding_key is None:
            stripped_no_comment = raw.split("#", 1)[0].rstrip()
        else:
            indent = len(raw) - len(raw.lstrip(" "))
            if raw.strip() == "":
                folding_lines.append("")
                continue
            if indent < folding_indent:
                _flush_folding()
                stripped_no_comment = raw.split("#", 1)[0].rstrip()
            else:
                folding_lines.append(raw[folding_indent:])
                continue

        if not stripped_no_comment.strip():
            continue

        if stripped_no_comment.startswith("- "):
            _flush_folding()
            if current is not None:
                entries.append(current)
            current = {}
            stripped_no_comment = stripped_no_comment[2:]

        if current is None:
            raise ValueError(f"non-list line at top level: {raw!r}")

        key, _, val = stripped_no_comment.lstrip().partition(":")
        key = key.strip()
        val = val.strip()
        if val == ">-" or val == ">":
            folding_key = key
            folding_indent = (len(raw) - len(raw.lstrip(" "))) + 2
            folding_lines = []
            continue
        if len(val) >= 2 and val[0] == val[-1] and val[0] in {'"', "'"}:
            val = val[1:-1]
        current[key] = val

    _flush_folding()
    if current is not None:
        entries.append(current)
    return entries


def _clean_dir(p: Path) -> None:
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True, exist_ok=True)


def _copy_tree(src: Path, dst: Path) -> int:
    """Copy every file under src into dst, mirroring structure. Returns
    file count. Skips dotfiles to avoid copying .git/.DS_Store etc."""
    count = 0
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        rel = Path(root).relative_to(src)
        out_root = dst / rel
        out_root.mkdir(parents=True, exist_ok=True)
        for fn in files:
            if fn.startswith("."):
                continue
            shutil.copy2(Path(root) / fn, out_root / fn)
            count += 1
    return count


def _stage_entry(entry: dict[str, Any]) -> tuple[int, int]:
    cve = entry["cve"]
    staged_rel = entry.get("staged_path")
    if not staged_rel:
        raise ValueError(f"{cve}: mode=stage requires staged_path")
    src = REPO_ROOT / staged_rel
    if not src.exists():
        raise FileNotFoundError(f"{cve}: staged_path {src} not found")
    target = CORPUS_DIR / cve
    _clean_dir(target / "vuln")
    _clean_dir(target / "safe")
    n_vuln = _copy_tree(src / "vuln", target / "vuln")
    n_safe = _copy_tree(src / "safe", target / "safe")
    if n_vuln == 0 or n_safe == 0:
        raise RuntimeError(
            f"{cve}: copied {n_vuln} vuln + {n_safe} safe files; both must be > 0"
        )
    return n_vuln, n_safe


def _git_available() -> bool:
    return shutil.which("git") is not None


def _clone_entry(entry: dict[str, Any]) -> tuple[int, int]:
    cve = entry["cve"]
    repo = entry.get("repo")
    vuln_sha = entry.get("vuln_commit")
    fixed_sha = entry.get("fixed_commit")
    files = entry.get("files") or []
    if not (repo and vuln_sha and fixed_sha and files):
        raise ValueError(
            f"{cve}: mode=clone requires repo, vuln_commit, fixed_commit, files[]"
        )
    if not _git_available():
        raise RuntimeError("git not available on PATH")

    target = CORPUS_DIR / cve
    _clean_dir(target / "vuln")
    _clean_dir(target / "safe")

    import tempfile

    n_vuln = n_safe = 0
    with tempfile.TemporaryDirectory(prefix=f"pycve-{cve}-") as tmp:
        repo_dir = Path(tmp) / "repo"
        subprocess.run(["git", "clone", "--no-checkout", repo, str(repo_dir)],
                       check=True)
        for label, sha, dest_root in (
            ("vuln", vuln_sha, target / "vuln"),
            ("safe", fixed_sha, target / "safe"),
        ):
            subprocess.run(["git", "-C", str(repo_dir), "checkout", sha],
                           check=True)
            for fent in files:
                rel = fent if isinstance(fent, str) else fent.get("path")
                if not rel:
                    continue
                src = repo_dir / rel
                if not src.exists():
                    print(f"  warning: {cve} {label} missing {rel}", file=sys.stderr)
                    continue
                dst = dest_root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                if label == "vuln":
                    n_vuln += 1
                else:
                    n_safe += 1
    return n_vuln, n_safe


def _write_expected(entry: dict[str, Any]) -> None:
    cve = entry["cve"]
    target = CORPUS_DIR / cve
    expected = {
        "cve": cve,
        "description": entry.get("description", ""),
        "cwe": entry.get("cwe", ""),
        "category": entry.get("category", ""),
    }
    if "reference" in entry:
        expected["reference"] = entry["reference"]
    if "file" in entry:
        expected["file"] = entry["file"]
    if "function" in entry:
        expected["function"] = entry["function"]
    (target / "expected.json").write_text(
        json.dumps(expected, indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str]) -> int:
    manifest_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_MANIFEST
    entries = _load_yaml(manifest_path)
    if not entries:
        print(f"no entries parsed from {manifest_path}", file=sys.stderr)
        return 1

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    ok = skipped = 0
    for entry in entries:
        cve = entry.get("cve", "<unknown>")
        mode = entry.get("mode", "stage")
        try:
            if mode == "stage":
                n_vuln, n_safe = _stage_entry(entry)
            elif mode == "clone":
                n_vuln, n_safe = _clone_entry(entry)
            else:
                raise ValueError(f"unknown mode {mode!r}")
            _write_expected(entry)
            print(f"{cve}: {n_vuln} vuln file(s), {n_safe} safe file(s) [{mode}]")
            ok += 1
        except Exception as exc:
            print(f"{cve}: SKIPPED ({exc})", file=sys.stderr)
            skipped += 1

    print(f"\n{ok} CVE(s) materialised, {skipped} skipped")
    return 0 if ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
