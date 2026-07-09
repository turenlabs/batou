#!/usr/bin/env python3
"""Deterministic large-file corpus generator for Batou perf+regression testing.

Generates realistic source files (Go, Python, JavaScript, C) at target line
counts (1k / 5k / 10k). Each file interleaves benign business logic with a
controlled density of GENUINE vuln patterns and intra-file taint flows so all
four layers (regex, AST, taint, callgraph) do real work. Deterministic: fixed
per-(lang,size) seed -> byte-identical reruns. PM-owned ground-truth corpus.
"""
import os
import random
import sys

OUT_ROOT = sys.argv[1] if len(sys.argv) > 1 else "corpus"
SIZES = [1000, 5000, 10000]


def rng_for(lang, size):
    return random.Random(f"batou-largefile::{lang}::{size}")


def gen_go(size):
    r = rng_for("go", size)
    L = []
    L += ["// Code generated for Batou large-file perf corpus. DO NOT rely on as a real program.",
          "// nolint", "package largecorpus", "",
          "import (", '\t"crypto/md5"', '\t"database/sql"', '\t"fmt"',
          '\t"net/http"', '\t"os"', '\t"os/exec"', '\t"strings"', ")", "",
          "var globalDB *sql.DB", ""]
    i = 0
    while len(L) < size:
        i += 1
        kind = r.random()
        if kind < 0.55:
            L += [f"func compute{i}(a, b int, name string) int {{",
                  f"\ttotal := a*{r.randint(2,9)} + b",
                  "\tfor k := 0; k < len(name); k++ {",
                  "\t\ttotal += int(name[k])", "\t}",
                  "\tmsg := fmt.Sprintf(\"row %d for %s\", total, name)", "\t_ = msg",
                  f"\tif total > {r.randint(10,9999)} {{", "\t\ttotal = total % 1000",
                  "\t}", "\treturn total", "}"]
        elif kind < 0.70:
            L += [f"func handleQuery{i}(w http.ResponseWriter, req *http.Request) {{",
                  "\tuserID := req.URL.Query().Get(\"id\")",
                  "\tquery := \"SELECT * FROM accounts WHERE id = '\" + userID + \"'\"",
                  "\trows, err := globalDB.Query(query)", "\tif err != nil {",
                  "\t\thttp.Error(w, err.Error(), 500)", "\t\treturn", "\t}",
                  "\tdefer rows.Close()", "}"]
        elif kind < 0.80:
            L += [f"func runCmd{i}(arg string) ([]byte, error) {{",
                  "\treturn exec.Command(\"sh\", \"-c\", arg).CombinedOutput()", "}",
                  f"func dispatch{i}(req *http.Request) {{",
                  "\tname := req.URL.Query().Get(\"cmd\")",
                  f"\tout, _ := runCmd{i}(\"echo \" + name)", "\t_ = out", "}"]
        elif kind < 0.88:
            L += [f"func readFile{i}(req *http.Request) ([]byte, error) {{",
                  "\tp := req.URL.Query().Get(\"path\")",
                  "\treturn os.ReadFile(\"/var/data/\" + p)", "}"]
        elif kind < 0.93:
            L += [f"func hashToken{i}(tok string) string {{",
                  "\th := md5.Sum([]byte(tok))",
                  "\treturn fmt.Sprintf(\"%x\", h)", "}"]
        elif kind < 0.96:
            L += [f"func client{i}() string {{",
                  f"\tapiKey := \"AKIA{r.randint(10**11,10**12-1)}EXAMPLE\"",
                  "\treturn apiKey", "}"]
        else:
            L += [f"type Record{i} struct {{", "\tID   int", "\tName string",
                  "\tTags []string", "}",
                  f"func (r *Record{i}) Label() string {{",
                  "\treturn strings.Join(r.Tags, \",\")", "}"]
        L.append("")
    return "\n".join(L[:size]) + "\n"


def gen_py(size):
    r = rng_for("python", size)
    L = ["# Code generated for Batou large-file perf corpus.",
         "import os", "import hashlib", "import subprocess", "import sqlite3",
         "from flask import request, Flask", "", "app = Flask(__name__)",
         "db = sqlite3.connect('app.db', check_same_thread=False)", ""]
    i = 0
    while len(L) < size:
        i += 1
        kind = r.random()
        if kind < 0.55:
            L += [f"def compute_{i}(a, b, name):",
                  f"    total = a * {r.randint(2,9)} + b",
                  "    for ch in str(name):", "        total += ord(ch)",
                  f"    if total > {r.randint(10,9999)}:", "        total %= 1000",
                  "    return total"]
        elif kind < 0.70:
            L += [f"@app.route('/q{i}')", f"def handle_query_{i}():",
                  "    uid = request.args.get('id')",
                  "    query = \"SELECT * FROM accounts WHERE id = '\" + uid + \"'\"",
                  "    cur = db.cursor()", "    cur.execute(query)",
                  "    return str(cur.fetchall())"]
        elif kind < 0.80:
            L += [f"def run_cmd_{i}(arg):",
                  "    return subprocess.check_output('echo ' + arg, shell=True)",
                  f"@app.route('/c{i}')", f"def dispatch_{i}():",
                  "    name = request.args.get('cmd')", f"    return run_cmd_{i}(name)"]
        elif kind < 0.88:
            L += [f"@app.route('/f{i}')", f"def read_file_{i}():",
                  "    p = request.args.get('path')",
                  "    with open('/var/data/' + p) as fh:", "        return fh.read()"]
        elif kind < 0.93:
            L += [f"def hash_token_{i}(tok):",
                  "    return hashlib.md5(tok.encode()).hexdigest()"]
        elif kind < 0.96:
            L += [f"def client_{i}():",
                  f"    api_key = 'AKIA{r.randint(10**11,10**12-1)}EXAMPLE'",
                  "    return api_key"]
        else:
            L += [f"class Record{i}:",
                  "    def __init__(self, rid, name, tags):",
                  "        self.id = rid", "        self.name = name",
                  "        self.tags = tags", "    def label(self):",
                  "        return ','.join(self.tags)"]
        L.append("")
    return "\n".join(L[:size]) + "\n"


def gen_js(size):
    r = rng_for("javascript", size)
    L = ["// Code generated for Batou large-file perf corpus.", "'use strict';",
         "const express = require('express');", "const crypto = require('crypto');",
         "const cp = require('child_process');", "const app = express();", "let db;", ""]
    i = 0
    while len(L) < size:
        i += 1
        kind = r.random()
        if kind < 0.55:
            L += [f"function compute{i}(a, b, name) {{",
                  f"  let total = a * {r.randint(2,9)} + b;",
                  "  for (let k = 0; k < String(name).length; k++) {",
                  "    total += String(name).charCodeAt(k);", "  }",
                  f"  if (total > {r.randint(10,9999)}) total = total % 1000;",
                  "  return total;", "}"]
        elif kind < 0.70:
            L += [f"app.get('/q{i}', (req, res) => {{", "  const uid = req.query.id;",
                  "  const query = \"SELECT * FROM accounts WHERE id = '\" + uid + \"'\";",
                  "  db.query(query, (e, rows) => res.json(rows));", "});"]
        elif kind < 0.80:
            L += [f"function runCmd{i}(arg) {{", "  return cp.execSync('echo ' + arg);", "}",
                  f"app.get('/c{i}', (req, res) => {{", "  const name = req.query.cmd;",
                  f"  res.send(runCmd{i}(name));", "});"]
        elif kind < 0.88:
            L += [f"app.get('/x{i}', (req, res) => {{", "  const name = req.query.name;",
                  "  res.send('<h1>Hello ' + name + '</h1>');", "});"]
        elif kind < 0.93:
            L += [f"function hashToken{i}(tok) {{",
                  "  return crypto.createHash('md5').update(tok).digest('hex');", "}"]
        elif kind < 0.96:
            L += [f"function client{i}() {{",
                  f"  const apiKey = 'AKIA{r.randint(10**11,10**12-1)}EXAMPLE';",
                  "  return apiKey;", "}"]
        else:
            L += [f"class Record{i} {{", "  constructor(id, name, tags) {",
                  "    this.id = id; this.name = name; this.tags = tags;", "  }",
                  "  label() { return this.tags.join(','); }", "}"]
        L.append("")
    return "\n".join(L[:size]) + "\n"


def gen_c(size):
    r = rng_for("c", size)
    L = ["/* Code generated for Batou large-file perf corpus. */",
         "#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>",
         "#include <unistd.h>", ""]
    i = 0
    while len(L) < size:
        i += 1
        kind = r.random()
        if kind < 0.55:
            L += [f"int compute_{i}(int a, int b, const char *name) {{",
                  f"    int total = a * {r.randint(2,9)} + b;",
                  "    for (size_t k = 0; k < strlen(name); k++) {",
                  "        total += (int)name[k];", "    }",
                  f"    if (total > {r.randint(10,9999)}) total %= 1000;",
                  "    return total;", "}"]
        elif kind < 0.72:
            L += [f"void handle_{i}(char *input) {{", "    char buf[64];",
                  "    strcpy(buf, input);", "    printf(\"%s\\n\", buf);", "}"]
        elif kind < 0.85:
            L += [f"void run_{i}(const char *arg) {{", "    char cmd[256];",
                  "    sprintf(cmd, \"echo %s\", arg);", "    system(cmd);", "}"]
        elif kind < 0.93:
            L += [f"void logmsg_{i}(const char *msg) {{", "    printf(msg);", "}"]
        else:
            L += [f"struct Record{i} {{", "    int id;", "    char name[32];", "};",
                  f"int label_{i}(struct Record{i} *r) {{", "    return r->id;", "}"]
        L.append("")
    return "\n".join(L[:size]) + "\n"


GENERATORS = {("go", "go"): gen_go, ("python", "py"): gen_py,
              ("javascript", "js"): gen_js, ("c", "c"): gen_c}


def main():
    for (lang, ext), gen in GENERATORS.items():
        d = os.path.join(OUT_ROOT, lang)
        os.makedirs(d, exist_ok=True)
        for size in SIZES:
            content = gen(size)
            path = os.path.join(d, f"large_{size // 1000}k.{ext}")
            # batou:ignore BATOU-PYAST-004 -- trusted local generator; path = fixed OUT_ROOT + hardcoded filename, no user input
            with open(path, "w") as f:
                f.write(content)
            print(f"{path}: {content.count(chr(10))} lines, {len(content)} bytes")


if __name__ == "__main__":
    main()
