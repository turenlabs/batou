// Tests for the catalog-backed caller-side sanitizer gate
// (crossfile_sanitizer_gate.go). The gate is purely suppressive, so every
// scenario has a control twin proving no recall loss:
//
//	(a) y = <catalog sanitizer>(x); calleeSink(y)  → NO finding
//	(b) same without the sanitizer                 → finding (control)
//	(c) sanitize-then-plain-rebind                 → finding PRESERVED
//	(d) sanitizer of the WRONG category            → finding PRESERVED
//
// The sanitizers are chosen deliberately: `int(...)` (Python) and
// `parseInt(...)` (JS) are catalog sanitizers that the coarse per-language
// name regexes (pythonSanitizerRe / javascriptSanitizerRe) do NOT cover,
// so suppression in (a) can only come from the new catalog gate.
package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// --- Python -----------------------------------------------------------

func TestPythonCrossFile_CatalogSanitizerPrevLine_NoFinding(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE id='" + name + "'")
`,
		"app.py": `from flask import Request
from db import find_user

def handle(request: Request):
    safe_id = int(request.args.get('id'))
    find_user(safe_id)
`,
	})
	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) != 0 {
		t.Errorf("int(...) is a catalog SQL sanitizer on the previous line; expected 0 findings, got %d: %+v",
			len(sqlFindings), sqlFindings)
	}
}

func TestPythonCrossFile_CatalogSanitizerControl_Finding(t *testing.T) {
	// Control for the previous test: identical shape WITHOUT the
	// sanitizer wrap — the finding must survive (no recall loss).
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE id='" + name + "'")
`,
		"app.py": `from flask import Request
from db import find_user

def handle(request: Request):
    raw_id = request.args.get('id')
    find_user(raw_id)
`,
	})
	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("control case (no sanitizer) must still produce SQL_QUERY finding; got %v",
			findingRuleIDs(findings))
	}
}

func TestPythonCrossFile_SanitizeThenPlainRebind_FindingPreserved(t *testing.T) {
	// Last-assignment-wins: the plain rebind revokes the earlier
	// sanitize, so the finding must be preserved.
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE id='" + name + "'")
`,
		"app.py": `from flask import Request
from db import find_user

def handle(request: Request):
    val = int(request.args.get('id'))
    val = request.args.get('id')
    find_user(val)
`,
	})
	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("plain rebind after sanitize must revoke the suppression; got %v",
			findingRuleIDs(findings))
	}
}

func TestPythonCrossFile_WrongCategorySanitizer_FindingPreserved(t *testing.T) {
	// os.path.basename neutralizes FILE_WRITE / FILE_READ — not SQL. A
	// basename wrap before a SQL sink must NOT suppress. (basename is
	// also absent from pythonSanitizerRe, so nothing else suppresses.)
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE id='" + name + "'")
`,
		"app.py": `import os.path
from flask import Request
from db import find_user

def handle(request: Request):
    val = os.path.basename(request.args.get('id'))
    find_user(val)
`,
	})
	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("wrong-category sanitizer (basename vs SQL) must not suppress; got %v",
			findingRuleIDs(findings))
	}
}

// --- JavaScript --------------------------------------------------------

func TestJavaScriptCrossFile_CatalogSanitizerPrevLine_NoFinding(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.js": `const child_process = require('child_process');
function runShell(cmd) {
  child_process.exec(cmd);
}
module.exports = { runShell };
`,
		"app.js": `const { runShell } = require('./runner');
function handle(req, res) {
  const idNum = parseInt(req.body.id);
  runShell(idNum);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) != 0 {
		t.Errorf("parseInt(...) is a catalog command sanitizer on the previous line; expected 0 findings, got %d: %+v",
			len(cmdFindings), cmdFindings)
	}
}

func TestJavaScriptCrossFile_CatalogSanitizerControl_Finding(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.js": `const child_process = require('child_process');
function runShell(cmd) {
  child_process.exec(cmd);
}
module.exports = { runShell };
`,
		"app.js": `const { runShell } = require('./runner');
function handle(req, res) {
  const rawId = req.body.id;
  runShell(rawId);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")) == 0 {
		t.Fatalf("control case (no sanitizer) must still produce COMMAND_EXEC finding; got %v",
			findingRuleIDs(findings))
	}
}

func TestJavaScriptCrossFile_SanitizeThenPlainRebind_FindingPreserved(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.js": `const child_process = require('child_process');
function runShell(cmd) {
  child_process.exec(cmd);
}
module.exports = { runShell };
`,
		"app.js": `const { runShell } = require('./runner');
function handle(req, res) {
  let val = parseInt(req.body.id);
  val = req.body.id;
  runShell(val);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")) == 0 {
		t.Fatalf("plain rebind after sanitize must revoke the suppression; got %v",
			findingRuleIDs(findings))
	}
}

func TestJavaScriptCrossFile_WrongCategorySanitizer_FindingPreserved(t *testing.T) {
	// path.basename neutralizes FILE_WRITE / FILE_READ — not command
	// exec. (basename is also absent from javascriptSanitizerRe.)
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.js": `const child_process = require('child_process');
function runShell(cmd) {
  child_process.exec(cmd);
}
module.exports = { runShell };
`,
		"app.js": `const path = require('path');
const { runShell } = require('./runner');
function handle(req, res) {
  const val = path.basename(req.body.id);
  runShell(val);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")) == 0 {
		t.Fatalf("wrong-category sanitizer (basename vs command exec) must not suppress; got %v",
			findingRuleIDs(findings))
	}
}

// --- helper-level unit tests -------------------------------------------

func TestSanitizerGateBaseVar(t *testing.T) {
	cases := map[string]string{
		"y":           "y",
		" y ":         "y",
		"$y":          "y",
		"@user":       "user",
		"\"$y\"":      "y",
		"obj.field":   "obj",
		"row[\"k\"]":  "row",
		"p->name":     "p",
		"A::B":        "A",
		"y.strip()":   "", // call → decline
		"a + b":       "", // operator → decline
		"f(x)":        "", // call → decline
		"'literal'":   "", // quoted literal is stripped to a bare word — but
		"123":         "", // numeric → decline (must start with letter/_)
		"":            "",
		"${y}":        "", // interpolation braces → decline
		"req.body.id": "req",
		"list [0]":    "", // space → decline
		"_priv":       "_priv",
	}
	// Note: "'literal'" strips quotes to "literal" which IS a plain word;
	// adjust expectation — a bare word is indistinguishable from a var
	// name, and a literal never has an assignment fact, so gating it is
	// harmless. Fix the map entry accordingly.
	cases["'literal'"] = "literal"
	for in, want := range cases {
		if got := sanitizerGateBaseVar(in); got != want {
			t.Errorf("sanitizerGateBaseVar(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCallerArgSanitizedByCatalog_FailOpen(t *testing.T) {
	// Unsupported language → false (keep the finding).
	if callerArgSanitizedByCatalog(nil, "/app/x.go", "package main", rules.LangGo, "y", 10, taint.SnkSQLQuery) {
		t.Error("Go (unsupported by tsflow) must fail open")
	}
	// Empty language → false.
	if callerArgSanitizedByCatalog(nil, "/app/x", "y = int(x)", "", "y", 10, taint.SnkSQLQuery) {
		t.Error("empty language must fail open")
	}
	// Complex arg expression → false.
	content := "def f(request):\n    y = int(request.args.get('id'))\n    g(y)\n"
	if callerArgSanitizedByCatalog(nil, "/app/x.py", content, rules.LangPython, "y + z", 3, taint.SnkSQLQuery) {
		t.Error("complex arg expression must fail open")
	}
	// Positive case sanity: the simple identifier IS gated.
	if !callerArgSanitizedByCatalog(nil, "/app/x.py", content, rules.LangPython, "y", 3, taint.SnkSQLQuery) {
		t.Error("y = int(...) before line 3 should be sanitized for SQL")
	}
	// No fact before the line → false.
	if callerArgSanitizedByCatalog(nil, "/app/x.py", content, rules.LangPython, "y", 2, taint.SnkSQLQuery) {
		t.Error("no fact strictly before line 2 → must fail open")
	}
}

func TestSanitizerFactsMemo_CachesPerFile(t *testing.T) {
	memo := newSanitizerFactsMemo()
	content := "def f(request):\n    y = int(request.args.get('id'))\n"
	f1 := memo.factsFor("/app/x.py", content, rules.LangPython)
	if len(f1) == 0 {
		t.Fatal("expected facts")
	}
	// Second call must hit the cache (same slice header data).
	f2 := memo.factsFor("/app/x.py", "IGNORED — cache keyed by path", rules.LangPython)
	if len(f2) != len(f1) {
		t.Fatalf("memo miss: %d vs %d facts", len(f2), len(f1))
	}
	// Parse failures are cached as empty non-nil (no per-finding retry).
	bad := memo.factsFor("/app/y.go", "package main", rules.LangGo)
	if bad == nil {
		t.Fatal("negative result should be cached as empty slice")
	}
	if len(bad) != 0 {
		t.Fatalf("Go content should have no facts, got %v", bad)
	}
}
