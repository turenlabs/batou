package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// hasFileFlow reports whether any flow from the list lands on a file-traversal
// sink (SnkFileRead or SnkFileWrite — open() in Python is registered as
// SnkFileWrite by py.open; os.listdir/stat/etc. are SnkFileRead).
func hasFileFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			return true
		}
	}
	return false
}

// TestPython_PathTraversal_Vulnerable_NoGuard is the positive baseline:
// open(request.args.get('p')) with no sanitisation must still fire a
// CWE-22 file-write flow. Guards the negative tests below against passing
// for the wrong reason (e.g. taint engine failing to register the source).
func TestPython_PathTraversal_Vulnerable_NoGuard(t *testing.T) {
	code := `
from flask import request

def download():
    path = request.args.get('p')
    f = open(path)
    return f.read()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasFileFlow(flows) {
		t.Fatal("expected file-traversal flow: request.args.get -> open with no sanitizer")
	}
}

// TestPython_PathTraversal_Sanitized_SecureFilename verifies that
// werkzeug.utils.secure_filename strips traversal sequences and is treated
// as a complete sanitizer — open(os.path.join(BASE, safe)) must not flow.
func TestPython_PathTraversal_Sanitized_SecureFilename(t *testing.T) {
	code := `
import os
from flask import request
from werkzeug.utils import secure_filename

BASE = "/var/uploads"

def download():
    raw = request.args.get('p')
    p = secure_filename(raw)
    f = open(os.path.join(BASE, p))
    return f.read()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("secure_filename should neutralize file taint flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_Sanitized_ResolveIsRelativeTo verifies the
// pathlib combo: Path(BASE)/x → resolve() → is_relative_to(BASE). The
// resolve() call alone is not a sanitizer (it would resolve "../etc" to
// "/etc"), but the is_relative_to() containment check completes the
// CWE-22 defence and must clear the file-write taint on `rp`.
func TestPython_PathTraversal_Sanitized_ResolveIsRelativeTo(t *testing.T) {
	code := `
from pathlib import Path
from flask import request

BASE = Path("/var/uploads")

def download():
    x = request.args.get('p')
    rp = (BASE / x).resolve()
    if rp.is_relative_to(BASE):
        f = open(rp)
        return f.read()
    return "rejected"
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("Path.resolve()+is_relative_to(BASE) guard should neutralize file flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_Sanitized_NormpathStartswith verifies the
// os.path.normpath + startswith combo. normpath alone is not a sanitizer
// (normpath("../etc") returns "../etc"); the startswith(BASE) containment
// check is what neutralises the flow.
func TestPython_PathTraversal_Sanitized_NormpathStartswith(t *testing.T) {
	code := `
import os
from flask import request

BASE = "/var/uploads/"

def download():
    raw = request.args.get('p')
    p = os.path.normpath(raw)
    if p.startswith(BASE):
        f = open(p)
        return f.read()
    return "rejected"
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("os.path.normpath+startswith(BASE) guard should neutralize file flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_Vulnerable_NormpathAlone verifies the key
// regression-prevention invariant: normpath WITHOUT a containment check
// must STILL fire a path-traversal flow. normpath("../../etc/passwd")
// returns "../../etc/passwd" unchanged — it normalises double dots but
// does not reject escapes.
func TestPython_PathTraversal_Vulnerable_NormpathAlone(t *testing.T) {
	code := `
import os
from flask import request

def download():
    raw = request.args.get('p')
    p = os.path.normpath(raw)
    f = open(p)
    return f.read()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasFileFlow(flows) {
		t.Fatal("os.path.normpath alone is NOT a sanitizer; expected file-traversal flow to still fire")
	}
}

// TestPython_PathTraversal_Vulnerable_RealpathAlone is the corresponding
// regression test for os.path.realpath. Like normpath, realpath only
// canonicalises (resolves symlinks); it does not enforce a containing dir.
func TestPython_PathTraversal_Vulnerable_RealpathAlone(t *testing.T) {
	code := `
import os
from flask import request

def download():
    raw = request.args.get('p')
    p = os.path.realpath(raw)
    f = open(p)
    return f.read()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasFileFlow(flows) {
		t.Fatal("os.path.realpath alone is NOT a sanitizer; expected file-traversal flow to still fire")
	}
}

// TestPython_PathTraversal_Vulnerable_ResolveAlone — pathlib variant of
// the above. Path(x).resolve() canonicalises but does not enforce a
// containing directory; without is_relative_to / startswith / commonpath
// the open() must still flow.
func TestPython_PathTraversal_Vulnerable_ResolveAlone(t *testing.T) {
	code := `
from pathlib import Path
from flask import request

def download():
    raw = request.args.get('p')
    rp = Path(raw).resolve()
    f = open(rp)
    return f.read()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasFileFlow(flows) {
		t.Fatal("Path.resolve() alone is NOT a sanitizer; expected file-traversal flow to still fire")
	}
}

// TestPython_PathTraversal_Sanitized_CommonpathEqual verifies the
// commonpath containment-equality combo: realpath(x) is canonicalised then
// commonpath([BASE, real]) is compared against BASE. The equality check
// completes the CWE-22 defence.
//
// Test shape note: os.path.join() is itself a SnkFileWrite sink in the
// Python catalog, so a join() call BEFORE the guard would already fire
// regardless of the downstream containment check. The fixture below uses
// pathlib's `/` operator (which is not a sink) to construct the candidate
// path, then realpath() canonicalises it, then commonpath() == BASE
// completes the guard before any actual file sink (open).
func TestPython_PathTraversal_Sanitized_CommonpathEqual(t *testing.T) {
	code := `
import os
from flask import request

BASE = "/var/uploads"

def download():
    raw = request.args.get('p')
    real = os.path.realpath(raw)
    if os.path.commonpath([BASE, real]) == BASE:
        f = open(real)
        return f.read()
    return "rejected"
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("commonpath([BASE,x])==BASE guard should neutralize file flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_Sanitized_BinaryJoinResolveStartswith (PR-PATHpy)
// covers the OWASP Benchmark Python "pathtraver" SAFE idiom:
//
//	testfiles = pathlib.Path(BASE_CONST)
//	p = (testfiles / bar).resolve()
//	if not str(p).startswith(str(testfiles)):
//	    return "rejected"
//	p.read_text()
//
// Before the PR, the receiver-tainted branch in propagateCallResultInterproc
// didn't set pathDerivedFrom on `p` because the receiver of `.resolve()` was
// a binary_operator (`testfiles / bar`), not a bare identifier. That left
// pyHasPathContext unable to back-propagate sanitisation from the
// downstream `startswith(str(testfiles))` guard to the original tainted
// `bar`, producing a false positive on `p.read_text()`.
func TestPython_PathTraversal_Sanitized_BinaryJoinResolveStartswith(t *testing.T) {
	code := `
import pathlib
from flask import request

BASE = "/var/uploads"

def download():
    bar = request.args.get('p')
    testfiles = pathlib.Path(BASE)
    p = (testfiles / bar).resolve()
    if not str(p).startswith(str(testfiles)):
        return "rejected"
    return p.read_text()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("(Path(BASE)/bar).resolve()+startswith(str(BASE)) guard should neutralize file flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_Vulnerable_BinaryJoinResolveNoGuard is the
// negative companion to BinaryJoinResolveStartswith: the same Path-join
// shape WITHOUT a containment guard must still fire. Guards PR-PATHpy
// against silently turning .resolve() on a Path-join into an unconditional
// sanitizer.
func TestPython_PathTraversal_Vulnerable_BinaryJoinResolveNoGuard(t *testing.T) {
	code := `
import pathlib
from flask import request

BASE = "/var/uploads"

def download():
    bar = request.args.get('p')
    testfiles = pathlib.Path(BASE)
    p = (testfiles / bar).resolve()
    return p.read_text()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasFileFlow(flows) {
		t.Fatal("(Path(BASE)/bar).resolve() WITHOUT a containment guard must still fire; flows were neutralised incorrectly")
	}
}

// TestPython_PathTraversal_Sanitized_DotDotIn verifies the
// `if ".." in x: raise` manual-rejection pattern. The early-return body
// makes the fall-through the safe path; the variable's path categories
// are sanitised after the guard.
func TestPython_PathTraversal_Sanitized_DotDotIn(t *testing.T) {
	code := `
from flask import request

def download():
    p = request.args.get('p')
    if ".." in p:
        raise ValueError("path traversal attempt")
    f = open(p)
    return f.read()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("'..' in x raise guard should neutralize file flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_PathCategoryScoped verifies that a Python path
// guard sanitises ONLY the path categories — a follow-up SQL sink on the
// same variable must still flow. This is the precision improvement over
// the generic validation-guard handler, which deletes the variable
// entirely (sanitising all categories).
func TestPython_PathTraversal_PathCategoryScoped(t *testing.T) {
	code := `
import os
import sqlite3
from flask import request

BASE = "/var/data/"

def lookup():
    raw = request.args.get('p')
    p = os.path.normpath(raw)
    if p.startswith(BASE):
        conn = sqlite3.connect("/db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM t WHERE name = '" + p + "'")
        return cur.fetchall()
    return "rejected"
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	foundSQL := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			foundSQL = true
		}
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("path guard should clear file taint, got %+v", f)
		}
	}
	if !foundSQL {
		t.Error("path-traversal guard must NOT clear SQL-injection taint on the same variable; expected SnkSQLQuery flow to still fire")
	}
}

// TestPython_PathTraversal_Sanitized_BareRelativeTo verifies the canonical
// CWE-22 containment idiom where `Path.relative_to(base)` is called as a BARE
// STATEMENT (its result discarded) for its raising side effect: it throws
// ValueError when the resolved path escapes `base`, and the surrounding
// try/except returns 404. This is aiohttp's static-file-server shape
// (web_urldispatcher.py _resolve_path_to_response) and the dominant Python
// containment pattern. Because the guard is neither an if-condition nor an
// assignment, only pyMatchBareStatementPathGuard recognises it.
//
// LOAD-BEARING: stash the py.pathlib.resolve.relative_to catalog entry AND the
// pyMatchBareStatementPathGuard wiring and this test fails (the file flow
// reappears) — see TestPython_PathTraversal_Vulnerable_NoBareRelativeTo for the
// matching positive baseline.
func TestPython_PathTraversal_Sanitized_BareRelativeTo(t *testing.T) {
	code := `
from pathlib import Path
from aiohttp.web import FileResponse

class Handler:
    def _resolve(self, request, directory):
        filename = request.match_info["filename"]
        unresolved_path = directory.joinpath(filename)
        try:
            file_path = unresolved_path.resolve()
            file_path.relative_to(directory)
        except ValueError:
            raise HTTPNotFound()
        return FileResponse(file_path)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasFileFlow(flows) {
		t.Errorf("bare-statement file_path.relative_to(base) containment guard should neutralize file flow; got flows=%+v", flows)
	}
}

// TestPython_PathTraversal_Vulnerable_NoBareRelativeTo is the positive baseline
// for the bare-statement guard: the SAME shape WITHOUT the .relative_to()
// containment call must STILL fire a CWE-22 file flow. This proves the
// suppression in TestPython_PathTraversal_Sanitized_BareRelativeTo is caused by
// the guard recognition and not by the engine losing the source, and that the
// sanitizer is FP-only (recall on the genuinely-unguarded flow is preserved).
func TestPython_PathTraversal_Vulnerable_NoBareRelativeTo(t *testing.T) {
	code := `
from pathlib import Path
from aiohttp.web import FileResponse

class Handler:
    def _resolve(self, request, directory):
        filename = request.match_info["filename"]
        unresolved_path = directory.joinpath(filename)
        file_path = unresolved_path.resolve()
        return FileResponse(file_path)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasFileFlow(flows) {
		t.Fatal("expected file-traversal flow: resolve() with NO relative_to() containment must still fire")
	}
}

// TestPython_PathTraversal_BareRelativeTo_KeepsSQLTaint verifies the guard is
// category-scoped: the bare relative_to() containment check validates only the
// path, so SQL-injection taint on the same variable must survive (it says
// nothing about quoting). Mirrors the if-guard category-scoping test.
func TestPython_PathTraversal_BareRelativeTo_KeepsSQLTaint(t *testing.T) {
	code := `
import sqlite3
from pathlib import Path

def lookup(request, directory):
    name = request.match_info["filename"]
    p = (directory / name).resolve()
    p.relative_to(directory)
    conn = sqlite3.connect("/db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE name = '" + str(p) + "'")
    return cur.fetchall()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	foundSQL := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			foundSQL = true
		}
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("bare relative_to guard should clear file taint, got %+v", f)
		}
	}
	if !foundSQL {
		t.Error("bare relative_to path-guard must NOT clear SQL-injection taint on the same variable; expected SnkSQLQuery flow to still fire")
	}
}
