package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Python tuple/list unpacking assignment taint propagation.
//
// Before this support, the LHS of `a, b = ...` parses as a pattern_list which
// extractAssignLHS cannot represent (it returns ""), so processAssignInterproc
// bailed and every unpacked target silently lost taint. These tests pin the
// recall fix and guard its element-wise precision against false positives.

// Conservative whole-RHS distribution: every element unpacked from a tainted
// iterable derives from it.
func TestPythonUnpack_SplitTaintsAllTargets(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    raw = request.args.get("data")
    a, b = raw.split(",")
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow: request.args -> split -> unpacked a -> subprocess.call")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Conservative distribution must also taint the *second* target.
func TestPythonUnpack_SplitTaintsSecondTarget(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    raw = request.args.get("data")
    a, b = raw.split(",")
    subprocess.call(b, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow on second unpacked target b")
	}
}

// Element-wise binding from a literal tuple RHS: the tainted element flows.
func TestPythonUnpack_ElementWiseTaintedFirst(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    a, b = request.args.get("data"), "safe"
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow: inline source in tuple element -> a -> subprocess.call")
	}
}

// Element-wise PRECISION: only the matching target is tainted. The clean
// element must NOT carry taint (no false positive).
func TestPythonUnpack_ElementWisePrecision(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    a, b = "ls", request.args.get("data")
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("false positive: clean element a must not be tainted under element-wise binding")
	}
}

// Element-wise binding via a tracked variable element flows to SQL too.
func TestPythonUnpack_ElementWiseSQL(t *testing.T) {
	code := `
from flask import request

def handler():
    name = request.args.get("name")
    a, b = name, "const"
    cursor.execute("SELECT * FROM users WHERE name = '" + a + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through element-wise unpacked variable a")
	}
}

// list_pattern LHS (`[a, b] = ...`) with a tainted single-expression RHS.
func TestPythonUnpack_ListPattern(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    raw = request.args.get("data")
    parts = raw.split(",")
    [a, b] = parts
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow through list_pattern unpack [a, b] = parts")
	}
}

// Starred target (`first, *rest = ...`): conservative distribution taints the
// star target as well.
func TestPythonUnpack_StarredTarget(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    raw = request.args.get("data")
    first, *rest = raw.split(",")
    subprocess.call(first, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow through starred unpack first, *rest")
	}
}

// Swap (`a, b = b, a`) must read pre-assignment taint state: after the swap the
// previously-tainted b lands in a.
func TestPythonUnpack_SwapReadsPreState(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    a = "safe"
    b = request.args.get("data")
    a, b = b, a
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow: swap should move b's taint into a")
	}
}

// Negative control: all-literal unpack produces no taint.
func TestPythonUnpack_LiteralsNoFlow(t *testing.T) {
	code := `
import subprocess

def handler():
    a, b = "ls", "-la"
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("false positive: literal-only unpack must not produce taint")
	}
}

// Negative control: rebinding an unpack target to literals clears prior taint.
func TestPythonUnpack_RebindClearsTaint(t *testing.T) {
	code := `
from flask import request
import subprocess

def handler():
    a = request.args.get("data")
    a, b = "clean1", "clean2"
    subprocess.call(a, shell=True)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("false positive: literal unpack must clear prior taint on a")
	}
}
