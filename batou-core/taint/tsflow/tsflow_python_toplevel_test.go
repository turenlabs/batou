package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python flat-script (top-level / module-scope) taint tests.
//
// A huge share of real Python is a flat script with no enclosing def: CLI
// tools, data/ETL jobs, Streamlit/Jupyter-as-script, and simple CGI all read
// input and reach a sink at module top level
// (`cmd = input(); os.system(cmd)`). Before the top-level walk these produced
// ZERO flows — the per-function pass only descends into function/method
// bodies, so a byte-identical `def handler(): ...` wrapper fired while the
// flat form did not (proven by probe). The walk shares a single taint map
// across top-level statements so a source threaded through assignment /
// interpolation / concatenation reaches a downstream sink.
//
// These tests lock in the recall AND the matching FP-safe behaviour
// (sanitizers, guards, imports/constants, class-method scoping).
// =========================================================================

// countCat returns the number of flows that reached the given sink category.
func countCat(flows []taint.TaintFlow, cat taint.SinkCategory) int {
	n := 0
	for i := range flows {
		if flows[i].Sink.Category == cat {
			n++
		}
	}
	return n
}

func TestPython_TopLevel_CommandInjection_Input(t *testing.T) {
	code := `import os
cmd = input("cmd> ")
os.system("echo " + cmd)`
	flows := Analyze(code, "/app/tool.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected top-level command-injection flow input() -> os.system")
	}
}

func TestPython_TopLevel_SQLi_Concat(t *testing.T) {
	code := `import sqlite3
name = input()
conn = sqlite3.connect("app.db")
cur = conn.cursor()
cur.execute("SELECT * FROM users WHERE name = '" + name + "'")`
	flows := Analyze(code, "/app/report.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected top-level SQLi flow input() -> concatenated query -> cursor.execute")
	}
}

func TestPython_TopLevel_Argv_FileSink(t *testing.T) {
	// sys.argv[1] threaded into open() at file scope.
	code := `import sys
p = sys.argv[1]
open("/data/" + p).read()`
	flows := Analyze(code, "/app/cat.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected top-level file flow sys.argv -> open()")
	}
}

func TestPython_TopLevel_Environ_SSRF(t *testing.T) {
	code := `import os
import urllib.request
host = os.environ["HOST"]
urllib.request.urlopen("http://" + host + "/api")`
	flows := Analyze(code, "/app/fetch.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected top-level SSRF flow os.environ -> urllib.request.urlopen")
	}
}

func TestPython_TopLevel_IfGuardBody_Walked(t *testing.T) {
	// The whole flow lives inside an `if <cond>:` block at file scope.
	code := `import os
name = input()
if name:
    os.system("ls " + name)`
	flows := Analyze(code, "/app/tool.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow inside a top-level if-body")
	}
}

func TestPython_TopLevel_Sanitized_NoFlow(t *testing.T) {
	// shlex.quote() neutralizes the command-injection flow.
	code := `import os
import shlex
cmd = input()
os.system("echo " + shlex.quote(cmd))`
	flows := Analyze(code, "/app/tool.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("shlex.quote() must neutralize the top-level command-injection flow")
	}
}

func TestPython_TopLevel_ExitGuard_ClearsTaint(t *testing.T) {
	// A '..' containment guard with sys.exit() on the unsafe path must clear
	// taint on the safe fall-through, so the subsequent open() is NOT flagged.
	code := `import sys
p = sys.argv[1]
if ".." in p:
    sys.exit("bad path")
open("/data/" + p).read()`
	flows := Analyze(code, "/app/cat.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("'..' guard + sys.exit() must clear taint on the safe path")
	}
}

func TestPython_TopLevel_ConstantArg_NoFP(t *testing.T) {
	// A constant (non-tainted) argument must not flag.
	code := `import os
os.system("ls -la /tmp")`
	flows := Analyze(code, "/app/tool.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("constant os.system() argument must not flag at top level")
	}
}

func TestPython_TopLevel_ImportsConstants_NoFP(t *testing.T) {
	// Module-level imports, constants, and framework setup must not produce
	// any flow — the common reason the other 13 tsflow languages were
	// deliberately left out of the top-level walk.
	code := `import os
import sys
from flask import Flask

DEBUG = True
NAME = "service"
app = Flask(__name__)
app.config["SECRET_KEY"] = "static"
print("starting", NAME)`
	flows := Analyze(code, "/app/app.py", rules.LangPython)
	if len(flows) != 0 {
		t.Errorf("module-level imports/constants/setup must produce no flows, got %d", len(flows))
	}
}

func TestPython_TopLevel_ClassMethod_NotDoubleCounted(t *testing.T) {
	// A class method's internal source->sink is analyzed once by the
	// per-function pass. The top-level walk must NOT descend into the class
	// body (which would double-report the flow).
	code := `import os
class Handler:
    def run(self):
        cmd = input()
        os.system(cmd)`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if got := countCat(flows, taint.SnkCommand); got != 1 {
		t.Errorf("class-method flow must be reported exactly once, got %d", got)
	}
}
