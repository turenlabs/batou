package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Returns-source summaries (TaintSummary.ReturnsSource).
//
// A local function that READS a catalog source and RETURNS it used to produce
// zero taint at its call sites — worse than an unknown function. The summary
// machinery was entirely param-indexed (ParamFlows/ReturnTaint/Sanitizes), so
// `def get_q(): return request.args.get('q')` had no propagating params, hit
// the local-summary early return in propagateCallResultInterproc, and never
// reached even the conservative external-call fallback:
//
//	q = get_q()
//	cursor.execute(q)   # ZERO flows before the fix, in every tsflow language
//
// These tests lock in: (TP) helper returning request/CLI/env input taints its
// call site and reaches the sink; (TN) helper returning a constant stays
// clean; (sanitized) helper returning escape(source) is neutralized ONLY for
// the sanitizer's categories.
// =========================================================================

// --- Python ---

func TestReturnsSource_Python_DirectReturn_SQLi(t *testing.T) {
	code := `from flask import request
import sqlite3

def get_q():
    return request.args.get('q')

def handler():
    q = get_q()
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    cur.execute(q)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatalf("expected SQLi flow through zero-arg source-returning helper, got %d flows", len(flows))
	}
}

func TestReturnsSource_Python_ViaLocalVariable_SQLi(t *testing.T) {
	code := `from flask import request

def get_q():
    val = request.args.get('q')
    return val

def handler(cur):
    q = get_q()
    cur.execute(q)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatalf("expected SQLi flow through helper returning a source-assigned local, got %d flows", len(flows))
	}
}

func TestReturnsSource_Python_ConstantReturn_NoFlow(t *testing.T) {
	code := `def get_q():
    return "SELECT * FROM users WHERE id = 1"

def handler(cur):
    q = get_q()
    cur.execute(q)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("helper returning a constant must NOT taint its call site")
	}
}

// The sanitizer's Neutralizes list must scope the call-site taint: escape()
// neutralizes html_output, so the same helper value is clean at an HTML sink
// but still tainted at a SQL sink.
func TestReturnsSource_Python_SanitizedReturn_CategoryScoped(t *testing.T) {
	code := `from flask import request, make_response
from markupsafe import escape

def get_name():
    return escape(request.args.get('name'))

def render(cur):
    name = get_name()
    resp = make_response(name)
    cur.execute(name)
    return resp
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("escape()-wrapped helper return must NOT produce an html_output flow")
	}
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("escape() neutralizes html_output only — the SQL flow must survive")
	}
}

// Helper whose params DO propagate but whose call site passes an untainted
// argument: the old code returned after the param loop found nothing; the
// returns-source fallthrough must still taint the LHS from the in-body source.
func TestReturnsSource_Python_UntaintedArg_FallsThroughToSource(t *testing.T) {
	code := `from flask import request

def get_q(default):
    val = request.args.get('q')
    if val is None:
        return default
    return val

def handler(cur):
    q = get_q("none")
    cur.execute(q)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatalf("expected SQLi flow via returns-source fallthrough when no tainted arg is passed, got %d flows", len(flows))
	}
}

// --- JavaScript ---

func TestReturnsSource_JavaScript_CLIArg_CommandExec(t *testing.T) {
	code := `const { exec } = require('child_process');

function getTarget() {
  return process.argv[2];
}

function run() {
  const target = getTarget();
  exec(target);
}
`
	flows := Analyze(code, "/app/cli.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Fatalf("expected command-injection flow through source-returning JS helper, got %d flows", len(flows))
	}
}

func TestReturnsSource_JavaScript_ConstantReturn_NoFlow(t *testing.T) {
	code := `const { exec } = require('child_process');

function getTarget() {
  return "ls -la /tmp";
}

function run() {
  const target = getTarget();
  exec(target);
}
`
	flows := Analyze(code, "/app/cli.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("JS helper returning a constant must NOT taint its call site")
	}
}

// --- Java ---

func TestReturnsSource_Java_EnvVar_CommandExec(t *testing.T) {
	code := `package com.example;

public class Launcher {
    private String target() {
        return System.getenv("TARGET");
    }

    public void run() throws Exception {
        String t = target();
        Runtime.getRuntime().exec(t);
    }
}
`
	flows := Analyze(code, "/srv/app/Launcher.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Fatalf("expected command-injection flow through source-returning Java helper, got %d flows", len(flows))
	}
}

func TestReturnsSource_Java_ConstantReturn_NoFlow(t *testing.T) {
	code := `package com.example;

public class Launcher {
    private String target() {
        return "/usr/bin/uptime";
    }

    public void run() throws Exception {
        String t = target();
        Runtime.getRuntime().exec(t);
    }
}
`
	flows := Analyze(code, "/srv/app/Launcher.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Java helper returning a constant must NOT taint its call site")
	}
}
