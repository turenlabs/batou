package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Inline taint sources inside a conditional / ternary branch.
//
// Before the findSourceInExpr ternary fix, an as-yet-unbound inline source
// living in a ternary BRANCH was silently dropped:
//
//	const x = flag ? req.query.cmd : "safe";   // x lost taint -> 0 flows
//	cp.exec(flag ? req.query.cmd : "safe");     // inline-source-at-sink missed
//
// nodeIsTainted already recurses ternary branches for tracked-VARIABLE taint,
// but findSourceInExpr (the inline-source resolver used for both the
// assignment-RHS binding and inline-source-at-sink paths) had no conditional
// case, so a source that had never been bound to a local was invisible. This
// affects every tsflow language with a ternary / conditional expression. The
// fix recurses into the consequence and alternative (not the condition) and
// unwraps parenthesized branches, mirroring the existing nodeIsTainted ternary
// + parenthesized handling. These tests pin the recall fix and its FP-safety.

func ternaryHasCmd(code, path string, lang rules.Language) bool {
	return hasTaintFlow(Analyze(code, path, lang), taint.SnkCommand)
}

// --- JavaScript / TypeScript ---

func TestTernarySource_JS_AssignConsequence(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const x = req.query.flag ? req.query.cmd : "safe";
  cp.exec(x);
}`
	if !ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("expected command_exec flow for inline source in ternary consequence")
	}
}

func TestTernarySource_JS_AssignAlternative(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const x = req.query.flag ? "safe" : req.query.cmd;
  cp.exec(x);
}`
	if !ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("expected command_exec flow for inline source in ternary alternative")
	}
}

func TestTernarySource_JS_InlineAtSink(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  cp.exec(req.query.flag ? req.query.cmd : "safe");
}`
	if !ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("expected command_exec flow for ternary inline-source directly at sink")
	}
}

func TestTernarySource_JS_NestedParenthesized(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const x = req.query.a ? "s" : (req.query.b ? req.query.cmd : "t");
  cp.exec(x);
}`
	if !ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("expected command_exec flow for source in a parenthesized nested ternary")
	}
}

func TestTernarySource_JS_ParenthesizedSource(t *testing.T) {
	// Exercises the parenthesized_expression unwrap on its own.
	code := `
const cp = require('child_process');
function handler(req) {
  const x = (req.query.cmd);
  cp.exec(x);
}`
	if !ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("expected command_exec flow for a parenthesized inline source")
	}
}

func TestTernarySource_TS_Assign(t *testing.T) {
	code := `
import { exec } from 'child_process';
function handler(req: any) {
  const x = req.query.flag ? req.query.cmd : "safe";
  exec(x);
}`
	if !ternaryHasCmd(code, "/app/handler.ts", rules.LangTypeScript) {
		t.Error("expected command_exec flow for TS ternary inline source")
	}
}

// --- Python (conditional_expression: `cons if cond else alt`) ---

func TestTernarySource_Python_Assign(t *testing.T) {
	code := `
import subprocess
def handler(request):
    x = request.args.get("cmd") if request.args.get("f") else "safe"
    subprocess.call(x, shell=True)`
	if !ternaryHasCmd(code, "/app/handler.py", rules.LangPython) {
		t.Error("expected command_exec flow for Python conditional-expression inline source")
	}
}

func TestTernarySource_Python_AtSink(t *testing.T) {
	code := `
import subprocess
def handler(request):
    subprocess.call(request.args.get("cmd") if request.args.get("f") else "safe", shell=True)`
	if !ternaryHasCmd(code, "/app/handler.py", rules.LangPython) {
		t.Error("expected command_exec flow for Python conditional-expression at sink")
	}
}

// --- Ruby ---

func TestTernarySource_Ruby_Assign(t *testing.T) {
	code := `
def handler(params)
  x = params[:f] ? params[:cmd] : "safe"
  system(x)
end`
	if !ternaryHasCmd(code, "/app/handler.rb", rules.LangRuby) {
		t.Error("expected command_exec flow for Ruby ternary inline source")
	}
}

// --- Java ---

func TestTernarySource_Java_Assign(t *testing.T) {
	code := `
public class Handler {
  void handle(javax.servlet.http.HttpServletRequest request) throws Exception {
    String x = request.getParameter("f") != null ? request.getParameter("cmd") : "safe";
    Runtime.getRuntime().exec(x);
  }
}`
	if !ternaryHasCmd(code, "/app/Handler.java", rules.LangJava) {
		t.Error("expected command_exec flow for Java ternary inline source")
	}
}

// --- PHP (conditional_expression names the consequence field "body") ---

func TestTernarySource_PHP_Assign(t *testing.T) {
	code := `<?php
function handler() {
  $x = isset($_GET['f']) ? $_GET['cmd'] : "safe";
  system($x);
}`
	if !ternaryHasCmd(code, "/app/handler.php", rules.LangPHP) {
		t.Error("expected command_exec flow for PHP ternary inline source")
	}
}

// --- FP-safety ---

// A source appearing ONLY in the ternary CONDITION must not taint the bound
// result — both branches are safe literals, so the value is always safe. The
// fix deliberately checks the branches, not the condition.
func TestTernarySource_FP_ConditionOnlySource(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const x = req.query.flag ? "a" : "b";
  cp.exec(x);
}`
	if ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("false positive: a source only in the ternary condition must not taint the result")
	}
}

// A ternary with no source anywhere must produce no flow.
func TestTernarySource_FP_NoSource(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(flag) {
  const x = flag ? "a" : "b";
  cp.exec(x);
}`
	if ternaryHasCmd(code, "/app/handler.js", rules.LangJavaScript) {
		t.Error("false positive: ternary of literals must not produce a flow")
	}
}
