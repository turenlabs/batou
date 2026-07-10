package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Regression: an UNBOUND inline source-call passed as an argument to a LOCAL
// function whose result is assigned and reaches a sink must propagate taint,
// exactly as the bound-variable sibling does. The local-callee
// argument-propagation path in propagateCallResultInterproc gated on
// nodeIsTainted(arg), which does not resolve an inline source-call expression.
//
//	x = transform(request.args.get("y"))   <- inline source as arg
//	cur.execute(x)                          <- sink
func TestInlineSourceArg_AssignResult_LocalCallee(t *testing.T) {
	code := `
from flask import request

def transform(v):
    return v.strip()

def handler(cur):
    x = transform(request.args.get("y"))
    cur.execute(x)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for x = transform(request.args.get(y)); cur.execute(x); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Bound-variable sibling (already worked pre-fix) — guards against a future
// change that breaks the canonical path the inline case mirrors.
func TestBoundSourceArg_AssignResult_LocalCallee(t *testing.T) {
	code := `
from flask import request

def transform(v):
    return v.strip()

def handler(cur):
    s = request.args.get("y")
    x = transform(s)
    cur.execute(x)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for bound s; x = transform(s); cur.execute(x); got %d flows", len(flows))
	}
}

// Same inline-source-arg shape through an UNKNOWN/external function (the
// conservative arg-propagation branch of propagateCallResultInterproc).
func TestInlineSourceArg_AssignResult_ExternalCallee(t *testing.T) {
	code := `
from flask import request
import somelib

def handler(cur):
    x = somelib.passthrough(request.args.get("y"))
    cur.execute(x)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for x = somelib.passthrough(request.args.get(y)); cur.execute(x); got %d flows", len(flows))
	}
}

// Clean negative sibling: a constant argument must not produce a flow, so the
// inline-source resolution above is not just blanket-tainting every call arg.
func TestConstantArg_AssignResult_LocalCallee_NoFlow(t *testing.T) {
	code := `
def transform(v):
    return v.strip()

def handler(cur):
    x = transform("constant")
    cur.execute(x)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant arg should not produce a SQLi flow")
	}
}
