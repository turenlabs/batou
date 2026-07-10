package tsflow

// Intra-function MUST-alias tests for tsflow.
//
// These verify the contract documented on taintMap.aliases: a straight
// `b = a` copy of a bare object reference makes the two names interchangeable
// for field reads/writes within the same function, so a field written through
// one name (`b.field = src`) is observed through a field read on the other
// (`sink(a.field)`). The alias is MUST-alias (not may-alias): reassigning a
// name breaks its edge, and a sibling field is never tainted.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

func sqlFlowCount(flows []taint.TaintFlow) int {
	n := 0
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			n++
		}
	}
	return n
}

// Positive (the FN this fix closes): `b = a; b.q = src; sink(a.q)`. Tainting a
// field through the alias `b` must be seen when read through the original `a`.
// Without the must-alias map this produced ZERO flows.
func TestPython_ObjectAlias_FieldWriteThroughAlias_Detected(t *testing.T) {
	code := `
from flask import request

def handler():
    a = obj
    b = a
    b.q = request.args.get('q')
    cursor.execute(a.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for b=a; b.q=src; execute(a.q) (object aliasing)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Symmetry: the field may be written through the original and read through the
// alias — `a.q = src; b = a; sink(b.q)`.
func TestPython_ObjectAlias_FieldWriteThroughOriginal_ReadThroughAlias(t *testing.T) {
	code := `
from flask import request

def handler():
    a = obj
    a.q = request.args.get('q')
    b = a
    cursor.execute(b.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for a.q=src; b=a; execute(b.q) (alias read)")
	}
}

// Negative (must-alias precision): reassigning `b` to a different object breaks
// the alias, so a later `b.q = src` does NOT reflect on `a.q`.
func TestPython_ObjectAlias_BrokenByReassignment_NoFlow(t *testing.T) {
	code := `
from flask import request

def handler():
    a = obj
    b = a
    b = other
    b.q = request.args.get('q')
    cursor.execute(a.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if n := sqlFlowCount(flows); n != 0 {
		t.Errorf("did not expect SQL flow after `b = other` breaks the alias; got %d", n)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative (sibling precision): tainting `b.q` must not taint a DIFFERENT field
// `a.other`. Only the written field is aliased, not the whole object's slots.
func TestPython_ObjectAlias_SiblingField_NoFlow(t *testing.T) {
	code := `
from flask import request

def handler():
    a = obj
    b = a
    b.q = request.args.get('q')
    cursor.execute(a.other)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if n := sqlFlowCount(flows); n != 0 {
		t.Errorf("did not expect SQL flow on sibling field a.other; got %d", n)
	}
}

// Negative (no spurious alias): a third, unrelated variable must not pick up
// the alias' field taint. `b` aliases `a`; tainting `b.q` must not flow to an
// unrelated `c.q`.
func TestPython_ObjectAlias_UnrelatedVar_NoFlow(t *testing.T) {
	code := `
from flask import request

def handler():
    a = obj
    b = a
    c = other
    b.q = request.args.get('q')
    cursor.execute(c.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if n := sqlFlowCount(flows); n != 0 {
		t.Errorf("did not expect SQL flow on unrelated c.q; got %d", n)
	}
}

// Soundness of the over-clear direction must be preserved: `a = src; b = a;
// a = "safe"; sink(b)` still fires — clearing `a` (and breaking its alias)
// must NOT clear `b`'s own copied taint. Guards against the alias machinery
// over-clearing the existing last-write-wins behaviour.
func TestPython_ObjectAlias_OverClearStillFires(t *testing.T) {
	code := `
from flask import request

def handler():
    a = request.args.get('q')
    b = a
    a = "safe"
    cursor.execute(b)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for a=src; b=a; a=safe; execute(b) (over-clear must stay sound)")
	}
}

// JS gets the must-alias behaviour for free (tsflow's mechanism is
// language-agnostic): `const b = a; b.q = req.query.q; db.query(a.q)`.
func TestJS_ObjectAlias_FieldWriteThroughAlias_Detected(t *testing.T) {
	code := `
function handler(req, res) {
    const a = {};
    const b = a;
    b.q = req.query.q;
    db.query(a.q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected JS SQL flow for const b=a; b.q=req.query.q; query(a.q)")
	}
}

// JS sibling precision: tainting `b.q` does not taint `a.other`.
func TestJS_ObjectAlias_SiblingField_NoFlow(t *testing.T) {
	code := `
function handler(req, res) {
    const a = {};
    const b = a;
    b.q = req.query.q;
    db.query(a.other);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if n := sqlFlowCount(flows); n != 0 {
		t.Errorf("did not expect JS SQL flow on sibling a.other; got %d", n)
	}
}
