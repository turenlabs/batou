package tsflow

// Shallow (first-level) field-sensitive taint tests for Python.
//
// These verify the contract documented in taintmap.go's field-sensitive
// helpers: `obj.attr = ...` taints a per-field key `"obj.attr"`, distinct
// from `obj` itself; rebinding `obj` clears all `obj.*` fields; rebinding
// `obj.attr` to a safe literal clears that field; sinks reading the whole
// `obj` conservatively over-approximate by surfacing any `obj.*` taint.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Positive: attribute assignment of a tainted source flows through an
// attribute read into a SQL sink.
func TestPython_FieldSensitive_AttrAssignToAttrRead(t *testing.T) {
	code := `
from flask import request

def handler():
    s.q = request.args.get('q')
    cursor.execute(s.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL injection flow for s.q = request.args.get('q') -> cursor.execute(s.q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Positive: string-concat propagation preserves attribute-level taint —
// `s.q + " AND active=1"` still flows to the sink.
func TestPython_FieldSensitive_AttrStringConcatToSink(t *testing.T) {
	code := `
from flask import request

def handler():
    s.q = request.args.get('q')
    cursor.execute(s.q + " AND active=1")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL injection flow for s.q + concat -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative: a hardcoded attribute value does not flow.
func TestPython_FieldSensitive_AttrHardcoded_NoFlow(t *testing.T) {
	code := `
def handler():
    s.q = "hardcoded"
    cursor.execute(s.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did not expect SQL flow for hardcoded s.q; got %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: tainting one object's field must not flow through an unrelated
// object's field — `s.q` and `other.x` are distinct keys.
func TestPython_FieldSensitive_DifferentObj_NoFlow(t *testing.T) {
	code := `
from flask import request

def handler():
    s.q = request.args.get('q')
    other.x = ""
    cursor.execute(other.x)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did not expect SQL flow on other.x; got %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// Regression: the existing variable-to-variable taint shape (no attribute)
// must still be detected. This guards against the field-sensitive changes
// disturbing the baseline `q = source(); sink(q)` flow.
func TestPython_FieldSensitive_PlainVar_StillDetected(t *testing.T) {
	code := `
from flask import request

def handler():
    q = request.args.get('q')
    cursor.execute(q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("baseline regression: expected SQL flow for q = request.args.get('q') -> cursor.execute(q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Sink-read over-approximation: `cursor.execute(s)` when `s.q` is tainted
// should still detect, since the sink may internally read any field of the
// object. Implemented by anyFieldTainted when fromFieldAssign=true.
func TestPython_FieldSensitive_SinkOnBareObj_FindsAttrTaint(t *testing.T) {
	code := `
from flask import request

def handler():
    s.q = request.args.get('q')
    cursor.execute(s)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for cursor.execute(s) when s.q is tainted")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Rebinding the bare object invalidates all per-field taints: after
// `s = "safe"`, the prior `s.q` taint is gone.
func TestPython_FieldSensitive_RebindObjClearsFields(t *testing.T) {
	code := `
from flask import request

def handler():
    s.q = request.args.get('q')
    s = "safe"
    cursor.execute(s.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did not expect SQL flow after rebinding s; got %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// Rebinding the attribute to a safe literal clears the per-field taint.
func TestPython_FieldSensitive_RebindAttrToSafeLiteral_ClearsField(t *testing.T) {
	code := `
from flask import request

def handler():
    s.q = request.args.get('q')
    s.q = "safe"
    cursor.execute(s.q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did not expect SQL flow after rebinding s.q to literal; got %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// Field-sensitivity is shallow: `obj.a.b` truncates to `obj.a`. Tainting
// `obj.a` (via a deeper LHS in the user's mental model) reads as tainted
// at `obj.a` regardless of nested attribute reads.
func TestPython_FieldSensitive_DeepAttrTruncatesToFirstLevel(t *testing.T) {
	code := `
from flask import request

def handler():
    obj.a = request.args.get('q')
    cursor.execute(obj.a.upper())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for obj.a tainted -> obj.a.upper() -> execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// JS gets shallow field-sensitivity for free since tsflow's mechanism is
// language-agnostic: `obj.attr = source()` stores under "obj.attr", and
// `sink(obj.attr)` reads it back. Verifies that the JS extractAssignLHS
// update is in effect and doesn't disturb non-Python languages.
func TestJS_FieldSensitive_AttrAssignToAttrRead(t *testing.T) {
	code := `
function handler(req, res) {
    const s = {};
    s.q = req.query.q;
    db.query(s.q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected JS SQL flow for s.q = req.query.q -> db.query(s.q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
