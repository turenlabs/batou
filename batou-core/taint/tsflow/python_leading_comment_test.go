package tsflow

// Permanent regression tests for the tree-sitter-python "leading-comment suite"
// parser quirk (fixed by pyResolveSuite in langconfig.go).
//
// When a Python suite's first physical line is a comment, tree-sitter assigns
// the body-like FIELD ("body" on a function_definition, "consequence" on an
// if_statement) to the leading `comment` node and emits the real `block` suite
// as a SEPARATE same-field sibling. A plain ChildByFieldName therefore returned
// the childless comment node, and the ENTIRE suite's dataflow was silently
// dropped — a severe, Python-only Layer-3 recall loss:
//
//	def run():
//	    # leading comment          <- body field landed here (childless)
//	    name = request.args.get("x")
//	    cursor.execute("... " + name)   <- never walked  -> 0 flows (FN)
//
// The identical body WITHOUT the leading comment fired BATOU-TAINT-sql_query at
// confidence ~1.0. These tests pin the FN fix (0 -> 1 flow) for the function
// body, the if-consequence body, and the for body, AND pin the FP discipline
// that the recovered block is analyzed with full fidelity (a sanitized source
// in a leading-comment body still produces NO finding).

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- Positive: function body whose first line is a comment (PRIMARY fix) ---

func TestLeadingComment_FunctionBody_Fires(t *testing.T) {
	code := `
from flask import request

def run():
    # leading comment
    name = request.args.get("x")
    cursor.execute("SELECT * FROM t WHERE a=" + name)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for leading-comment function body (request.args.get -> execute)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Positive: method body whose first line is a comment (same root cause;
// also exercises the cross-method stored-state harvest via extractFuncBody) ---

func TestLeadingComment_MethodBody_Fires(t *testing.T) {
	code := `
from flask import request

class H:
    def run(self):
        # leading comment
        name = request.args.get("x")
        cursor.execute("SELECT * FROM t WHERE a=" + name)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for leading-comment method body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Positive: if-consequence body whose first line is a comment (EXTENSION) ---

func TestLeadingComment_IfBody_Fires(t *testing.T) {
	code := `
from flask import request

def run(flag):
    if flag:
        # leading comment
        name = request.args.get("x")
        cursor.execute("SELECT * FROM t WHERE a=" + name)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for leading-comment if-body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Positive: for body whose first line is a comment. The for-loop handler
// already walks all named children (so this survived pre-fix), but pin it so a
// future refactor toward field-based body access stays covered. ---

func TestLeadingComment_ForBody_Fires(t *testing.T) {
	code := `
from flask import request

def run(items):
    for i in items:
        # leading comment
        name = request.args.get("x")
        cursor.execute("SELECT * FROM t WHERE a=" + name)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for leading-comment for-body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- FP discipline: a SAFE leading-comment body must stay clean. The recovered
// block is analyzed with full fidelity, so a sanitized source produces NO
// finding (this is NOT a blunt "any source in a comment-body -> flag"). ---

func TestLeadingComment_SafeBody_Clean(t *testing.T) {
	code := `
from flask import request
import html

def run():
    # leading comment
    name = request.args.get("x")
    safe = html.escape(name)
    render(safe)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO XSS flow when html.escape sanitizes the leading-comment body; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
