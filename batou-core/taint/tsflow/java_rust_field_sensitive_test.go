package tsflow

// Shallow (first-level) field-sensitive taint tests for Java and Rust.
//
// Regression guard for the langconfig.go extractAssignLHS fix: the Java
// (`field_access`) and Rust (`field_expression`) configs used to return ""
// for a field-write LHS, so `obj.f = src` / `this.data = src` /
// `self.data = src` silently dropped the taint (a missed detection). The
// extractAssignLHS now returns the dotted member text, seeding the per-field
// key — exactly as the JS, C#, and Python configs already do. The engine
// machinery (isFieldKey / fromFieldAssign / anyFieldTainted in taintmap.go,
// prefixTainted reads in propagation.go) is language-agnostic and was already
// proven by JS firing on the identical shape; this was purely a per-language
// config omission.
//
// Each construct is verified two ways: the tainted field flows to a sink
// (FN 0->1) AND a clean sibling field stays clean (no over-taint, FP stays 0).

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Java — field_access LHS
// ---------------------------------------------------------------------------

// Positive: `obj.f = request.getParameter(...)` taints the field, and an
// attribute read at a SQL sink resolves it. Construct #4 (field sensitivity).
func TestJava_FieldSensitive_AttrAssignToAttrRead(t *testing.T) {
	code := `
public class C {
    public void m(HttpServletRequest request) throws Exception {
        obj.f = request.getParameter("q");
        stmt.executeQuery(obj.f);
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for obj.f = request.getParameter -> executeQuery(obj.f)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Positive: `this.data = src` — the write side of construct #14 (instance
// field). The `this.` receiver is a valid field base, keyed "this.data".
func TestJava_FieldSensitive_ThisFieldAssignToRead(t *testing.T) {
	code := `
public class C {
    public void m(HttpServletRequest request) throws Exception {
        this.data = request.getParameter("q");
        stmt.executeQuery(this.data);
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for this.data = request.getParameter -> executeQuery(this.data)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative (no over-taint): tainting `obj.f` must NOT taint a sibling `obj.g`.
// This is the precision half of the fix — returning the full dotted text (not
// the bare receiver) keeps siblings distinct.
func TestJava_FieldSensitive_SiblingField_NoFlow(t *testing.T) {
	code := `
public class C {
    public void m(HttpServletRequest request) throws Exception {
        obj.f = request.getParameter("q");
        stmt.executeQuery(obj.g);
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did not expect SQL flow on sibling obj.g; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// Sink-read over-approximation: `executeQuery(obj)` when `obj.f` is tainted
// still detects, since the sink may internally read any field. Implemented by
// anyFieldTainted (requires fromFieldAssign=true, stamped by processAssign).
func TestJava_FieldSensitive_SinkOnBareObj_FindsFieldTaint(t *testing.T) {
	code := `
public class C {
    public void m(HttpServletRequest request) throws Exception {
        obj.f = request.getParameter("q");
        stmt.executeQuery(obj);
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for executeQuery(obj) when obj.f is tainted")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a hardcoded field value must not flow.
func TestJava_FieldSensitive_HardcodedField_NoFlow(t *testing.T) {
	code := `
public class C {
    public void m() throws Exception {
        obj.f = "hardcoded";
        stmt.executeQuery(obj.f);
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did not expect SQL flow for hardcoded obj.f; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// Regression: the baseline plain-variable taint shape must still be detected —
// guards against the field-access branch disturbing bare-identifier handling.
func TestJava_FieldSensitive_PlainVar_StillDetected(t *testing.T) {
	code := `
public class C {
    public void m(HttpServletRequest request) throws Exception {
        String q = request.getParameter("q");
        stmt.executeQuery(q);
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("baseline regression: expected SQL flow for plain var q")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Rust — field_expression LHS
// ---------------------------------------------------------------------------

// Positive: `obj.f = env::var(...)` taints the field, flowing to a command
// sink through a field read. Construct #4 (field sensitivity).
func TestRust_FieldSensitive_AttrAssignToAttrRead(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn m() {
    let mut s = State::new();
    s.f = env::var("X").unwrap();
    Command::new("sh").arg(s.f);
}
`
	flows := Analyze(code, "/app/m.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected command flow for s.f = env::var -> Command::arg(s.f)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Positive: `self.data = src` — the write side of construct #14 (instance
// field) in Rust. The `self.` receiver is a valid field base ("self.data").
func TestRust_FieldSensitive_SelfFieldAssignToRead(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

impl Handler {
    fn m(&mut self) {
        self.data = env::var("X").unwrap();
        Command::new("sh").arg(self.data);
    }
}
`
	flows := Analyze(code, "/app/m.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected command flow for self.data = env::var -> Command::arg(self.data)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative (no over-taint): tainting `s.f` must NOT taint a sibling `s.g`.
func TestRust_FieldSensitive_SiblingField_NoFlow(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn m() {
    let mut s = State::new();
    s.f = env::var("X").unwrap();
    Command::new("sh").arg(s.g);
}
`
	flows := Analyze(code, "/app/m.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("did not expect command flow on sibling s.g; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// Sink-read over-approximation: `Command::arg(s)` when `s.f` is tainted still
// detects via anyFieldTainted (fromFieldAssign stamped on the field write).
func TestRust_FieldSensitive_SinkOnBareObj_FindsFieldTaint(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn m() {
    let mut s = State::new();
    s.f = env::var("X").unwrap();
    Command::new("sh").arg(s);
}
`
	flows := Analyze(code, "/app/m.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected command flow for Command::arg(s) when s.f is tainted")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Regression: baseline plain-variable taint must still be detected in Rust.
func TestRust_FieldSensitive_PlainVar_StillDetected(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn m() {
    let input = env::var("X").unwrap();
    Command::new("sh").arg(input);
}
`
	flows := Analyze(code, "/app/m.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("baseline regression: expected command flow for plain var input")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
