package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Augmented-assignment (`q += &tainted`) taint propagation for Rust.
//
// `+=` is the dominant string-building idiom in Rust: `String` implements
// `AddAssign<&str>`, so SQL/shell/URL strings are commonly assembled with
// `let mut q = String::from("..."); q += &user_input;`. tree-sitter-rust
// parses this as a `compound_assignment_expr`, a distinct node from
// `assignment_expression`. Before the langconfig fix that node type was absent
// from the Rust config's assignTypes set, so a clean variable accumulating a
// tainted operand via `+=` was a silent false negative — even though the
// desugared `q = q + &tainted` form was already detected. Mirrors the JS/PHP
// configs, which list the augmented-assignment node type.

// FN that the fix closes: untainted base accumulates a tainted operand via +=,
// reaching a SQL sink.
func TestRust_AugmentedAssign_TaintedRHS_SQLi(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let name = env::var("NAME").unwrap();
    let mut q = String::from("SELECT * FROM users WHERE name = '");
    q += &name;
    sqlx::query(&q);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for env::var -> q += &name -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Command-injection variant of the same += accumulation.
func TestRust_AugmentedAssign_TaintedRHS_CmdInjection(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn handler() {
    let name = env::var("NAME").unwrap();
    let mut cmd = String::from("echo ");
    cmd += &name;
    Command::new(cmd).spawn().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for env::var -> cmd += &name -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Chained `+=` accumulation: a tainted operand added in the middle of several
// constant `+=` steps must still reach the sink. Exercises repeated processing
// of the compound_assignment_expr node with untainted literals interspersed.
func TestRust_AugmentedAssign_ChainedAccumulation(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let name = env::var("NAME").unwrap();
    let mut q = String::from("SELECT * FROM users WHERE name = ");
    q += "'";
    q += &name;
    q += "'";
    sqlx::query(&q);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through chained q += '\\'' / q += &name / q += '\\''")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Regression guard: a base that is ALREADY tainted, then `+=` of an untainted
// literal, must keep its accumulated taint. `+=` reads the prior value, so the
// untainted RHS must not clear it. (This case passed before the fix only
// because the node was ignored entirely; it must keep passing now that the
// node is processed as an assignment.)
func TestRust_AugmentedAssign_TaintedBase_KeepsTaint(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let mut q = env::var("NAME").unwrap();
    q += " ORDER BY id";
    sqlx::query(&q);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected accumulated taint to survive `q += <literal>` after q = env::var(...)")
	}
}

// Negative control: an entirely constant += chain must NOT produce a flow.
func TestRust_AugmentedAssign_AllConstant_NoFlow(t *testing.T) {
	code := `
fn handler() {
    let mut q = String::from("SELECT ");
    q += " FROM users";
    sqlx::query(&q);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant += chain must not produce a SQL injection flow (false positive)")
	}
}
