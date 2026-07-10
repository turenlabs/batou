package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// PHP list-destructuring (`list($a, $b) = ...`, `[$a, $b] = ...`) recall-FN
// regression tests.
//
// Before the processPHPListAssign walker branch, the LHS of a PHP
// list-destructuring assignment is a `list_literal`, for which extractAssignLHS
// returns "" — so every destructured target silently lost its taint and
// downstream sinks produced zero flows. These tests pin the fix and its
// element-wise precision (only the target bound to the tainted element is
// flagged).
//
// Note: PHP's normal assign path does not propagate an inline source-subscript
// through a call arg (`$p = explode("@", $_GET["x"])` does NOT taint $p), but it
// does once the source is bound to a variable. The realistic exploit shape
// therefore binds the source first, which is what these fixtures exercise.

// --- Positive: taint must flow through the destructured target ---

func TestPHP_ListDestructure_WholeRHS_Command(t *testing.T) {
	// list($u, $h) = $parts; where $parts is a tainted array → both targets taint.
	code := `<?php
function handler() {
    $email = $_GET["email"];
    $parts = explode("@", $email);
    list($user, $host) = $parts;
    system($user);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for $user via list() destructuring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_BracketDestructure_WholeRHS_SQL(t *testing.T) {
	// [$a, $b] = $parts short-syntax destructuring; sink reads the second target.
	code := `<?php
function handler($mysqli) {
    $raw = $_POST["filter"];
    $parts = explode(":", $raw);
    [$col, $val] = $parts;
    $mysqli->query($val);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for $val via [] destructuring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_ListDestructure_DirectCallVarArg_Command(t *testing.T) {
	// list($u, $h) = explode("@", $email); — non-sanitizer call RHS with a
	// tainted variable argument must distribute taint to both targets.
	code := `<?php
function handler() {
    $email = $_GET["email"];
    list($user, $host) = explode("@", $email);
    system($host);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for $host via direct explode() destructuring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_ListDestructure_ArrayLiteral_ElementWise_Command(t *testing.T) {
	// list($a, $b) = [$tainted, "safe"]; element-wise binds taint to $a only.
	code := `<?php
function handler() {
    $cmd = $_GET["cmd"];
    list($a, $b) = [$cmd, "constant"];
    system($a);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for $a via element-wise destructuring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_ListDestructure_Nested_Command(t *testing.T) {
	// list($a, list($b, $c)) = $parts; nested target collected and tainted.
	code := `<?php
function handler() {
    $raw = $_GET["data"];
    $parts = json_decode($raw, true);
    list($a, list($b, $c)) = $parts;
    system($c);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for nested target $c")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: precision must NOT over-taint safe targets ---

func TestPHP_ListDestructure_ElementWise_SafeTarget_NoFlow(t *testing.T) {
	// list($a, $b) = [$tainted, "safe"]; sink reads ONLY the safe target $b.
	code := `<?php
function handler() {
    $cmd = $_GET["cmd"];
    list($a, $b) = [$cmd, "constant"];
    system($b);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a flow — $b is bound to a constant element")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_ListDestructure_AllConstant_NoFlow(t *testing.T) {
	// list($a, $b) = ["one", "two"]; no taint regardless of which target is read.
	code := `<?php
function handler() {
    list($a, $b) = ["one", "two"];
    system($a);
    system($b);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect any flow — both targets are constants")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
