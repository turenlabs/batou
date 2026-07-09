package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// PHP dynamic-callable (CWE-95) sinks: array_map / array_filter / usort /
// array_walk / preg_replace_callback / register_shutdown_function fire ONLY
// when the callback-name argument is a tainted STRING, and never when it is a
// closure / arrow-function literal (the dominant safe idiom).

func TestPHP_ArrayMap_TaintedStringCallback_Fires(t *testing.T) {
	code := `<?php
function handler() {
    $fn = $_GET["fn"];
    array_map($fn, $items);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-95") {
		t.Error("expected CWE-95 flow for $_GET -> array_map callback-name position")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_Usort_TaintedInlineCallback_Fires(t *testing.T) {
	code := `<?php
function handler() {
    usort($items, $_GET["cmp"]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-95") {
		t.Error("expected CWE-95 flow for usort() with tainted comparator string")
	}
}

func TestPHP_RegisterShutdownFunction_TaintedCallback_Fires(t *testing.T) {
	code := `<?php
function handler() {
    $cb = $_REQUEST["sh"];
    register_shutdown_function($cb);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-95") {
		t.Error("expected CWE-95 flow for register_shutdown_function with tainted callback")
	}
}

// Near-miss: a closure / arrow-function literal in the callback slot that
// captures a tainted value via `use` is NOT an arbitrary-function-call and must
// not fire (the FP class fixed by narrowPHPDynamicCallbackArg).

func TestPHP_ArrayMap_ClosureCapturingTainted_NoFire(t *testing.T) {
	code := `<?php
function handler($details, $items) {
    $details = $_GET["d"];
    return array_map(function ($x) use ($details) { return $x . $details; }, $items);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-95") {
		t.Error("closure callback capturing a tainted var must NOT fire CWE-95 (false positive)")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPHP_ArrayFilter_ArrowFnCapturingTainted_NoFire(t *testing.T) {
	code := `<?php
function handler($items) {
    $needle = $_GET["n"];
    return array_filter($items, fn($x) => $x === $needle);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-95") {
		t.Error("arrow-fn callback capturing a tainted var must NOT fire CWE-95 (false positive)")
	}
}

// Near-miss: a literal string callback is not tainted and must not fire.
func TestPHP_ArrayMap_LiteralCallback_NoFire(t *testing.T) {
	code := `<?php
function handler() {
    $items = $_GET["items"];
    return array_map('intval', $items);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	// The tainted DATA array is arg 1, which is NOT a dangerous arg for this
	// sink (only arg 0, the callback, is). A literal callback carries no taint,
	// so no CWE-95 code_eval flow should be produced.
	for _, f := range flows {
		if f.Sink.CWEID == "CWE-95" && f.Sink.Category == taint.SnkEval {
			t.Errorf("literal callback 'intval' must NOT fire CWE-95: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
