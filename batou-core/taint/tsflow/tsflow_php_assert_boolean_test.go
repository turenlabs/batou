package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// PHP assert() argument-shape gate (CWE-94). PHP's assert() only evaluates code
// when its first argument is a STRING (the legacy form removed in PHP 8.0).
// Modern PHP uses assert() as a pure runtime type/state assertion whose argument
// is a BOOLEAN expression (is_string(...), $x !== null, $x instanceof Foo, …).
// Those must NOT produce a CWE-94 code_eval flow, while the genuine string /
// tainted-variable RCE form must still fire.
//
// Real-repo FP cluster: cakephp src/Http/Cookie/Cookie.php, src/Database/Schema/*,
// src/Http/Client.php, … 21 boolean-assert findings, all safe.

func TestPHP_Assert_BooleanForms_NoEval(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"is_string", `assert(is_string($value));`},
		{"is_array", `assert(is_array($value), '$value is not an array');`},
		{"not_null", `assert($column !== null);`},
		{"not_true", `assert($body !== true);`},
		{"instanceof", `assert($response instanceof Response);`},
		{"logical_or_instanceof", `assert($conditions === null || $conditions instanceof ExpressionInterface);`},
		{"negation", `assert(!$disabled);`},
		{"comparison_with_call", `assert(strlen($value) > 0);`},
		{"isset", `assert(isset($value));`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// $value is tainted from user input so a flow WOULD exist if the
			// sink fired; the boolean argument shape is what suppresses it.
			code := "<?php\nfunction handler() {\n    $value = $_GET[\"v\"];\n    " + c.expr + "\n}\n?>"
			flows := Analyze(code, "/app/handler.php", rules.LangPHP)
			if hasTaintFlowCWE(flows, "CWE-94") {
				t.Errorf("boolean assert(%s) must NOT fire CWE-94 code_eval (false positive)", c.expr)
				for _, f := range flows {
					t.Logf("  unexpected flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
				}
			}
		})
	}
}

// Positive: the genuine string-eval / tainted-variable RCE form still fires.
func TestPHP_Assert_StringEvalForm_Fires(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		// Bare tainted variable: assert($code) evaluates $code as PHP if it is a
		// string (the classic CVE form).
		{"tainted_variable", `assert($code);`},
		// String concatenation containing tainted input.
		{"tainted_concat", `assert("return " . $code . ";");`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code := "<?php\nfunction handler() {\n    $code = $_GET[\"code\"];\n    " + c.expr + "\n}\n?>"
			flows := Analyze(code, "/app/handler.php", rules.LangPHP)
			if !hasTaintFlowCWE(flows, "CWE-94") {
				t.Errorf("string/variable assert(%s) MUST still fire CWE-94 code_eval (over-suppression)", c.expr)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
				}
			}
		})
	}
}
