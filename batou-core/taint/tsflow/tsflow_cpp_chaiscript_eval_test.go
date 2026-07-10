package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ embedded-scripting code-injection sinks (ChaiScript / JerryScript)
// =========================================================================
// These engines evaluate a string (or a file path) of script source. When
// the source/path is user-controlled, the attacker can execute arbitrary
// script — and, for ChaiScript, call any C++ function bound into the engine
// (CWE-94). pybind11 / V8 / Lua C-API / Python C-API were already covered;
// ChaiScript and JerryScript were the remaining gaps.

func TestCPP_ChaiScript_Eval_Injection(t *testing.T) {
	code := `
#include <chaiscript/chaiscript.hpp>
#include <cstdlib>

void run() {
    char *userCode = getenv("SCRIPT");
    chaiscript::ChaiScript chai;
    chai.eval(userCode);
}
`
	flows := Analyze(code, "/app/chai_eval.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> chai.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ChaiScript_EvalFile_Injection(t *testing.T) {
	code := `
#include <chaiscript/chaiscript.hpp>
#include <cstdlib>

void run() {
    char *path = getenv("SCRIPT_PATH");
    chaiscript::ChaiScript chai;
    chai.eval_file(path);
}
`
	flows := Analyze(code, "/app/chai_evalfile.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> chai.eval_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_JerryScript_Eval_Injection(t *testing.T) {
	code := `
#include <jerryscript.h>
#include <cstdlib>
#include <cstring>

void run() {
    char *src = getenv("JS");
    jerry_init(JERRY_INIT_EMPTY);
    jerry_eval(src, strlen(src), 0);
}
`
	flows := Analyze(code, "/app/jerry_eval.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> jerry_eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant script string must NOT produce an eval flow.
func TestCPP_ChaiScript_Eval_Safe(t *testing.T) {
	code := `
#include <chaiscript/chaiscript.hpp>

void run() {
    chaiscript::ChaiScript chai;
    chai.eval("print(42)");
}
`
	flows := Analyze(code, "/app/chai_safe.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("did not expect an eval flow for a constant script string")
	}
}
