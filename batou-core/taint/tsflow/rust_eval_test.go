package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// --- rhai: eval_expression (CWE-94) ---

func TestRust_Rhai_EvalExpression(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let input = env::var("USER_SCRIPT").unwrap();
    let engine = Engine::new();
    let result = engine.eval_expression(&input);
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai eval_expression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rhai: eval_with_scope (CWE-94) ---

func TestRust_Rhai_EvalWithScope(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let input = env::var("USER_SCRIPT").unwrap();
    let engine = Engine::new();
    let mut scope = Scope::new();
    let result = engine.eval_with_scope(&mut scope, &input);
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai eval_with_scope")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rhai: eval_file (CWE-94) ---

func TestRust_Rhai_EvalFile(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let path = env::var("SCRIPT_PATH").unwrap();
    let engine = Engine::new();
    let result = engine.eval_file(PathBuf::from(&path));
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai eval_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rhai: run_file (CWE-94) ---

func TestRust_Rhai_RunFile(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let path = env::var("SCRIPT_PATH").unwrap();
    let engine = Engine::new();
    engine.run_file(PathBuf::from(&path));
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai run_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rhai: compile_expression (CWE-94) ---

func TestRust_Rhai_CompileExpression(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let input = env::var("USER_SCRIPT").unwrap();
    let engine = Engine::new();
    let ast = engine.compile_expression(&input);
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai compile_expression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rhai: compile_file (CWE-94) ---

func TestRust_Rhai_CompileFile(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let path = env::var("SCRIPT_PATH").unwrap();
    let engine = Engine::new();
    let ast = engine.compile_file(PathBuf::from(&path));
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> rhai compile_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pyo3: py.eval (CWE-94) ---

func TestRust_Pyo3_Eval(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let code = env::var("PY_CODE").unwrap();
    let py = Python::new();
    py.eval(&code, None, None);
}
`
	flows := Analyze(code, "/app/pybridge.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> pyo3 py.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pyo3: py.run (CWE-94) ---

func TestRust_Pyo3_Run(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let script = env::var("PY_SCRIPT").unwrap();
    let py = Python::new();
    py.run(&script, None, None);
}
`
	flows := Analyze(code, "/app/pybridge.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> pyo3 py.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pyo3: PyModule::from_code (CWE-94) ---

func TestRust_Pyo3_FromCode(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let src = env::var("PY_SOURCE").unwrap();
    PyModule::from_code(py, &src, "dynamic.py", "dynamic");
}
`
	flows := Analyze(code, "/app/pybridge.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> pyo3 PyModule::from_code")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- deno_core: execute_script (CWE-94) ---

func TestRust_Deno_ExecuteScript(t *testing.T) {
	code := `
use std::env;

fn handle() {
    let script = env::var("JS_CODE").unwrap();
    let mut runtime = JsRuntime::new(Default::default());
    runtime.execute_script("user_script", &script);
}
`
	flows := Analyze(code, "/app/jsrunner.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for env::var -> deno execute_script")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe: hardcoded rhai script (should NOT flag) ---

func TestRust_Rhai_Safe_Hardcoded(t *testing.T) {
	code := `
fn handle() {
    let engine = Engine::new();
    let result = engine.eval_expression("2 + 3");
}
`
	flows := Analyze(code, "/app/scripting.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("hardcoded rhai script should not produce eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe: hardcoded pyo3 eval (should NOT flag) ---

func TestRust_Pyo3_Safe_Hardcoded(t *testing.T) {
	code := `
fn handle() {
    let py = Python::new();
    py.eval("1 + 1", None, None);
}
`
	flows := Analyze(code, "/app/pybridge.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("hardcoded pyo3 eval should not produce eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
