package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C embedded-interpreter code-injection sink tests (CWE-94).
//
// C programs that link an embedded scripting engine and forward a
// user-controlled string to the engine's "evaluate this source" entry point
// get arbitrary code execution. The CPython C-API high-level eval/compile
// functions (PyRun_SimpleString, PyRun_String, Py_CompileString, ...) and
// GNU Guile's scm_c_eval_string take the code string as the FIRST argument,
// so they fit the C tsflow arg[0] sink model. All fixtures use an
// environment-variable source (getenv) — a clean, function-call C source.
// =========================================================================

func TestC_Getenv_ToPyRunSimpleString(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyRun_SimpleString(script);
}
`
	flows := Analyze(code, "/app/pyrun_simple.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> PyRun_SimpleString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPyRunSimpleStringFlags(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyRun_SimpleStringFlags(script, NULL);
}
`
	flows := Analyze(code, "/app/pyrun_simpleflags.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> PyRun_SimpleStringFlags")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPyRunString(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyObject *g = NULL, *l = NULL;
    PyRun_String(script, Py_file_input, g, l);
}
`
	flows := Analyze(code, "/app/pyrun_string.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> PyRun_String")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPyRunStringFlags(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyObject *g = NULL, *l = NULL;
    PyRun_StringFlags(script, Py_file_input, g, l, NULL);
}
`
	flows := Analyze(code, "/app/pyrun_stringflags.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> PyRun_StringFlags")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPyCompileString(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyObject *co = Py_CompileString(script, "<user>", Py_file_input);
    (void)co;
}
`
	flows := Analyze(code, "/app/pycompile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> Py_CompileString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPyCompileStringFlags(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyObject *co = Py_CompileStringFlags(script, "<user>", Py_file_input, NULL);
    (void)co;
}
`
	flows := Analyze(code, "/app/pycompileflags.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> Py_CompileStringFlags")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPyCompileStringObject(t *testing.T) {
	code := `
#include <stdlib.h>
#include <Python.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    PyObject *fn = NULL;
    PyObject *co = Py_CompileStringObject(script, fn, Py_file_input, NULL, -1);
    (void)co;
}
`
	flows := Analyze(code, "/app/pycompileobject.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> Py_CompileStringObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToGuileEvalString(t *testing.T) {
	code := `
#include <stdlib.h>
#include <libguile.h>

void run_input(void) {
    char *script = getenv("USER_INPUT");
    SCM result = scm_c_eval_string(script);
    (void)result;
}
`
	flows := Analyze(code, "/app/guile_eval.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow for getenv -> scm_c_eval_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a hardcoded constant script (no user input) must NOT
// produce a code-eval flow.
func TestC_ConstantScript_NoFlow(t *testing.T) {
	code := `
#include <Python.h>

void run_fixed(void) {
    PyRun_SimpleString("print('hello')");
}
`
	flows := Analyze(code, "/app/pyrun_const.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("did not expect a code-eval flow for a constant script string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
