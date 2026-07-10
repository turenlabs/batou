// Regression tests for the Flask make_response((body, headers)) body/header
// split in the Python html_output sink (see narrowPythonMakeResponseBody in
// walker.go).
//
// Motivating OWASP-Benchmark FPs (all xss, all `false`):
//
//	BenchmarkTest00150/00257/00334/00591/01082/01083/01084/01213 (+others)
//	  RESPONSE = make_response((RESPONSE, {'hdr': bar}))
//
// where RESPONSE (the body, first tuple element) is a CONSTANT string and the
// tainted `bar` lives only in the headers dict (second tuple element). Writing
// a tainted value into a response header is not reflected XSS, so html_output
// must not fire. A tainted BODY (first tuple element) must still fire.
package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// FP shape: tainted var only in the headers dict, constant body. Must NOT fire.
func TestPython_MakeResponse_TaintInHeaderOnly_NoXSS(t *testing.T) {
	code := `
from flask import request, make_response

def handler():
    RESPONSE = ""
    param = request.form.get("x")
    bar = param.split(' ')[0]
    RESPONSE += 'The value of the bar parameter is now in a custom header.'
    RESPONSE = make_response((RESPONSE, {'yourHeader': bar}))
    return RESPONSE
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("tainted value only in make_response headers dict should NOT be reported as XSS (html_output)")
	}
}

// TP shape: tainted var IS the body (first tuple element). MUST still fire.
func TestPython_MakeResponse_TaintInBody_StillXSS(t *testing.T) {
	code := `
from flask import request, make_response

def handler():
    param = request.form.get("x")
    bar = param
    body = "hello " + bar
    RESPONSE = make_response((body, {'yourHeader': 'constant'}))
    return RESPONSE
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("tainted response body in make_response tuple should still be reported as XSS (html_output)")
	}
}

// TP shape: plain (non-tuple) make_response(tainted) must still fire — the
// narrowing is a no-op when arg 0 is not a tuple.
func TestPython_MakeResponse_PlainTaintedBody_StillXSS(t *testing.T) {
	code := `
from flask import request, make_response

def handler():
    param = request.form.get("x")
    body = "hello " + param
    return make_response(body)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("plain make_response(tainted body) should still be reported as XSS (html_output)")
	}
}
