package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Redirect sanitizers (CWE-601) ---

func TestPython_Redirect_Unsanitized(t *testing.T) {
	code := `
from flask import request, redirect

def handler():
    next_url = request.args.get("next")
    return redirect(next_url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow when user input goes directly to redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Redirect_Sanitized_UrlHasAllowedHost(t *testing.T) {
	code := `
from django.utils.http import url_has_allowed_host_and_scheme
from flask import request, redirect

def handler():
    next_url = request.args.get("next")
    safe = url_has_allowed_host_and_scheme(next_url, allowed_hosts={"example.com"})
    return redirect(safe)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected NO redirect flow when url_has_allowed_host_and_scheme sanitizes the data flow")
		}
	}
}

func TestPython_Redirect_Sanitized_IsSafeUrl(t *testing.T) {
	code := `
from django.utils.http import is_safe_url
from flask import request, redirect

def handler():
    next_url = request.args.get("next")
    safe = is_safe_url(next_url, allowed_hosts={"example.com"})
    return redirect(safe)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected NO redirect flow when is_safe_url sanitizes the data flow")
		}
	}
}

// --- Eval sanitizers (CWE-94) ---

func TestPython_Eval_Unsanitized(t *testing.T) {
	code := `
from flask import request

def handler():
    expr = request.args.get("expr")
    result = eval(expr)
    return str(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow when user input goes directly to eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Eval_Sanitized_SimpleEval(t *testing.T) {
	code := `
from flask import request
from simpleeval import simple_eval

def handler():
    expr = request.args.get("expr")
    result = simple_eval(expr)
    return str(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow when simpleeval.simple_eval is used")
		}
	}
}

func TestPython_Eval_Sanitized_Numexpr(t *testing.T) {
	code := `
from flask import request
import numexpr

def handler():
    expr = request.args.get("expr")
    result = numexpr.evaluate(expr)
    return str(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow when numexpr.evaluate is used (numeric-only evaluator)")
		}
	}
}

// --- Deserialization sanitizers (CWE-502) ---

func TestPython_Deser_Unsanitized_Pickle(t *testing.T) {
	code := `
from flask import request
import pickle

def handler():
    data = request.args.get("payload")
    obj = pickle.loads(data)
    return str(obj)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow when user input goes to pickle.loads()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Note: Deserialization sanitizer tests (json.loads, tomllib.loads, django.core.signing.loads)
// cannot be verified via tsflow because ALL Python deser sinks have ObjectType="" — causing
// the sanitizer call itself to match as a deser sink on the INPUT argument. The sanitizer
// correctly marks the OUTPUT as clean, but processCall fires on the same call node as a sink.
// These catalog entries still work correctly with the regex taint engine (taint.Analyze).

// --- XPath injection sanitizers (CWE-643) ---

func TestPython_XPath_Unsanitized(t *testing.T) {
	code := `
from flask import request
from lxml import etree

def handler():
    username = request.args.get("user")
    tree = etree.parse("users.xml")
    result = tree.xpath("//user[@name='" + username + "']")
    return str(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow when user input goes directly to xpath()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Note: The saxutils.escape sanitizer (py.xpath.saxutils.escape) cannot be verified via
// tsflow due to a first-match issue: py.html.escape (ObjectType="") intercepts all escape()
// calls. The existing py.xpath.quoteattr and py.xpath.lxml.xpath.variables sanitizers
// already provide tsflow-verified XPath sanitizer coverage.
