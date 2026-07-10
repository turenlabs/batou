package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python XSLT injection tests (lxml.etree.XSLT, lxml.isoschematron) — CWE-91
// =========================================================================
//
// Untrusted XSLT stylesheets enable file read via the document() function,
// outbound network access via xsl:include / xsl:import, and command
// execution through EXSLT extensions (exsl:document, dyn:evaluate).
// CVE-2025-6985 (langchain-text-splitters) is the canonical real-world
// case of Flask-style request data flowing straight into etree.XSLT().

// lxml.etree.XSLT with stylesheet text lifted from a Flask request.
func TestPython_LXML_XSLT_TaintFlow(t *testing.T) {
	code := `
from flask import request
from lxml import etree

def handler():
    xsl_text = request.args.get("stylesheet")
    xsl_doc = etree.fromstring(xsl_text)
    transform = etree.XSLT(xsl_doc)
    return transform(etree.fromstring("<doc/>"))
`
	flows := Analyze(code, "/app/xslt_view.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected SnkXPath flow when Flask request flows into lxml.etree.XSLT()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Fully-qualified lxml.etree.XSLT — exercises the lxml.-prefixed branch.
func TestPython_LXML_XSLT_Qualified_TaintFlow(t *testing.T) {
	code := `
from flask import request
import lxml.etree

def handler():
    body = request.values["stylesheet"]
    doc = lxml.etree.fromstring(body)
    transform = lxml.etree.XSLT(doc)
    return transform(lxml.etree.fromstring("<doc/>"))
`
	flows := Analyze(code, "/app/xslt_qualified.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected SnkXPath flow for lxml.etree.XSLT(tainted_doc)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Schematron uses XSLT internally; passing a tainted schema XML tree is
// XSLT injection by proxy.
func TestPython_LXML_Schematron_TaintFlow(t *testing.T) {
	code := `
from flask import request
from lxml import etree, isoschematron

def handler():
    schema_src = request.form["schema"]
    schema_doc = etree.fromstring(schema_src)
    validator = isoschematron.Schematron(schema_doc)
    return str(validator)
`
	flows := Analyze(code, "/app/schematron_view.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected SnkXPath flow when request form flows into isoschematron.Schematron()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Hardcoded stylesheet literal — no taint source in play, so no flow.
func TestPython_LXML_XSLT_Hardcoded_Safe(t *testing.T) {
	code := `
from lxml import etree

def handler():
    xsl_text = "<xsl:stylesheet version='1.0'/>"
    xsl_doc = etree.fromstring(xsl_text)
    transform = etree.XSLT(xsl_doc)
    return transform(etree.fromstring("<doc/>"))
`
	flows := Analyze(code, "/app/xslt_static.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Errorf("expected NO SnkXPath flow for hardcoded stylesheet, got %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}

// XSLT parameter built via XSLT.strparam is escaped as an XPath string
// literal and must not raise SnkXPath even when the value is tainted.
func TestPython_LXML_XSLT_Strparam_Sanitized(t *testing.T) {
	code := `
from flask import request
from lxml import etree

def handler():
    name = request.args.get("name")
    safe_param = etree.XSLT.strparam(name)
    xsl = etree.XSLT(etree.parse("trusted.xsl"))
    return xsl(etree.fromstring("<doc/>"), user_name=safe_param)
`
	flows := Analyze(code, "/app/xslt_param.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Errorf("expected strparam to neutralize SnkXPath, got %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}
