package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog verification ---

func TestJS_XPath_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJavaScript)
	if cat == nil {
		t.Fatal("JavaScript catalog not loaded")
	}
	sinks := cat.Sinks()
	found := map[string]bool{}
	for _, s := range sinks {
		if s.Category == taint.SnkXPath {
			found[s.ID] = true
		}
	}
	want := []string{
		"js.dom.document.evaluate",
		"js.fontoxpath.evaluatexpath",
		"js.fontoxpath.evaluatexpathtonodes",
		"js.fontoxpath.evaluatexpathtostring",
		"js.fontoxpath.evaluatexpathtofirstnode",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SnkXPath sink: %s", id)
		}
	}
}

// --- DOM-native document.evaluate (CWE-643) ---

func TestJS_DOM_DocumentEvaluate_XPath_Injection(t *testing.T) {
	code := `
function handler(req, res) {
    var username = req.query.username;
    var result = document.evaluate("//user[name='" + username + "']", doc, null, XPathResult.ANY_TYPE, null);
    res.send(result.stringValue);
}
`
	flows := Analyze(code, "/app/routes/search.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow from req.query -> document.evaluate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- fontoxpath evaluateXPath family (CWE-643) ---

func TestJS_FontoXPath_EvaluateXPath_Injection(t *testing.T) {
	code := `
const { evaluateXPath } = require("fontoxpath");
function handler(req, res) {
    const q = req.query.q;
    const result = evaluateXPath("//item[@name='" + q + "']", doc);
    res.send(result);
}
`
	flows := Analyze(code, "/app/routes/lookup.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow from req.query -> fontoxpath evaluateXPath()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_FontoXPath_EvaluateXPathToNodes_Injection(t *testing.T) {
	code := `
const { evaluateXPathToNodes } = require("fontoxpath");
function handler(req, res) {
    const name = req.body.name;
    const nodes = evaluateXPathToNodes("//user[@name='" + name + "']", doc);
    res.json(nodes);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow from req.body -> evaluateXPathToNodes()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_FontoXPath_EvaluateXPathToString_Injection(t *testing.T) {
	code := `
const { evaluateXPathToString } = require("fontoxpath");
function handler(req, res) {
    const role = req.params.role;
    const s = evaluateXPathToString("//user[@role='" + role + "']/name", doc);
    res.send(s);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow from req.params -> evaluateXPathToString()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_FontoXPath_EvaluateXPathToFirstNode_Injection(t *testing.T) {
	code := `
const { evaluateXPathToFirstNode } = require("fontoxpath");
function handler(req, res) {
    const id = req.query.id;
    const node = evaluateXPathToFirstNode("//item[@id='" + id + "']", doc);
    res.send(node.textContent);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow from req.query -> evaluateXPathToFirstNode()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
