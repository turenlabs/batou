package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C libxml2 XPath injection tests (CWE-643)
// =========================================================================

func TestC_LibxmlXPathCompile_Injection(t *testing.T) {
	code := `
#include <libxml/xpath.h>
#include <stdlib.h>

void lookup(void) {
    char *expr = getenv("XPATH_EXPR");
    xmlXPathCompExprPtr comp = xmlXPathCompile((const xmlChar *)expr);
}
`
	flows := Analyze(code, "/app/xpath_compile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getenv -> xmlXPathCompile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlXPathCtxtCompile_Injection(t *testing.T) {
	code := `
#include <libxml/xpath.h>
#include <stdlib.h>

void lookup(xmlXPathContextPtr ctxt) {
    char *expr = getenv("XPATH_EXPR");
    xmlXPathCompExprPtr comp = xmlXPathCtxtCompile(ctxt, (const xmlChar *)expr);
}
`
	flows := Analyze(code, "/app/xpath_ctxtcompile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getenv -> xmlXPathCtxtCompile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlXPathNodeEval_Injection(t *testing.T) {
	code := `
#include <libxml/xpath.h>
#include <stdlib.h>

void lookup(xmlNodePtr node, xmlXPathContextPtr ctx) {
    char *expr = getenv("XPATH_EXPR");
    xmlXPathObjectPtr obj = xmlXPathNodeEval(node, (const xmlChar *)expr, ctx);
}
`
	flows := Analyze(code, "/app/xpath_nodeeval.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getenv -> xmlXPathNodeEval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test — a hardcoded expression should not trigger a finding.
func TestC_LibxmlXPathCompile_HardcodedSafe(t *testing.T) {
	code := `
#include <libxml/xpath.h>

void lookup(void) {
    xmlXPathCompExprPtr comp = xmlXPathCompile((const xmlChar *)"/book/author");
}
`
	flows := Analyze(code, "/app/xpath_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("did not expect XPath flow for hardcoded expression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
