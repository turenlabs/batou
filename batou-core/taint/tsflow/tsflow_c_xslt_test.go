package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C — libxslt XSLT injection tests (CWE-91)
//
// Untrusted XSLT stylesheets can read arbitrary files via document(),
// invoke shell commands via EXSLT extensions (str:tokenize, exsl:document),
// and exfiltrate data through xsl:include — equivalent to code execution.
// See CVE-2012-0876 (libxslt) and CVE-2019-13117 for real-world impact.
// =========================================================================

func TestC_Libxslt_ParseStylesheetFile_Tainted(t *testing.T) {
	code := `
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <stdlib.h>

void load_user_xslt(void) {
    char *uri = getenv("STYLESHEET_URI");
    xsltStylesheetPtr style = xsltParseStylesheetFile((const xmlChar *)uri);
    (void)style;
}
`
	flows := Analyze(code, "/app/xslt_load.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT injection flow for getenv -> xsltParseStylesheetFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxslt_ParseStylesheetDoc_Tainted(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <stdlib.h>

void parse_user_doc(void) {
    char *xml_src = getenv("XSLT_BODY");
    xmlDocPtr doc = xmlParseMemory(xml_src, 4096);
    xsltStylesheetPtr style = xsltParseStylesheetDoc(doc);
    (void)style;
}
`
	flows := Analyze(code, "/app/xslt_doc.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT injection flow for getenv -> xsltParseStylesheetDoc")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxslt_LoadStylesheetPI_Tainted(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <stdlib.h>

void load_pi(void) {
    char *xml_src = getenv("INPUT_XML");
    xmlDocPtr doc = xmlParseMemory(xml_src, 4096);
    xsltStylesheetPtr style = xsltLoadStylesheetPI(doc);
    (void)style;
}
`
	flows := Analyze(code, "/app/xslt_pi.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT injection flow for getenv -> xsltLoadStylesheetPI")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxslt_ApplyStylesheet_TaintedDoc(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <libxslt/transform.h>
#include <stdlib.h>

void transform_user_input(xsltStylesheetPtr style) {
    char *xml_src = getenv("INPUT_XML");
    xmlDocPtr input = xmlParseMemory(xml_src, 4096);
    xmlDocPtr result = xsltApplyStylesheet(style, input, NULL);
    (void)result;
}
`
	flows := Analyze(code, "/app/xslt_apply.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT injection flow for getenv -> xsltApplyStylesheet (input doc)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Libxslt_ApplyStylesheet_Hardcoded_Safe(t *testing.T) {
	code := `
#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <libxslt/transform.h>

void transform_static(xsltStylesheetPtr style) {
    xmlDocPtr input = xmlParseFile("/etc/known/data.xml");
    xmlDocPtr result = xsltApplyStylesheet(style, input, NULL);
    (void)result;
}
`
	flows := Analyze(code, "/app/xslt_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath && f.Source.Category != taint.SrcEnvVar {
			continue
		}
		if f.Sink.Category == taint.SnkXPath {
			t.Errorf("expected NO XSLT injection flow when input is hardcoded; got: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
