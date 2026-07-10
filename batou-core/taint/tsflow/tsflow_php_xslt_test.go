package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP XSLT injection tests — XSLTProcessor (CWE-91)
// =========================================================================
//
// Threat model: an attacker-controlled XSL stylesheet passed to
// XSLTProcessor::importStyleSheet grants file read (document()),
// SSRF (xsl:include/xsl:import), DoS, and — when registerPHPFunctions()
// is called — RCE via php:function(). See CVE-2018-5712.

// Tainted stylesheet flows into XSLTProcessor::importStyleSheet.
func TestPHP_XSLT_ImportStyleSheet_Tainted(t *testing.T) {
	code := `<?php
function handler() {
    $xsl = $_POST["xsl"];
    $xslt = new XSLTProcessor();
    $xslt->importStyleSheet($xsl);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT-injection flow for $_POST -> XSLTProcessor->importStyleSheet")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Case-variant method spelling: PHP normalizes method names and both
// camelCase spellings appear in the wild.
func TestPHP_XSLT_ImportStylesheet_LowercaseSheet_Tainted(t *testing.T) {
	code := `<?php
function handler() {
    $xsl = $_GET["xsl"];
    $xslt = new XSLTProcessor();
    $xslt->importStylesheet($xsl);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT-injection flow for $_GET -> XSLTProcessor->importStylesheet")
	}
}

// transformToXml with tainted input document argument.
func TestPHP_XSLT_TransformToXml_TaintedDoc(t *testing.T) {
	code := `<?php
function handler() {
    $doc = $_POST["xml"];
    $xslt = new XSLTProcessor();
    $xslt->transformToXml($doc);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT flow for $_POST -> XSLTProcessor->transformToXml")
	}
}

// transformToUri with tainted output URI — an arbitrary-write primitive
// via whatever file:// or network scheme the attacker picks.
func TestPHP_XSLT_TransformToUri_TaintedTarget(t *testing.T) {
	code := `<?php
function handler() {
    $target = $_GET["out"];
    $doc = new DOMDocument();
    $xslt = new XSLTProcessor();
    $xslt->transformToUri($doc, $target);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT flow for $_GET -> XSLTProcessor->transformToUri(target)")
	}
}

// Negative case: hardcoded stylesheet literal must not fire the sink.
func TestPHP_XSLT_ImportStyleSheet_Hardcoded_Safe(t *testing.T) {
	code := `<?php
function handler() {
    $xsl = "/etc/app/trusted.xsl";
    $xslt = new XSLTProcessor();
    $xslt->importStyleSheet($xsl);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("hardcoded stylesheet path must not fire XSLT injection sink")
	}
}

// Negative case: an unrelated class with an importStyleSheet method must not
// match our sink — receiver type matters.
func TestPHP_XSLT_ImportStyleSheet_NonXSLTProcessor(t *testing.T) {
	code := `<?php
function handler() {
    $xsl = $_POST["xsl"];
    $theme = new ThemeBuilder();
    $theme->importStyleSheet($xsl);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("importStyleSheet() on a non-XSLTProcessor receiver must not fire XSLT sink")
	}
}
