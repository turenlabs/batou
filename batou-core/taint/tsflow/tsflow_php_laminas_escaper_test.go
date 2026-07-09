package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP laminas-escaper sanitizer tests
//
// Laminas\Escaper\Escaper is the OWASP-recommended PHP context-aware output
// encoder (formerly Zend\Escaper). Each of its five methods escapes a string
// for a specific output context and should neutralize the XSS (SnkHTMLOutput /
// SnkTemplate) taint flow when its result is what reaches the sink.
//
// Each positive test takes a tainted $_GET source, runs it through one Escaper
// method, then prints the result — the SnkHTMLOutput flow must NOT be present.
// The negative control prints the raw source so the harness proves the sink
// itself is detected without the sanitizer.
// =========================================================================

func TestPHP_LaminasEscaper_Sanitized_EscapeHtml(t *testing.T) {
	code := `<?php
function render() {
    $escaper = new Laminas\Escaper\Escaper('utf-8');
    $name = $_GET["name"];
    $safe = $escaper->escapeHtml($name);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("escapeHtml() should neutralize the HTML-output (XSS) taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LaminasEscaper_Sanitized_EscapeHtmlAttr(t *testing.T) {
	code := `<?php
function render() {
    $escaper = new Laminas\Escaper\Escaper('utf-8');
    $cls = $_GET["cls"];
    $safe = $escaper->escapeHtmlAttr($cls);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("escapeHtmlAttr() should neutralize the HTML-output (XSS) taint flow")
	}
}

func TestPHP_LaminasEscaper_Sanitized_EscapeJs(t *testing.T) {
	code := `<?php
function render() {
    $escaper = new Laminas\Escaper\Escaper('utf-8');
    $val = $_GET["val"];
    $safe = $escaper->escapeJs($val);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("escapeJs() should neutralize the HTML-output (XSS) taint flow")
	}
}

func TestPHP_LaminasEscaper_Sanitized_EscapeCss(t *testing.T) {
	code := `<?php
function render() {
    $escaper = new Laminas\Escaper\Escaper('utf-8');
    $color = $_GET["color"];
    $safe = $escaper->escapeCss($color);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("escapeCss() should neutralize the HTML-output (XSS) taint flow")
	}
}

func TestPHP_LaminasEscaper_Sanitized_EscapeUrl(t *testing.T) {
	code := `<?php
function render() {
    $escaper = new Laminas\Escaper\Escaper('utf-8');
    $next = $_GET["next"];
    $safe = $escaper->escapeUrl($next);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("escapeUrl() should neutralize the HTML-output (XSS) taint flow")
	}
}

// Negative control: without the escaper the $_GET -> printf flow must fire,
// proving the sink is detected and the positive tests above are meaningful.
func TestPHP_LaminasEscaper_Unsanitized_Printf(t *testing.T) {
	code := `<?php
function render() {
    $name = $_GET["name"];
    printf("%s", $name);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output (XSS) flow for $_GET -> printf without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
