package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP CodeIgniter 4 / Yii 2 output-escaping sanitizer tests
//
// CodeIgniter and Yii both have request sources (and CodeIgniter a
// db->query() SQL sink) already modeled in the catalog, but neither
// framework's canonical XSS-prevention call was registered as a sanitizer.
// That meant correctly-escaped output still produced an HTML-output (XSS)
// taint flow — a false positive.
//
//   - CodeIgniter 4 esc()             — context-aware output escaping helper
//   - Yii 2 Html::encode()            — htmlspecialchars-based entity encoding
//   - Yii 2 HtmlPurifier::process()   — HTML Purifier markup sanitization
//
// Each positive test takes a tainted $_GET source, runs it through the
// framework escaper, then prints the result — the SnkHTMLOutput flow must
// NOT be present. The negative control prints the raw source so the harness
// proves the sink itself is detected and the positive tests are meaningful.
// =========================================================================

func TestPHP_CodeIgniter_Esc_SanitizesXSS(t *testing.T) {
	code := `<?php
function render() {
    $name = $_GET["name"];
    $safe = esc($name);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("CodeIgniter esc() should neutralize the HTML-output (XSS) taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Yii_HtmlEncode_SanitizesXSS(t *testing.T) {
	code := `<?php
function render() {
    $name = $_GET["name"];
    $safe = Html::encode($name);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Yii Html::encode() should neutralize the HTML-output (XSS) taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Yii_HtmlPurifier_SanitizesXSS(t *testing.T) {
	code := `<?php
function render() {
    $bio = $_GET["bio"];
    $safe = HtmlPurifier::process($bio);
    printf("%s", $safe);
}
?>`
	flows := Analyze(code, "/app/view.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Yii HtmlPurifier::process() should neutralize the HTML-output (XSS) taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative control: without any escaper the $_GET -> printf flow must fire,
// proving the sink is detected and the positive tests above are meaningful.
func TestPHP_CIYii_Unsanitized_Printf(t *testing.T) {
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
