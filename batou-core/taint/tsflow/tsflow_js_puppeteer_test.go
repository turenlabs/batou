package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the Puppeteer/Playwright headless-browser automation sinks:
//
//   - js.puppeteer.goto           — page.goto(url)        SSRF (CWE-918)
//   - js.puppeteer.evaluate       — page.evaluate(code)   code injection (CWE-94)
//   - js.puppeteer.evaluatehandle — page.evaluateHandle() code injection (CWE-94)
//   - js.puppeteer.setcontent     — page.setContent(html) HTML/script injection (CWE-79)
//
// All four pin ObjectType "Page" so they fire on the conventional `page` (or `p`)
// receiver and do not false-fire on unrelated objects. Both Puppeteer and
// Playwright share the `page.<method>` shape, so one entry covers both.

func TestJS_Puppeteer_Goto_SSRF(t *testing.T) {
	code := `
async function screenshot(req, res) {
    const page = await browser.newPage();
    const target = req.query.url;
    await page.goto(target);
}
`
	flows := Analyze(code, "/app/routes/screenshot.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.puppeteer.goto") {
		t.Error("expected js.puppeteer.goto flow from req.query -> page.goto()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Puppeteer_Goto_ShortReceiver_SSRF(t *testing.T) {
	// `p` is a prefix-abbreviation of "Page" and a common alias.
	code := `
async function render(req, res) {
    const p = await browser.newPage();
    const dest = req.params.host;
    await p.goto(dest);
}
`
	flows := Analyze(code, "/app/routes/render.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.puppeteer.goto") {
		t.Error("expected js.puppeteer.goto flow from req.params -> p.goto()")
	}
}

func TestJS_Puppeteer_Evaluate_CodeInjection(t *testing.T) {
	code := `
async function run(req, res) {
    const page = await browser.newPage();
    const script = req.body.script;
    await page.evaluate(script);
}
`
	flows := Analyze(code, "/app/routes/run.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.puppeteer.evaluate") {
		t.Error("expected js.puppeteer.evaluate flow from req.body -> page.evaluate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Puppeteer_EvaluateHandle_CodeInjection(t *testing.T) {
	code := `
async function run(req, res) {
    const page = await browser.newPage();
    const expr = req.query.expr;
    await page.evaluateHandle(expr);
}
`
	flows := Analyze(code, "/app/routes/handle.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.puppeteer.evaluatehandle") {
		t.Error("expected js.puppeteer.evaluatehandle flow from req.query -> page.evaluateHandle()")
	}
}

func TestJS_Puppeteer_SetContent_HTMLInjection(t *testing.T) {
	code := `
async function preview(req, res) {
    const page = await browser.newPage();
    const html = req.body.html;
    await page.setContent(html);
}
`
	flows := Analyze(code, "/app/routes/preview.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.puppeteer.setcontent") {
		t.Error("expected js.puppeteer.setcontent flow from req.body -> page.setContent()")
	}
}

// --- Negative tests: scoping must not over-fire ---

// A constant URL must not produce an SSRF flow.
func TestJS_Puppeteer_Goto_ConstantURL_NoFlow(t *testing.T) {
	code := `
async function health(req, res) {
    const page = await browser.newPage();
    await page.goto("https://example.com/health");
}
`
	flows := Analyze(code, "/app/routes/health.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.puppeteer.goto") {
		t.Error("did not expect js.puppeteer.goto flow for a constant URL")
	}
}

// `evaluate` on an unrelated (non-page) receiver must not fire the eval sink.
func TestJS_Puppeteer_Evaluate_UnrelatedReceiver_NoFlow(t *testing.T) {
	code := `
function compute(req, res) {
    const formula = req.body.formula;
    const calculator = makeCalculator();
    calculator.evaluate(formula);
}
`
	flows := Analyze(code, "/app/routes/compute.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.puppeteer.evaluate") {
		t.Error("did not expect js.puppeteer.evaluate flow on an unrelated `calculator` receiver")
	}
}
