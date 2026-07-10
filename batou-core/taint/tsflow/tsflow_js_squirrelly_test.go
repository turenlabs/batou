package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ---------------------------------------------------------------------------
// Squirrelly SSTI — SnkTemplate (CWE-1336)
//
// Squirrelly compiles a template body into a callable JS function, so a
// user-controlled template string passed to Sqrl.render() / Sqrl.compile()
// is server-side template injection leading to RCE (CVE-2021-32819,
// GHSL-2021-023). See js.squirrelly.render / js.squirrelly.compile.
// ---------------------------------------------------------------------------

func TestJS_SSTI_Squirrelly_Render(t *testing.T) {
	code := `
const Sqrl = require('squirrelly');

app.post('/render', (req, res) => {
    const tmpl = req.body.template;
    const html = Sqrl.render(tmpl, { user: 'admin' });
    res.send(html);
});
`
	flows := Analyze(code, "/app/routes/render.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow from req.body.template -> Sqrl.render()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_SSTI_Squirrelly_Compile(t *testing.T) {
	code := `
const Sqrl = require('squirrelly');

app.post('/compile', (req, res) => {
    const src = req.body.templateSource;
    const fn = Sqrl.compile(src);
    res.send(fn({ name: 'world' }));
});
`
	flows := Analyze(code, "/app/routes/compile.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow from req.body.templateSource -> Sqrl.compile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Safe Squirrelly usage — a hardcoded template with no tainted input in scope
// must NOT produce a SnkTemplate flow (non-vacuous negative control).
// ---------------------------------------------------------------------------

func TestJS_SSTI_Squirrelly_Safe_ConstantTemplate(t *testing.T) {
	code := `
const Sqrl = require('squirrelly');

function banner() {
    const tmpl = "<h1>{{it.title}}</h1>";
    return Sqrl.render(tmpl, { title: 'Welcome' });
}
`
	flows := Analyze(code, "/app/routes/safe.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Errorf("constant template should not produce SnkTemplate flow (source=%s, conf=%.2f)", f.Source.Category, f.Confidence)
		}
	}
}
