package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ---------------------------------------------------------------------------
// Prototype-poisoning-safe JSON parsers as SnkPrototype sanitizers (CWE-1321).
//
// secure-json-parse (Fastify) and @hapi/bourne are drop-in JSON.parse
// replacements that strip / reject `__proto__` and `constructor.prototype`
// keys. Their parsed output is therefore safe to feed into deep-merge /
// set-by-path sinks. These tests pin the new sanitizer entries:
//   js.secure-json-parse.parse / .scan
//   js.bourne.parse / .scan
//
// The baseline flow shape (req.body -> _.merge(target, input)) is the one
// proven to fire in tsflow_js_proto_pollution_test.go (TestJS_ProtoPollution_
// Lodash_Merge). Inserting a secure parser between source and sink must
// neutralize the SnkPrototype flow.
// ---------------------------------------------------------------------------

func TestJS_Sanitizer_SecureJsonParse_NeutralizesProto(t *testing.T) {
	code := `
const _ = require('lodash');
const sjson = require('secure-json-parse');

app.post('/config', (req, res) => {
    const raw = req.body;
    const input = sjson.parse(raw);
    const config = _.merge(target, input);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow after sjson.parse() sanitizes the input")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Sanitizer_SecureJsonParse_SafeParse_NeutralizesProto(t *testing.T) {
	code := `
const _ = require('lodash');
const sjson = require('secure-json-parse');

app.post('/config', (req, res) => {
    const raw = req.body;
    const input = sjson.safeParse(raw);
    const config = _.merge(target, input);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow after sjson.safeParse() sanitizes the input")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Sanitizer_SecureJsonParse_Scan_NeutralizesProto(t *testing.T) {
	code := `
const _ = require('lodash');
const sjson = require('secure-json-parse');

app.post('/config', (req, res) => {
    const parsed = req.body;
    const clean = sjson.scan(parsed);
    const config = _.merge(target, clean);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow after sjson.scan() sanitizes the object")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Sanitizer_Bourne_NeutralizesProto(t *testing.T) {
	code := `
const _ = require('lodash');
const Bourne = require('@hapi/bourne');

app.post('/config', (req, res) => {
    const raw = req.body;
    const input = Bourne.parse(raw);
    const config = _.merge(target, input);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow after Bourne.parse() sanitizes the input")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: plain JSON.parse is NOT a SnkPrototype sanitizer (it only
// neutralizes SnkEval), so the same flow shape MUST still fire. This proves the
// neutralization above is specifically attributable to the secure parsers, not
// to taint being lost through any `.parse()` call.
func TestJS_Sanitizer_PlainJsonParse_DoesNotNeutralizeProto(t *testing.T) {
	code := `
const _ = require('lodash');

app.post('/config', (req, res) => {
    const raw = req.body;
    const input = JSON.parse(raw);
    const config = _.merge(target, input);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected proto-pollution flow to still fire — plain JSON.parse does not strip __proto__")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
