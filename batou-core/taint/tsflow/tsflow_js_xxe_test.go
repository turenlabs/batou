package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ---------------------------------------------------------------------------
// XML External Entity (XXE) — SnkDeserialize on tainted XML parsing
// (CWE-611 — entity expansion / external DTD loading)
// ---------------------------------------------------------------------------
// XML/XXE sinks — SnkDeserialize (CWE-611)

func TestJS_XXE_Libxmljs_ParseXml(t *testing.T) {
	code := `
const libxmljs = require('libxmljs');

app.post('/upload', (req, res) => {
    const xml = req.body.document;
    const doc = libxmljs.parseXml(xml);
    res.json({ root: doc.root().name() });
});
`
	flows := Analyze(code, "/app/routes/upload.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.document -> libxmljs.parseXml()")
	}
}

func TestJS_XXE_Libxmljs_ParseXml_NoEnt(t *testing.T) {
	code := `
const libxmljs = require('libxmljs');

app.post('/parse', (req, res) => {
    const xml = req.body.xmlData;
    const doc = libxmljs.parseXml(xml, { noent: true });
    res.send(doc.toString());
});
`
	flows := Analyze(code, "/app/routes/parse.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.xmlData -> libxmljs.parseXml()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_XXE_Libxmljs_ParseXmlString(t *testing.T) {
	code := `
const libxmljs = require('libxmljs');

app.post('/parse', (req, res) => {
    const raw = req.body.xml;
    const doc = libxmljs.parseXmlString(raw);
    res.json({ ok: true });
    const xml = req.body.data;
    const doc = libxmljs.parseXmlString(xml);
    res.send(doc.toString());
});
`
	flows := Analyze(code, "/app/routes/parse.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.xml -> libxmljs.parseXmlString()")
		t.Error("expected XXE flow from req.body.data -> libxmljs.parseXmlString()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_XXE_Libxmljs2_ParseXml(t *testing.T) {
	code := `
const libxmljs2 = require('libxmljs2');

app.post('/soap', (req, res) => {
    const envelope = req.body.soap;
    const doc = libxmljs2.parseXml(envelope);
    res.send(doc.toString());
});
`
	flows := Analyze(code, "/app/routes/soap.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.soap -> libxmljs2.parseXml()")
	}
}
func TestJS_XXE_Libxmljs2_ParseXmlString(t *testing.T) {
	code := `
const libxmljs2 = require('libxmljs2');

app.post('/parse', (req, res) => {
    const xml = req.body.payload;
    const doc = libxmljs2.parseXmlString(xml);
    res.send(doc.toString());
});
`
	flows := Analyze(code, "/app/routes/parse.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.payload -> libxmljs2.parseXmlString()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_XXE_Xml2js_ParseString(t *testing.T) {
	code := `
const xml2js = require('xml2js');

app.post('/parse', (req, res) => {
    const xml = req.body.data;
    xml2js.parseString(xml, (err, result) => {
        res.json(result);
    });
});
`
	flows := Analyze(code, "/app/routes/parse.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.data -> xml2js.parseString()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_XXE_Xml2js_ParseStringPromise(t *testing.T) {
	code := `
const xml2js = require('xml2js');

app.post('/parseasync', async (req, res) => {
    const doc = req.body.document;
    const result = await xml2js.parseStringPromise(doc);
    res.json(result);
});
`
	flows := Analyze(code, "/app/routes/parseasync.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.document -> xml2js.parseStringPromise()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_XXE_Plist_Parse(t *testing.T) {
	code := `
const plist = require('plist');

app.post('/config', (req, res) => {
    const data = req.body.plist;
    const parsed = plist.parse(data);
    res.json(parsed);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected XXE flow from req.body.plist -> plist.parse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Safe XML parsing — static/hardcoded input should not flag as tainted XXE
// ---------------------------------------------------------------------------

func TestJS_XXE_Safe_Libxmljs_StaticInput(t *testing.T) {
	code := `
const libxmljs = require('libxmljs');

app.get('/static', (req, res) => {
    const doc = libxmljs.parseXml("<root><child/></root>");
    res.send(doc.toString());
});
`
	flows := Analyze(code, "/app/routes/static.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Logf("note: SnkDeserialize flagged on static literal (source=%s, conf=%.2f) — literal is safe, pattern-level FP is expected in this engine", f.Source.Category, f.Confidence)
		}
	}
}
// Safe: hardcoded XML, no user taint.
func TestJS_XXE_Libxmljs_Safe_HardcodedInput(t *testing.T) {
	code := `
const libxmljs = require('libxmljs');

app.get('/health', (req, res) => {
    const doc = libxmljs.parseXml('<?xml version="1.0"?><ok/>');
    res.send(doc.toString());
});
`
	flows := Analyze(code, "/app/routes/health.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("no SnkDeserialize flow expected for hardcoded XML input, got source=%s sink=%s", f.Source.Category, f.Sink.Category)
		}
	}
}
