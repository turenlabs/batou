package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// validator.js sanitizer-module type-coercion functions
// (toInt / toFloat / toBoolean / toDate). These return a number / boolean /
// Date (or NaN / null) so the result can no longer carry string-injection.
// =========================================================================

func TestJS_ValidatorToInt_NeutralizesSQL(t *testing.T) {
	code := `
const validator = require('validator');

function handler(req, res) {
    const raw = req.query.id;
    const id = validator.toInt(raw, 10);
    connection.query("SELECT * FROM users WHERE id = " + id);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.Category == taint.SrcUserInput {
			t.Errorf("validator.toInt should neutralize SQL taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_ValidatorToInt_NeutralizesCommand(t *testing.T) {
	code := `
const validator = require('validator');

function handler(req, res) {
    const raw = req.query.count;
    const n = validator.toInt(raw);
    execSync("head -n " + n + " /var/log/app.log");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Source.Category == taint.SrcUserInput {
			t.Errorf("validator.toInt should neutralize command taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_ValidatorToFloat_NeutralizesSQL(t *testing.T) {
	code := `
const validator = require('validator');

function handler(req, res) {
    const raw = req.query.price;
    const price = validator.toFloat(raw);
    connection.query("SELECT * FROM products WHERE price < " + price);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.Category == taint.SrcUserInput {
			t.Errorf("validator.toFloat should neutralize SQL taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_ValidatorToBoolean_NeutralizesEval(t *testing.T) {
	code := `
const validator = require('validator');

function handler(req, res) {
    const raw = req.query.flag;
    const flag = validator.toBoolean(raw, true);
    eval(flag);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Source.Category == taint.SrcUserInput {
			t.Errorf("validator.toBoolean should neutralize eval taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_ValidatorToDate_NeutralizesSQL(t *testing.T) {
	code := `
const validator = require('validator');

function handler(req, res) {
    const raw = req.query.since;
    const since = validator.toDate(raw);
    connection.query("SELECT * FROM events WHERE created_at > '" + since + "'");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.Category == taint.SrcUserInput {
			t.Errorf("validator.toDate should neutralize SQL taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// lodash / underscore _.escape() — HTML entity encoding
// =========================================================================

func TestJS_LodashEscape_NeutralizesXSS(t *testing.T) {
	code := `
const _ = require('lodash');

function handler(req, res) {
    const name = req.query.name;
    const safe = _.escape(name);
    res.send("<div>" + safe + "</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("_.escape should neutralize HTMLOutput taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// entities package — encodeHTML / encodeXML / escapeUTF8
// =========================================================================

func TestJS_EntitiesEncodeHTML_NeutralizesXSS(t *testing.T) {
	code := `
const entities = require('entities');

function handler(req, res) {
    const comment = req.query.comment;
    const safe = entities.encodeHTML(comment);
    res.send("<p>" + safe + "</p>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("entities.encodeHTML should neutralize HTMLOutput taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_EntitiesEscapeUTF8_NeutralizesXSS(t *testing.T) {
	code := `
const entities = require('entities');

function handler(req, res) {
    const title = req.query.title;
    const safe = entities.escapeUTF8(title);
    res.send("<h1>" + safe + "</h1>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("entities.escapeUTF8 should neutralize HTMLOutput taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// @braintree/sanitize-url — sanitizeUrl()
// =========================================================================

func TestJS_SanitizeUrl_NeutralizesRedirect(t *testing.T) {
	code := `
const { sanitizeUrl } = require('@braintree/sanitize-url');

function handler(req, res) {
    const next = req.query.next;
    const safe = sanitizeUrl(next);
    res.redirect(safe);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Source.Category == taint.SrcUserInput {
			t.Errorf("sanitizeUrl should neutralize redirect taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_SanitizeUrl_NeutralizesXSSHref(t *testing.T) {
	code := `
const { sanitizeUrl } = require('@braintree/sanitize-url');

function handler(req, res) {
    const link = req.query.link;
    const safe = sanitizeUrl(link);
    res.send('<a href="' + safe + '">click</a>');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("sanitizeUrl should neutralize HTMLOutput taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// js-xss library — filterXSS()
// =========================================================================

func TestJS_FilterXSS_NeutralizesXSS(t *testing.T) {
	code := `
const { filterXSS } = require('xss');

function handler(req, res) {
    const bio = req.query.bio;
    const safe = filterXSS(bio);
    res.send("<section>" + safe + "</section>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("filterXSS should neutralize HTMLOutput taint, got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// Negative controls — without the sanitizer, the flow must still be detected.
// =========================================================================

func TestJS_ValidatorEscape_Unsanitized_SQLStillDetected(t *testing.T) {
	code := `
function handler(req, res) {
    const id = req.query.id;
    connection.query("SELECT * FROM users WHERE id = " + id);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for unsanitized req.query.id -> connection.query")
	}
}

func TestJS_ValidatorEscape_Unsanitized_EvalStillDetected(t *testing.T) {
	code := `
function handler(req, res) {
    const flag = req.query.flag;
    eval(flag);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for unsanitized req.query.flag -> eval")
	}
}

func TestJS_ValidatorEscape_Unsanitized_XSSStillDetected(t *testing.T) {
	code := `
function handler(req, res) {
    const name = req.query.name;
    res.send("<div>" + name + "</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTMLOutput flow for unsanitized req.query.name -> res.send")
	}
}

func TestJS_ValidatorEscape_Unsanitized_RedirectStillDetected(t *testing.T) {
	code := `
function handler(req, res) {
    const next = req.query.next;
    res.redirect(next);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for unsanitized req.query.next -> res.redirect")
	}
}

// =========================================================================
// Catalog registration — every new js.* entry must also be mirrored to ts.*
// =========================================================================

func TestJS_ValidatorEscapeSanitizers_Registered(t *testing.T) {
	want := []string{
		"js.validator.toint", "js.validator.tofloat", "js.validator.toboolean", "js.validator.todate",
		"js.lodash.escape", "js.entities.encodehtml", "js.braintree.sanitizeurl", "js.xss.filterxss",
		"ts.validator.toint", "ts.validator.tofloat", "ts.validator.toboolean", "ts.validator.todate",
		"ts.lodash.escape", "ts.entities.encodehtml", "ts.braintree.sanitizeurl", "ts.xss.filterxss",
	}
	got := map[string]bool{}
	for _, c := range taint.AllCatalogs() {
		if c.Language() != rules.LangJavaScript && c.Language() != rules.LangTypeScript {
			continue
		}
		for _, s := range c.Sanitizers() {
			got[s.ID] = true
		}
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("sanitizer %q not registered", id)
		}
	}
}
