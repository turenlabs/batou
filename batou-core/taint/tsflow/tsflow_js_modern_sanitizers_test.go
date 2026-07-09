package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Yahoo xss-filters (HTML context-aware encoders)
// =========================================================================

func TestJS_XSSFilters_InHTMLData_NeutralizesXSS(t *testing.T) {
	code := `
const xssFilters = require('xss-filters');

function handler(req, res) {
    const userInput = req.query.name;
    const safe = xssFilters.inHTMLData(userInput);
    res.send("<div>" + safe + "</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("xssFilters.inHTMLData should neutralize HTMLOutput taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_XSSFilters_InUnQuotedAttr_NeutralizesXSS(t *testing.T) {
	code := `
const xssFilters = require('xss-filters');

function handler(req, res) {
    const cls = req.query.cls;
    const safe = xssFilters.inUnQuotedAttr(cls);
    res.send("<div class=" + safe + ">x</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("xssFilters.inUnQuotedAttr should neutralize HTMLOutput taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_XSSFilters_InDoubleQuotedAttr_NeutralizesXSS(t *testing.T) {
	code := `
const xssFilters = require('xss-filters');

function handler(req, res) {
    const title = req.query.title;
    const safe = xssFilters.inDoubleQuotedAttr(title);
    res.send('<a title="' + safe + '">link</a>');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("xssFilters.inDoubleQuotedAttr should neutralize HTMLOutput taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_XSSFilters_InSingleQuotedAttr_NeutralizesXSS(t *testing.T) {
	code := `
const xssFilters = require('xss-filters');

function handler(req, res) {
    const id = req.query.id;
    const safe = xssFilters.inSingleQuotedAttr(id);
    res.send("<a id='" + safe + "'>link</a>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("xssFilters.inSingleQuotedAttr should neutralize HTMLOutput taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_XSSFilters_UriInHTMLData_NeutralizesXSS(t *testing.T) {
	code := `
const xssFilters = require('xss-filters');

function handler(req, res) {
    const url = req.query.url;
    const safe = xssFilters.uriInHTMLData(url);
    res.send('<a href="' + safe + '">click</a>');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("xssFilters.uriInHTMLData should neutralize HTMLOutput taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Verify XSS without xss-filters still produces a finding (regression guard)
func TestJS_XSSFilters_Unsanitized_StillDetected(t *testing.T) {
	code := `
function handler(req, res) {
    const userInput = req.query.name;
    res.send("<div>" + userInput + "</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTMLOutput flow for unsanitized req.query -> res.send")
	}
}

// =========================================================================
// Argon2 password hashing
// =========================================================================

func TestJS_Argon2_Hash_NeutralizesCryptoSink(t *testing.T) {
	code := `
const argon2 = require('argon2');

async function register(req, res) {
    const password = req.body.password;
    const hash = await argon2.hash(password);
    return hash;
}
`
	flows := Analyze(code, "/app/auth.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Source.Category == taint.SrcUserInput {
			t.Errorf("argon2.hash should neutralize SnkCrypto taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Argon2_Verify_NeutralizesCryptoSink(t *testing.T) {
	code := `
const argon2 = require('argon2');

async function login(req, storedHash) {
    const password = req.body.password;
    const ok = await argon2.verify(storedHash, password);
    return ok;
}
`
	flows := Analyze(code, "/app/auth.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Source.Category == taint.SrcUserInput {
			t.Errorf("argon2.verify should neutralize SnkCrypto taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// Node crypto KDFs (scrypt, pbkdf2)
// =========================================================================

func TestJS_CryptoScrypt_NeutralizesCryptoSink(t *testing.T) {
	code := `
const crypto = require('crypto');

function deriveKey(req) {
    const password = req.body.password;
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 32);
    return key;
}
`
	flows := Analyze(code, "/app/auth.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Source.Category == taint.SrcUserInput {
			t.Errorf("crypto.scryptSync should neutralize SnkCrypto taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_CryptoPbkdf2_NeutralizesCryptoSink(t *testing.T) {
	code := `
const crypto = require('crypto');

function hashPassword(req) {
    const password = req.body.password;
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
    return hash;
}
`
	flows := Analyze(code, "/app/auth.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Source.Category == taint.SrcUserInput {
			t.Errorf("crypto.pbkdf2Sync should neutralize SnkCrypto taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// =========================================================================
// Bare-function unique-name sanitizers (striptags, slugify, filenamify)
// =========================================================================

func TestJS_Striptags_NeutralizesXSS(t *testing.T) {
	code := `
const striptags = require('striptags');

function handler(req, res) {
    const userHTML = req.body.comment;
    const safe = striptags(userHTML);
    res.send("<div>" + safe + "</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Source.Category == taint.SrcUserInput {
			t.Errorf("striptags should neutralize HTMLOutput taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Slugify_NeutralizesPathTraversal(t *testing.T) {
	code := `
const fs = require('fs');
const slugify = require('slugify');

function handler(req, res) {
    const title = req.body.title;
    const slug = slugify(title);
    fs.writeFileSync('/uploads/' + slug + '.txt', 'data');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Source.Category == taint.SrcUserInput {
			t.Errorf("slugify should neutralize FileWrite taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Filenamify_NeutralizesPathTraversal(t *testing.T) {
	code := `
const fs = require('fs');
const filenamify = require('filenamify');

function handler(req, res) {
    const name = req.body.filename;
    const safe = filenamify(name);
    fs.writeFileSync('/uploads/' + safe, 'data');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Source.Category == taint.SrcUserInput {
			t.Errorf("filenamify should neutralize FileWrite taint, but got flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Regression guard — without sanitization, the flow is detected.
func TestJS_Striptags_Unsanitized_StillDetected(t *testing.T) {
	code := `
function handler(req, res) {
    const userHTML = req.body.comment;
    res.send("<div>" + userHTML + "</div>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTMLOutput flow for unsanitized req.body -> res.send")
	}
}
