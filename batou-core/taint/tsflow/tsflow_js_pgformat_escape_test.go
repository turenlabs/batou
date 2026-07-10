package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// JavaScript pg-format (node-pg-format) dynamic-SQL escape sanitizer tests.
//
// pg-format implements PostgreSQL's format() and exposes standalone escape
// helpers used when parameter placeholders can't be applied (e.g. interpolating
// a table/column name into dynamic SQL):
//   - format.literal(value) -> escaped SQL literal   (quote_literal equivalent)
//   - format.ident(name)    -> escaped SQL identifier (quote_ident equivalent)
//
// Both are scoped to ObjectType "format" (the canonical `const format =
// require('pg-format')` receiver) so they do NOT match Sequelize.literal(),
// which injects raw unescaped SQL.
//
// Each positive test asserts NO SQL flow survives the sanitizer; the negative
// regression below confirms the sink fires without it.

func TestJS_Sanitizer_PgFormatLiteral(t *testing.T) {
	code := `
const format = require('pg-format');
const { Client } = require('pg');
const client = new Client();

function handler(req, res) {
    const name = req.query.name;
    const safe = format.literal(name);
    const sql = "SELECT * FROM users WHERE name = " + safe;
    client.query(sql);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.Category == taint.SrcUserInput {
			t.Errorf("format.literal() should neutralize SQL taint; got flow %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Sanitizer_PgFormatIdent(t *testing.T) {
	code := `
const format = require('pg-format');
const { Client } = require('pg');
const client = new Client();

function handler(req, res) {
    const tableName = req.query.table;
    const safeId = format.ident(tableName);
    const sql = "SELECT * FROM " + safeId + " WHERE active = 1";
    client.query(sql);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.Category == taint.SrcUserInput {
			t.Errorf("format.ident() should neutralize SQL identifier taint; got flow %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Negative regression: without the sanitizer, the sink MUST still fire ---

func TestJS_PgFormatEscape_NegativeRegression_NoSanitizer(t *testing.T) {
	code := `
const { Client } = require('pg');
const client = new Client();

function handler(req, res) {
    const name = req.query.name;
    const sql = "SELECT * FROM users WHERE name = '" + name + "'";
    client.query(sql);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.Category == taint.SrcUserInput {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow when no sanitizer is used (regression check)")
	}
}

// --- Catalog presence check ---

func TestJS_PgFormatEscape_SanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJavaScript)
	if cat == nil {
		t.Fatal("JavaScript catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sanitizers() {
		found[s.ID] = true
	}
	for _, id := range []string{"js.pgformat.literal", "js.pgformat.ident"} {
		if !found[id] {
			t.Errorf("missing expected sanitizer: %s", id)
		}
	}
}
