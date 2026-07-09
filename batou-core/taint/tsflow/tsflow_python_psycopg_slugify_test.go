package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- psycopg.sql.Identifier (safe SQL identifier composition) ---

func TestPython_PsycopgIdentifier_Unsanitized(t *testing.T) {
	code := `
from flask import request

def handler():
    table = request.args.get("table")
    query = "SELECT * FROM " + table
    cursor.execute(query)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow when user input is concatenated into raw SQL")
	}
}

func TestPython_PsycopgIdentifier_Sanitized_FromImport(t *testing.T) {
	code := `
from flask import request
from psycopg2 import sql

def handler():
    table = request.args.get("table")
    safe = sql.Identifier(table)
    cursor.execute(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow when sql.Identifier wraps user input; got %s", f.Sink.MethodName)
		}
	}
}

func TestPython_PsycopgIdentifier_Sanitized_FullyQualified(t *testing.T) {
	code := `
from flask import request
import psycopg2.sql

def handler():
    table = request.args.get("table")
    safe = psycopg2.sql.Identifier(table)
    cursor.execute(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow when psycopg2.sql.Identifier wraps user input; got %s", f.Sink.MethodName)
		}
	}
}

func TestPython_PsycopgIdentifier_Sanitized_Psycopg3(t *testing.T) {
	code := `
from flask import request
import psycopg.sql

def handler():
    column = request.args.get("col")
    safe = psycopg.sql.Identifier(column)
    cursor.execute(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow when psycopg.sql.Identifier wraps user input; got %s", f.Sink.MethodName)
		}
	}
}

// --- psycopg.sql.Literal ---

func TestPython_PsycopgLiteral_Sanitized(t *testing.T) {
	code := `
from flask import request
from psycopg2 import sql

def handler():
    value = request.args.get("v")
    safe = sql.Literal(value)
    cursor.execute(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow when sql.Literal wraps user input; got %s", f.Sink.MethodName)
		}
	}
}

// --- python-slugify ---

func TestPython_Slugify_Unsanitized(t *testing.T) {
	code := `
from flask import request

def handler():
    name = request.args.get("name")
    path = "/var/data/" + name
    open(path)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file flow when user input is concatenated into a path")
	}
}

func TestPython_Slugify_Sanitized_FromImport(t *testing.T) {
	code := `
from flask import request
from slugify import slugify

def handler():
    name = request.args.get("name")
    safe = slugify(name)
    path = "/var/data/" + safe
    open(path)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected NO file flow when slugify() sanitizes user input; got %s", f.Sink.MethodName)
		}
	}
}

func TestPython_Slugify_Sanitized_ModuleQualified(t *testing.T) {
	code := `
from flask import request
import slugify

def handler():
    name = request.args.get("name")
    safe = slugify.slugify(name)
    path = "/var/data/" + safe
    open(path, "w")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected NO file flow when slugify.slugify() sanitizes user input; got %s", f.Sink.MethodName)
		}
	}
}
