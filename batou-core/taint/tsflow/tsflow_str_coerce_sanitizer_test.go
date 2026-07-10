package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// These tests pin the precision of the str()/String() type-coercion
// sanitizers (py.str, js.string.coerce).
//
// The bug they guard against: both entries previously claimed to neutralize
// SnkSQLQuery and SnkCommand. But str()/String() of an already-string payload
// is the IDENTITY operation — `str("' OR '1'='1")` == `"' OR '1'='1"` — so the
// injection survives completely unchanged. Treating str() as a SQL/command
// sanitizer silently dropped real injection flows (false negatives).
//
// The legitimate protection these coercions DO provide is against NoSQL
// operator injection: a dict/object such as {"$ne": null} coerces to a harmless
// string, defeating the operator. So the entries are scoped to SnkNoSQL only.

func TestStrCoerce_Python_DoesNotSanitizeSQL(t *testing.T) {
	// str() wrapping a tainted value at the SQL sink must STILL flow.
	code := `
from flask import request
import sqlite3

def handler():
    name = request.args.get("name")
    cursor.execute(str(name))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("str(name) at a SQL sink must NOT be treated as sanitized — str() is identity on strings; got flows=%+v", flows)
	}
}

func TestStrCoerce_Python_DoesNotSanitizeCommand(t *testing.T) {
	code := `
from flask import request
import os

def handler():
    name = request.args.get("name")
    os.system("echo " + str(name))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("str(name) reaching os.system must NOT be treated as sanitized; got flows=%+v", flows)
	}
}

func TestStrCoerce_Python_AssignedThenSink(t *testing.T) {
	// Assign-then-sink form: q = str(name); cursor.execute(q)
	code := `
from flask import request
import sqlite3

def handler():
    name = request.args.get("name")
    q = str(name)
    cursor.execute(q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("q = str(name); execute(q) must flow to SQL sink; got flows=%+v", flows)
	}
}

func TestStrCoerce_Python_StillSanitizesNoSQL(t *testing.T) {
	// str() DOES defeat NoSQL operator injection (dict -> string), so the
	// flow into a NoSQL sink must remain neutralized. (Verified non-vacuous:
	// the same fixture without str() produces a SnkNoSQL flow.)
	code := `
from flask import request

def handler():
    flt = request.get_json()
    collection.find_one(str(flt))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Errorf("str() must still neutralize NoSQL operator injection; got NoSQL flow=%+v", flows)
	}
}

func TestStrCoerce_JS_DoesNotSanitizeSQL(t *testing.T) {
	code := `
function handler(req, res) {
  const name = req.query.name;
  db.query(String(name));
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("String(name) at a SQL sink must NOT be treated as sanitized; got flows=%+v", flows)
	}
}

func TestStrCoerce_JS_StillSanitizesNoSQL(t *testing.T) {
	// String() coercion defeats Mongo operator injection ({$ne:null} -> string).
	// (Verified non-vacuous: the same fixture without String() produces a
	// SnkNoSQL flow.)
	code := `
function handler(req, res) {
  const filter = req.body.filter;
  collection.aggregate(String(filter));
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Errorf("String() must still neutralize NoSQL operator injection; got NoSQL flow=%+v", flows)
	}
}
