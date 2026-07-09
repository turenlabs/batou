package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Tests for two genuinely-missing, unambiguously-correct Python escaper
// sanitizers:
//
//   - py.mysql.escape_string : PyMySQL/mysqlclient escape_string() escapes
//     user input for a MySQL string literal (SnkSQLQuery). Direct analogue of
//     PHP's mysqli_real_escape_string, which is already a sanitizer.
//   - py.shlex.join          : shlex.join() (stdlib 3.8+) shell-escapes every
//     element of a token list into one safe command string (SnkCommand). The
//     canonical companion to the already-modeled shlex.quote.
//
// Each sanitized test pairs a tainted Flask request param with the relevant
// sink and asserts the category is cleared off the flow. Each Unsanitized
// baseline confirms the raw source -> sink path IS detected without the
// sanitizer, so the sanitized test isn't passing vacuously.
//
// All call sites are wrapped in `def handler()` because the Python tsflow
// walker only descends into function_definition bodies.
// =========================================================================

func TestPython_EscapeString_Unsanitized_Baseline(t *testing.T) {
	code := `
from flask import request

def handler():
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
`
	flows := Analyze(code, "/app/db.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatal("expected SnkSQLQuery flow when raw request param reaches cursor.execute")
	}
}

func TestPython_EscapeString_Sanitized(t *testing.T) {
	code := `
from flask import request

def handler():
    name = request.args.get("name")
    safe = conn.escape_string(name)
    cursor.execute("SELECT * FROM users WHERE name = '" + safe + "'")
`
	flows := Analyze(code, "/app/db.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("conn.escape_string() should neutralize SnkSQLQuery taint")
		}
	}
}

func TestPython_EscapeString_ModuleForm_Sanitized(t *testing.T) {
	code := `
import pymysql
from flask import request

def handler():
    name = request.args.get("name")
    safe = pymysql.escape_string(name)
    cursor.execute("SELECT * FROM users WHERE name = '" + safe + "'")
`
	flows := Analyze(code, "/app/db.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("pymysql.escape_string() should neutralize SnkSQLQuery taint")
		}
	}
}

func TestPython_ShlexJoin_Unsanitized_Baseline(t *testing.T) {
	code := `
import os
from flask import request

def handler():
    name = request.args.get("name")
    os.system("ls " + name)
`
	flows := Analyze(code, "/app/run.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Fatal("expected SnkCommand flow when raw request param reaches os.system")
	}
}

func TestPython_ShlexJoin_Sanitized(t *testing.T) {
	code := `
import os
import shlex
from flask import request

def handler():
    name = request.args.get("name")
    cmd = shlex.join(["ls", name])
    os.system(cmd)
`
	flows := Analyze(code, "/app/run.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("shlex.join() should neutralize SnkCommand taint")
		}
	}
}

// Guards the ObjectType:"shlex" scoping: a plain str.join (e.g. " ".join(...))
// must NOT be treated as the shlex.join sanitizer, otherwise any joined string
// would silently clear command taint and mask real injection.
func TestPython_ShlexJoin_StrJoin_NotSanitizer(t *testing.T) {
	code := `
import os
from flask import request

def handler():
    name = request.args.get("name")
    cmd = " ".join(["ls", name])
    os.system(cmd)
`
	flows := Analyze(code, "/app/run.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("str.join() must not be mistaken for shlex.join — SnkCommand flow should still fire")
	}
}
