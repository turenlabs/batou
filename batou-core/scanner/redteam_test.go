package scanner_test

import (
	"fmt"
	"strings"
	"testing"
	"github.com/turenlabs/batou-core/testutil"
	// Register all rule packages.
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/memory"
	// Taint analysis.
	_ "github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
)

// helper: check if any finding matches rule prefix or category keyword
func hasAnyFinding(result *testutil.ScanResult, keywords ...string) bool {
	for _, f := range result.Findings {
		for _, kw := range keywords {
			if strings.Contains(f.RuleID, kw) || strings.Contains(strings.ToLower(f.Description), strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

func redteamRuleIDs(result *testutil.ScanResult) []string {
	return testutil.FindingRuleIDs(result)
}

// =========================================================================
// 1. UNICODE IDENTIFIER EVASION
// =========================================================================

func TestRedTeam_UnicodeEval_Python(t *testing.T) {
	// Use Cyrillic 'а' (U+0430) instead of Latin 'a' in 'eval'
	code := `import os
user_input = input()
ev\u0430l(user_input)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: Unicode eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Unicode ev\u0430l() evaded detection (0 findings)")
	}
}

func TestRedTeam_UnicodeExec_Python(t *testing.T) {
	// Use Cyrillic 'е' (U+0435) instead of Latin 'e' in 'exec'
	code := `user_input = input()
\u0435xec(user_input)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "exec") {
		t.Logf("CAUGHT: Unicode exec detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Unicode \u0435xec() evaded detection (0 findings)")
	}
}

func TestRedTeam_UnicodeSQL_Python(t *testing.T) {
	// Use Cyrillic 'Ѕ' (U+0405) instead of Latin 'S' in 'SELECT'
	code := `import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input()
cursor.execute(f"\u0405ELECT * FROM users WHERE id = {user_id}")
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Unicode SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Unicode ЅELECT evaded SQL injection detection (0 findings)")
	}
}

// =========================================================================
// 2. STRING SPLITTING / MULTI-LINE CONCAT
// =========================================================================

func TestRedTeam_MultiLineSQL_Python(t *testing.T) {
	// SQL built across multiple lines - no SQL keyword on concat line
	code := `import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input()
q = "SELECT * "
q += "FROM users "
q += "WHERE id=" + user_id
cursor.execute(q)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Multi-line SQL concat detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Multi-line SQL string building evaded detection (0 findings)")
	}
}

func TestRedTeam_MultiLineSQL_JS(t *testing.T) {
	// Same pattern in JavaScript
	code := `const express = require('express');
const db = require('./db');
app.get('/users', (req, res) => {
  let q = "SELECT * ";
  q += "FROM users ";
  q += "WHERE id=" + req.params.id;
  db.query(q);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Multi-line JS SQL concat detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Multi-line JS SQL string building evaded detection (0 findings)")
	}
}

func TestRedTeam_MultiLineSQL_Go(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "connstr")
	id := r.URL.Query().Get("id")
	q := "SELECT * "
	q += "FROM users "
	q += "WHERE id=" + id
	db.Query(q)
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Multi-line Go SQL concat detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Multi-line Go SQL string building evaded detection (0 findings)")
	}
}

// =========================================================================
// 3. ALIASED IMPORTS
// =========================================================================

func TestRedTeam_AliasedSubprocess_Python(t *testing.T) {
	code := `import subprocess as sp
user_cmd = input()
sp.call(user_cmd, shell=True)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "subprocess") {
		t.Logf("CAUGHT: Aliased subprocess detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: 'import subprocess as sp' evaded detection (0 findings)")
	}
}

func TestRedTeam_AliasedOs_Python(t *testing.T) {
	code := `import os as operating_system
user_cmd = input()
operating_system.system(user_cmd)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "system") {
		t.Logf("CAUGHT: Aliased os.system detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: 'import os as operating_system' evaded detection (0 findings)")
	}
}

func TestRedTeam_AliasedExec_Go(t *testing.T) {
	code := `package main

import (
	osExec "os/exec"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	osExec.Command("bash", "-c", cmd).Run()
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "exec") {
		t.Logf("CAUGHT: Go aliased exec detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Go aliased import 'osExec' evaded detection (0 findings)")
	}
}

func TestRedTeam_FromImport_Python(t *testing.T) {
	// from os import system
	code := `from os import system
user_cmd = input()
system(user_cmd)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "system") {
		t.Logf("CAUGHT: from-import system detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: 'from os import system' -> system() evaded detection (0 findings)")
	}
}

// =========================================================================
// 4. INDIRECT CALLS VIA VARIABLES
// =========================================================================

func TestRedTeam_IndirectEval_JS(t *testing.T) {
	code := `const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const fn = eval;
  fn(req.query.code);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: Indirect eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: const fn = eval; fn() evaded detection (0 findings)")
	}
}

func TestRedTeam_GetattrEval_Python(t *testing.T) {
	code := `user_input = input()
danger = getattr(__builtins__, 'eval')
danger(user_input)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval", "getattr") {
		t.Logf("CAUGHT: getattr eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: getattr(__builtins__, 'eval') evaded detection (0 findings)")
	}
}

func TestRedTeam_BracketsEval_Python(t *testing.T) {
	code := `user_input = input()
__builtins__['eval'](user_input)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: __builtins__['eval'] detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: __builtins__['eval']() evaded detection (0 findings)")
	}
}

func TestRedTeam_IndirectExecCommand_Go(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	runCmd := exec.Command
	runCmd("bash", "-c", cmd).Run()
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "exec") {
		t.Logf("CAUGHT: Indirect exec.Command detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: runCmd := exec.Command; runCmd() evaded detection (0 findings)")
	}
}

// =========================================================================
// 5. TEMPLATE LITERAL NESTING
// =========================================================================

func TestRedTeam_TemplateLiteralSQL_JS(t *testing.T) {
	code := `const express = require('express');
const db = require('./db');
app.get('/users', (req, res) => {
  const query = ` + "`SELECT * FROM users WHERE id = ${req.params.id}`" + `;
  db.query(query);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Template literal SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Template literal SQL evaded detection (0 findings)")
	}
}

func TestRedTeam_NestedTemplateLiteral_JS(t *testing.T) {
	// Nested template literal - the interpolation is inside a nested template
	code := `const express = require('express');
const db = require('./db');
app.get('/users', (req, res) => {
  const id = req.params.id;
  const clause = ` + "`WHERE id = ${id}`" + `;
  const query = ` + "`SELECT * FROM users ${clause}`" + `;
  db.query(query);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Nested template literal SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Nested template literal SQL evaded detection (0 findings)")
	}
}

// =========================================================================
// 6. ENCODING / DECODE TRICKS
// =========================================================================

func TestRedTeam_EncodeDecodeCmd_Python(t *testing.T) {
	code := `import os
user_input = input()
cmd = user_input.encode('utf-8')
os.system(cmd.decode())
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "system") {
		t.Logf("CAUGHT: Encode/decode trick detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: encode/decode cmd injection evaded detection (0 findings)")
	}
}

func TestRedTeam_Base64Eval_Python(t *testing.T) {
	code := `import base64
user_input = input()
encoded = base64.b64encode(user_input.encode())
eval(base64.b64decode(encoded).decode())
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: base64 eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: base64 encode/decode eval evaded detection (0 findings)")
	}
}

func TestRedTeam_BytesConcat_Python(t *testing.T) {
	code := `import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input()
query = b"SELECT * FROM users WHERE id=" + user_id.encode()
cursor.execute(query.decode())
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Bytes concat SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: bytes concat SQL injection evaded detection (0 findings)")
	}
}

// =========================================================================
// 7. DECORATOR / WRAPPER EVASION
// =========================================================================

func TestRedTeam_FlaskEval_Python(t *testing.T) {
	// Standard Flask eval - should be caught
	code := `from flask import Flask, request
app = Flask(__name__)

@app.route('/api')
def handler():
    return eval(request.args.get('code'))
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: Flask eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Flask eval evaded detection (0 findings)")
	}
}

func TestRedTeam_CustomDecoratorEval_Python(t *testing.T) {
	// Same vuln but with custom decorator instead of @app.route
	code := `from flask import request

def make_handler(fn):
    return fn

@make_handler
def handler():
    return eval(request.args.get('code'))
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: Custom decorator eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Custom decorator eval evaded detection (0 findings)")
	}
}

func TestRedTeam_LambdaEval_Python(t *testing.T) {
	code := `from flask import request
handler = lambda: eval(request.args.get('code'))
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: Lambda eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Lambda eval evaded detection (0 findings)")
	}
}

// =========================================================================
// 8. CROSS-FUNCTION / MULTI-STEP
// =========================================================================

func TestRedTeam_CrossFunctionSQL_Go(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func getQuery(id string) string {
	return "SELECT * FROM users WHERE id = " + id
}

func handler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "connstr")
	db.Query(getQuery(r.URL.Query().Get("id")))
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Cross-function SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Cross-function SQL injection evaded detection (0 findings)")
	}
}

func TestRedTeam_CrossFunctionCmd_Python(t *testing.T) {
	code := `import os

def run_command(cmd):
    os.system(cmd)

user_input = input()
run_command(user_input)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "system") {
		t.Logf("CAUGHT: Cross-function cmd detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Cross-function cmd injection evaded detection (0 findings)")
	}
}

func TestRedTeam_DoubleIndirection_Python(t *testing.T) {
	// Two levels of function indirection
	code := `import sqlite3

def build_query(user_id):
    return "SELECT * FROM users WHERE id = " + user_id

def execute_query(query):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)

user_id = input()
q = build_query(user_id)
execute_query(q)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Double indirection SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Double function indirection SQL injection evaded detection (0 findings)")
	}
}

// =========================================================================
// 9. STRING MANIPULATION EVASION
// =========================================================================

func TestRedTeam_JoinSQL_Python(t *testing.T) {
	// Build SQL using str.join()
	code := `import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input()
parts = ["SELECT * FROM users WHERE id=", user_id]
query = "".join(parts)
cursor.execute(query)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: str.join SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: str.join() SQL building evaded detection (0 findings)")
	}
}

func TestRedTeam_ArrayJoinSQL_JS(t *testing.T) {
	code := `const db = require('./db');
const express = require('express');
app.get('/users', (req, res) => {
  const parts = ["SELECT * FROM users WHERE id=", req.params.id];
  const query = parts.join("");
  db.query(query);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: Array.join SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Array.join() SQL building evaded detection (0 findings)")
	}
}

func TestRedTeam_FormatMapSQL_Python(t *testing.T) {
	code := `import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input()
query = "SELECT * FROM users WHERE id = {uid}".format_map({"uid": user_id})
cursor.execute(query)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: format_map SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: format_map() SQL building evaded detection (0 findings)")
	}
}

func TestRedTeam_ReplaceSQL_Python(t *testing.T) {
	code := `import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input()
query = "SELECT * FROM users WHERE id = PLACEHOLDER".replace("PLACEHOLDER", user_id)
cursor.execute(query)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: str.replace SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: str.replace() SQL building evaded detection (0 findings)")
	}
}

// =========================================================================
// 10. CONDITIONAL / TERNARY EVASION
// =========================================================================

func TestRedTeam_TernaryEval_JS(t *testing.T) {
	code := `const express = require('express');
app.get('/run', (req, res) => {
  const code = req.query.code;
  const result = code ? eval(code) : null;
  res.send(result);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: Ternary eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Ternary eval evaded detection (0 findings)")
	}
}

// =========================================================================
// 11. GLOBAL/LOCALS DICT ACCESS
// =========================================================================

func TestRedTeam_GlobalsEval_Python(t *testing.T) {
	code := `user_input = input()
globals()['ev' + 'al'](user_input)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "eval") {
		t.Logf("CAUGHT: globals() eval detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: globals()['ev'+'al']() evaded detection (0 findings)")
	}
}

func TestRedTeam_CompileExec_Python(t *testing.T) {
	code := `user_input = input()
code_obj = compile(user_input, '<string>', 'exec')
exec(code_obj)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "TAINT", "exec", "compile") {
		t.Logf("CAUGHT: compile+exec detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: compile()+exec() evaded detection (0 findings)")
	}
}

// =========================================================================
// 12. REFLECT / DYNAMIC DISPATCH (Go)
// =========================================================================

func TestRedTeam_ReflectCall_Go(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
	"reflect"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	fn := reflect.ValueOf(exec.Command)
	result := fn.Call([]reflect.Value{
		reflect.ValueOf("bash"),
		reflect.ValueOf("-c"),
		reflect.ValueOf(cmd),
	})
	_ = result
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "exec", "reflect") {
		t.Logf("CAUGHT: Reflect exec.Command detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: reflect.ValueOf(exec.Command).Call() evaded detection (0 findings)")
	}
}

// =========================================================================
// 13. DESERIALIZATION TRICKS
// =========================================================================

func TestRedTeam_PickleLoads_Python(t *testing.T) {
	code := `import pickle
from flask import request

@app.route('/load')
def load():
    data = request.data
    obj = pickle.loads(data)
    return str(obj)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "DESER", "TAINT", "pickle") {
		t.Logf("CAUGHT: Pickle deserialization detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: pickle.loads(request.data) evaded detection (0 findings)")
	}
}

func TestRedTeam_YAMLUnsafe_Python(t *testing.T) {
	code := `import yaml
from flask import request

@app.route('/parse')
def parse():
    data = request.data
    result = yaml.load(data, Loader=yaml.Loader)
    return str(result)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "DESER", "TAINT", "yaml") {
		t.Logf("CAUGHT: Unsafe YAML load detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: yaml.load(data, Loader=yaml.Loader) evaded detection (0 findings)")
	}
}

// =========================================================================
// 14. SSRF VIA VARIABLE INDIRECTION
// =========================================================================

func TestRedTeam_SSRFIndirect_Python(t *testing.T) {
	code := `import requests
from flask import request

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    target = url
    resp = requests.get(target)
    return resp.text
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "SSRF", "TAINT") {
		t.Logf("CAUGHT: SSRF via variable indirection detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: SSRF via variable indirection evaded detection (0 findings)")
	}
}

func TestRedTeam_SSRFFormatString_Go(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	url := fmt.Sprintf("http://%s/api/data", host)
	resp, _ := http.Get(url)
	defer resp.Body.Close()
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "SSRF", "TAINT") {
		t.Logf("CAUGHT: SSRF via fmt.Sprintf detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: SSRF via fmt.Sprintf URL construction evaded detection (0 findings)")
	}
}

// =========================================================================
// 15. PROTOTYPE POLLUTION / PROPERTY ACCESS
// =========================================================================

func TestRedTeam_DynamicPropertyAccess_JS(t *testing.T) {
	code := `const express = require('express');
app.post('/update', (req, res) => {
  const key = req.body.key;
  const val = req.body.value;
  const obj = {};
  obj[key] = val;
  res.json(obj);
});
`
	result := testutil.ScanContent(t, "/app/handler.js", code)
	if hasAnyFinding(result, "PROTO", "MASS", "TAINT") {
		t.Logf("CAUGHT: Dynamic property access detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Dynamic property access evaded detection (0 findings)")
	}
}

// =========================================================================
// 16. PATH TRAVERSAL VIA VARIABLE
// =========================================================================

func TestRedTeam_PathTraversalIndirect_Go(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	path := "/uploads/" + filename
	data, _ := os.ReadFile(path)
	w.Write(data)
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "TRAV", "PATH", "TAINT") {
		t.Logf("CAUGHT: Path traversal detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Path traversal via concat evaded detection (0 findings)")
	}
}

// =========================================================================
// 17. OPEN REDIRECT
// =========================================================================

func TestRedTeam_OpenRedirect_Go(t *testing.T) {
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "REDIRECT", "TAINT", "SSRF") {
		t.Logf("CAUGHT: Open redirect detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Open redirect evaded detection (0 findings)")
	}
}

// =========================================================================
// 18. STRING BUILDER / BUFFER
// =========================================================================

func TestRedTeam_StringBuilderSQL_Go(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "connstr")
	id := r.URL.Query().Get("id")
	var b strings.Builder
	b.WriteString("SELECT * FROM users WHERE id = ")
	b.WriteString(id)
	db.Query(b.String())
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: strings.Builder SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: strings.Builder SQL injection evaded detection (0 findings)")
	}
}

func TestRedTeam_StringBuilderSQL_Java(t *testing.T) {
	code := `import java.sql.*;
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String id = request.getParameter("id");
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM users WHERE id = ");
        sb.append(id);
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sb.toString());
    }
}
`
	result := testutil.ScanContent(t, "/app/Handler.java", code)
	if hasAnyFinding(result, "INJ", "SQL", "TAINT") {
		t.Logf("CAUGHT: StringBuilder SQL detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: StringBuilder SQL injection evaded detection (0 findings)")
	}
}

// =========================================================================
// 19. IMPORT STAR / WILDCARD IMPORTS
// =========================================================================

func TestRedTeam_ImportStarOS_Python(t *testing.T) {
	code := `from os import *
user_cmd = input()
system(user_cmd)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT") {
		t.Logf("CAUGHT: import * system detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: from os import * -> system() evaded detection (0 findings)")
	}
}

// =========================================================================
// 20. SUBPROCESS WITH LIST (shell=True hidden)
// =========================================================================

func TestRedTeam_SubprocessShellHidden_Python(t *testing.T) {
	// shell=True buried in kwargs
	code := `import subprocess
user_cmd = input()
kwargs = {"shell": True}
subprocess.call(user_cmd, **kwargs)
`
	result := testutil.ScanContent(t, "/app/handler.py", code)
	if hasAnyFinding(result, "INJ", "CMD", "TAINT", "subprocess") {
		t.Logf("CAUGHT: hidden shell=True detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: subprocess.call with **kwargs shell=True evaded detection (0 findings)")
	}
}

// =========================================================================
// 21. HEADER INJECTION VIA INTERMEDIATE VAR
// =========================================================================

func TestRedTeam_HeaderInjection_Go(t *testing.T) {
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	val := r.URL.Query().Get("redirect")
	w.Header().Set("Location", val)
	w.WriteHeader(302)
}
`
	result := testutil.ScanContent(t, "/app/handler.go", code)
	if hasAnyFinding(result, "INJ", "HEADER", "TAINT") {
		t.Logf("CAUGHT: Header injection detected, rules: %v", redteamRuleIDs(result))
	} else {
		t.Logf("BYPASS: Header injection via intermediate variable evaded detection (0 findings)")
	}
}

// =========================================================================
// SUMMARY TEST - prints overall results
// =========================================================================

func TestRedTeam_Summary(t *testing.T) {
	t.Log("=== RED TEAM EVASION TEST SUMMARY ===")
	t.Log("Run individual tests above for detailed results")
	t.Log("Look for 'BYPASS' in test output to find successful evasions")

	type testCase struct {
		name     string
		filePath string
		code     string
		keywords []string
	}

	cases := []testCase{
		{"Unicode eval (Python)", "/app/handler.py", "user_input = input()\nev\u0430l(user_input)\n", []string{"INJ", "TAINT", "eval"}},
		{"Unicode exec (Python)", "/app/handler.py", "user_input = input()\n\u0435xec(user_input)\n", []string{"INJ", "TAINT", "exec"}},
		{"Multi-line SQL concat (Python)", "/app/handler.py", "import sqlite3\nconn = sqlite3.connect('test.db')\ncursor = conn.cursor()\nuser_id = input()\nq = \"SELECT * \"\nq += \"FROM users \"\nq += \"WHERE id=\" + user_id\ncursor.execute(q)\n", []string{"INJ", "SQL", "TAINT"}},
		{"Aliased subprocess (Python)", "/app/handler.py", "import subprocess as sp\nuser_cmd = input()\nsp.call(user_cmd, shell=True)\n", []string{"INJ", "CMD", "TAINT"}},
		{"Aliased os (Python)", "/app/handler.py", "import os as operating_system\nuser_cmd = input()\noperating_system.system(user_cmd)\n", []string{"INJ", "CMD", "TAINT"}},
		{"from os import system (Python)", "/app/handler.py", "from os import system\nuser_cmd = input()\nsystem(user_cmd)\n", []string{"INJ", "CMD", "TAINT"}},
		{"Indirect eval (JS)", "/app/handler.js", "const express = require('express');\napp.get('/run', (req, res) => {\n  const fn = eval;\n  fn(req.query.code);\n});\n", []string{"INJ", "TAINT", "eval"}},
		{"getattr eval (Python)", "/app/handler.py", "user_input = input()\ndanger = getattr(__builtins__, 'eval')\ndanger(user_input)\n", []string{"INJ", "TAINT", "eval"}},
		{"globals()['eval'] (Python)", "/app/handler.py", "user_input = input()\nglobals()['ev' + 'al'](user_input)\n", []string{"INJ", "TAINT", "eval"}},
		{"str.join SQL (Python)", "/app/handler.py", "import sqlite3\nconn = sqlite3.connect('test.db')\ncursor = conn.cursor()\nuser_id = input()\nparts = [\"SELECT * FROM users WHERE id=\", user_id]\nquery = \"\".join(parts)\ncursor.execute(query)\n", []string{"INJ", "SQL", "TAINT"}},
		{"str.replace SQL (Python)", "/app/handler.py", "import sqlite3\nconn = sqlite3.connect('test.db')\ncursor = conn.cursor()\nuser_id = input()\nquery = \"SELECT * FROM users WHERE id = PLACEHOLDER\".replace(\"PLACEHOLDER\", user_id)\ncursor.execute(query)\n", []string{"INJ", "SQL", "TAINT"}},
		{"format_map SQL (Python)", "/app/handler.py", "import sqlite3\nconn = sqlite3.connect('test.db')\ncursor = conn.cursor()\nuser_id = input()\nquery = \"SELECT * FROM users WHERE id = {uid}\".format_map({\"uid\": user_id})\ncursor.execute(query)\n", []string{"INJ", "SQL", "TAINT"}},
		{"subprocess **kwargs (Python)", "/app/handler.py", "import subprocess\nuser_cmd = input()\nkwargs = {\"shell\": True}\nsubprocess.call(user_cmd, **kwargs)\n", []string{"INJ", "CMD", "TAINT"}},
		{"strings.Builder SQL (Go)", "/app/handler.go", "package main\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n\t\"strings\"\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tdb, _ := sql.Open(\"postgres\", \"connstr\")\n\tid := r.URL.Query().Get(\"id\")\n\tvar b strings.Builder\n\tb.WriteString(\"SELECT * FROM users WHERE id = \")\n\tb.WriteString(id)\n\tdb.Query(b.String())\n}\n", []string{"INJ", "SQL", "TAINT"}},
		{"reflect exec.Command (Go)", "/app/handler.go", "package main\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n\t\"reflect\"\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tcmd := r.URL.Query().Get(\"cmd\")\n\tfn := reflect.ValueOf(exec.Command)\n\tresult := fn.Call([]reflect.Value{\n\t\treflect.ValueOf(\"bash\"),\n\t\treflect.ValueOf(\"-c\"),\n\t\treflect.ValueOf(cmd),\n\t})\n\t_ = result\n}\n", []string{"INJ", "CMD", "TAINT", "exec", "reflect"}},
		{"__builtins__['eval'] (Python)", "/app/handler.py", "user_input = input()\n__builtins__['eval'](user_input)\n", []string{"INJ", "TAINT", "eval"}},
		{"compile+exec (Python)", "/app/handler.py", "user_input = input()\ncode_obj = compile(user_input, '<string>', 'exec')\nexec(code_obj)\n", []string{"INJ", "TAINT", "exec", "compile"}},
	}

	bypasses := 0
	caught := 0
	for _, tc := range cases {
		result := testutil.ScanContent(t, tc.filePath, tc.code)
		found := hasAnyFinding(result, tc.keywords...)
		status := "CAUGHT"
		if !found {
			status = "BYPASS"
			bypasses++
		} else {
			caught++
		}
		t.Logf("  [%s] %s (findings: %d, rules: %v)", status, tc.name, testutil.CountFindings(result), redteamRuleIDs(result))
	}

	t.Logf("\n=== TOTALS: %d caught, %d bypasses out of %d tests ===", caught, bypasses, len(cases))
	if bypasses > 0 {
		t.Logf("WARNING: %d evasion vectors succeeded!", bypasses)
	}

	// Print detailed findings for debugging
	for _, tc := range cases {
		result := testutil.ScanContent(t, tc.filePath, tc.code)
		if testutil.CountFindings(result) > 0 {
			t.Logf("\n--- %s ---", tc.name)
			for _, f := range result.Findings {
				t.Logf("  Rule: %s, Line: %d, Severity: %v, Confidence: %.2f, Desc: %s",
					f.RuleID, f.LineNumber, f.Severity, f.ConfidenceScore,
					fmt.Sprintf("%.80s", f.Description))
			}
		}
	}
}
