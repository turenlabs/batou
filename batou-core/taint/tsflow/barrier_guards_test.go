package tsflow

// Tests for language-configurable BARRIER-GUARD flow-sensitivity (depth lever
// #30): a validation check in an if-condition (strict-charset regex, numeric
// type check, numeric parse) that constrains a tainted value to a safe domain
// on the guarded path. Verifies the guarded use is SILENT, the unguarded use
// FIRES, a guard on a DIFFERENT variable does NOT sanitize the tainted one, and
// a loose regex sanitizes NOTHING (recall preservation).

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

func bgHasSQL(flows []taint.TaintFlow) bool {
	return bgHasCat(flows, taint.SnkSQLQuery)
}

func TestBG_JS_Guarded_Silent(t *testing.T) {
	code := `
function handler(req, res) {
  const id = req.query.id;
  if (/^[0-9]+$/.test(id)) {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("JS numeric-regex guarded use should be SILENT")
	}
}

func TestBG_JS_Unguarded_Fires(t *testing.T) {
	code := `
function handler(req, res) {
  const id = req.query.id;
  db.query("SELECT * FROM t WHERE id=" + id);
}
`
	if !bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("JS unguarded use MUST fire")
	}
}

func TestBG_JS_WrongVar_Fires(t *testing.T) {
	code := `
function handler(req, res) {
  const id = req.query.id;
  const other = req.query.other;
  if (/^[0-9]+$/.test(other)) {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if !bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("JS guard on different var MUST still fire on tainted id")
	}
}

func TestBG_JS_LooseRegex_Fires(t *testing.T) {
	code := `
function handler(req, res) {
  const id = req.query.id;
  if (/id=.*/.test(id)) {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if !bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("JS loose regex MUST still fire")
	}
}

func TestBG_JS_Typeof_Silent(t *testing.T) {
	code := `
function handler(req, res) {
  const id = req.query.id;
  if (typeof id === "number") {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("JS typeof number guard should be SILENT")
	}
}

func TestBG_Java_Matches_Guarded_Silent(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    if (id.matches("[A-Za-z0-9]+")) {
      Statement stmt = conn.createStatement();
      stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
  }
}
`
	if bgHasSQL(Analyze(code, "/app/H.java", rules.LangJava)) {
		t.Error("Java matches() charset guard should be SILENT")
	}
}

func TestBG_Java_Matches_Unguarded_Fires(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    Statement stmt = conn.createStatement();
    stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if !bgHasSQL(Analyze(code, "/app/H.java", rules.LangJava)) {
		t.Error("Java unguarded MUST fire")
	}
}

func TestBG_Java_WrongVar_Fires(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    String other = req.getParameter("other");
    if (other.matches("[A-Za-z0-9]+")) {
      Statement stmt = conn.createStatement();
      stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
  }
}
`
	if !bgHasSQL(Analyze(code, "/app/H.java", rules.LangJava)) {
		t.Error("Java guard on different var MUST still fire on tainted id")
	}
}

func TestBG_Java_PatternMatches_Guarded_Silent(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    if (Pattern.matches("\\d+", id)) {
      Statement stmt = conn.createStatement();
      stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
  }
}
`
	if bgHasSQL(Analyze(code, "/app/H.java", rules.LangJava)) {
		t.Error("Java Pattern.matches charset guard should be SILENT")
	}
}

func TestBG_Java_ParseInt_Guarded_Silent(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    if (Integer.parseInt(id) > 0) {
      Statement stmt = conn.createStatement();
      stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
  }
}
`
	if bgHasSQL(Analyze(code, "/app/H.java", rules.LangJava)) {
		t.Error("Java parseInt numeric guard should be SILENT")
	}
}

// Loose Java regex with a literal metacharacter must NOT sanitize.
func TestBG_Java_LooseRegex_Fires(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    if (Pattern.matches(".*", id)) {
      Statement stmt = conn.createStatement();
      stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
  }
}
`
	if !bgHasSQL(Analyze(code, "/app/H.java", rules.LangJava)) {
		t.Error("Java loose regex .* MUST still fire")
	}
}

func bgHasCat(flows []taint.TaintFlow, cat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == cat {
			return true
		}
	}
	return false
}

// Guard sanitizes COMMAND category too (charset proof covers shell metachars).
func TestBG_JS_Guard_Command_Silent(t *testing.T) {
	code := `
function h(req) {
  const cmd = req.query.cmd;
  if (/^[a-zA-Z0-9_]+$/.test(cmd)) {
    require('child_process').execSync("tool " + cmd);
  }
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if bgHasCat(flows, taint.SnkCommand) {
		t.Error("alphanumeric-charset guard should sanitize COMMAND category")
	}
}

// TS path works (inherits JS config).
func TestBG_TS_Guard_Silent(t *testing.T) {
	code := `
function h(req: any) {
  const id: string = req.query.id;
  if (/^[0-9]+$/.test(id)) {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if bgHasSQL(Analyze(code, "/app/h.ts", rules.LangTypeScript)) {
		t.Error("TS numeric-regex guard should be SILENT")
	}
}

// Unit: safeCharsetCategories must exclude crypto and deserialize.
func TestBG_SafeCategories_ExcludeCryptoDeser(t *testing.T) {
	for _, c := range safeCharsetCategories {
		if c == taint.SnkCrypto {
			t.Error("safeCharsetCategories must NOT include SnkCrypto")
		}
		if c == taint.SnkDeserialize {
			t.Error("safeCharsetCategories must NOT include SnkDeserialize")
		}
	}
}

// Unit: charset analysis rejects loose/dangerous regexes, accepts strict ones.
func TestBG_RegexCharsetAnalysis(t *testing.T) {
	safe := []string{"^[0-9]+$", "^[a-zA-Z0-9_-]+$", `^\d+$`, `^\w{1,10}$`, "^[A-Fa-f0-9]+$"}
	for _, p := range safe {
		if !regexConstrainsToSafeCharset(p, "test") {
			t.Errorf("expected SAFE regex to be accepted: %q", p)
		}
	}
	unsafe := []string{
		"[0-9]+",      // JS .test unanchored — only proves CONTAINS a digit
		"^.*$",        // any char
		"^[^a-z]+$",   // negated class
		`^[a-z;'"]+$`, // class with metachars
		"^(a|b')+$",   // alternation + quote
		`^\S+$`,       // non-whitespace = anything
		"^a.b$",       // bare dot
	}
	for _, p := range unsafe {
		if regexConstrainsToSafeCharset(p, "test") {
			t.Errorf("expected UNSAFE regex to be REJECTED: %q", p)
		}
	}
	// Java implicit-anchor: unanchored is OK because matches() anchors whole input.
	if !regexConstrainsToSafeCharset("[0-9]+", "matches") {
		t.Error("Java matches() should treat [0-9]+ as fully anchored and safe")
	}
}

// SOUNDNESS: a guard behind `||` does NOT validate the variable on all paths
// into the body (the OTHER operand can be true while the guard is false), so
// the flow MUST still fire. Recall preservation.
func TestBG_JS_GuardBehindOr_Fires(t *testing.T) {
	code := `
function h(req) {
  const id = req.query.id;
  const admin = req.query.admin;
  if (admin === "1" || /^[0-9]+$/.test(id)) {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if !bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("guard behind || MUST NOT sanitize — flow must still fire")
	}
}

// Conjunction: a guard behind `&&` DOES validate on the path into the body.
func TestBG_JS_GuardBehindAnd_Silent(t *testing.T) {
	code := `
function h(req) {
  const id = req.query.id;
  if (id != null && /^[0-9]+$/.test(id)) {
    db.query("SELECT * FROM t WHERE id=" + id);
  }
}
`
	if bgHasSQL(Analyze(code, "/app/h.js", rules.LangJavaScript)) {
		t.Error("guard behind && should sanitize — flow should be SILENT")
	}
}
