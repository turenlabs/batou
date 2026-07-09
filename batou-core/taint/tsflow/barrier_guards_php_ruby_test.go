package tsflow

// Precision tests for the PHP / Ruby extension of the BARRIER-GUARD
// flow-sensitivity mechanism (barrier-guard follow-up). Each language gets
// the canonical four-case proof:
//   1. guarded use   → SILENT  (the guard sanitizes the validated variable)
//   2. unguarded use → FIRES   (no guard, taint reaches the sink)
//   3. wrong-var     → FIRES   (guard validates a DIFFERENT variable)
//   4. loose regex   → FIRES   (a non-charset / unanchored regex proves nothing)
// plus the language-specific charset/numeric idioms.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

func TestBG_PHP_CtypeDigit_Guarded_Silent(t *testing.T) {
	code := `<?php
function handler($db) {
    $id = $_GET["id"];
    if (ctype_digit($id)) {
        $db->query("SELECT * FROM t WHERE id=" . $id);
    }
}
?>`
	if bgHasSQL(Analyze(code, "/app/h.php", rules.LangPHP)) {
		t.Error("PHP ctype_digit() charset guard should be SILENT")
	}
}

func TestBG_PHP_Unguarded_Fires(t *testing.T) {
	code := `<?php
function handler($db) {
    $id = $_GET["id"];
    $db->query("SELECT * FROM t WHERE id=" . $id);
}
?>`
	if !bgHasSQL(Analyze(code, "/app/h.php", rules.LangPHP)) {
		t.Error("PHP unguarded use MUST fire")
	}
}

func TestBG_PHP_WrongVar_Fires(t *testing.T) {
	code := `<?php
function handler($db) {
    $id = $_GET["id"];
    $other = $_GET["other"];
    if (ctype_digit($other)) {
        $db->query("SELECT * FROM t WHERE id=" . $id);
    }
}
?>`
	if !bgHasSQL(Analyze(code, "/app/h.php", rules.LangPHP)) {
		t.Error("PHP guard on different var MUST still fire on tainted $id")
	}
}

func TestBG_PHP_PregMatch_Guarded_Silent(t *testing.T) {
	code := `<?php
function handler($db) {
    $id = $_GET["id"];
    if (preg_match("/^[0-9]+$/", $id)) {
        $db->query("SELECT * FROM t WHERE id=" . $id);
    }
}
?>`
	if bgHasSQL(Analyze(code, "/app/h.php", rules.LangPHP)) {
		t.Error("PHP preg_match strict-charset guard should be SILENT")
	}
}

// Unit: the barrier-guard charset proof correctly REJECTS a loose / unanchored
// preg_match pattern (so the barrier guard itself sanitizes NOTHING). We assert
// this at the matcher level rather than the whole-pipeline level because PHP's
// PRE-EXISTING detectAllowlistCheck mechanism (allowlist.go isPHPGuardFunctionName)
// already wholesale-suppresses any positive `preg_match()` guard regardless of
// charset — so a pipeline-level "loose regex fires" assertion would be testing
// that legacy mechanism, not this one. The recall-relevant property of THIS
// change — that the strict charset proof never EXPANDS suppression beyond the
// safe-charset categories — is proved by TestBG_PHP_CtypeGuard_PreservesDeser.
func TestBG_PHP_PregMatch_CharsetProof_RejectsLoose(t *testing.T) {
	// preg_match patterns are JS-".test()"-semantics: unanchored / metachar
	// patterns must NOT be accepted as a safe-charset constraint.
	reject := []string{"id=.*", "[0-9]+" /* unanchored */, "^.*$", `^[a-z;']+$`}
	for _, p := range reject {
		if regexConstrainsToSafeCharset(p, "test") {
			t.Errorf("loose/unanchored preg_match body %q must be REJECTED by charset proof", p)
		}
	}
	accept := []string{"^[0-9]+$", `^\d+$`, "^[A-Za-z0-9_-]+$"}
	for _, p := range accept {
		if !regexConstrainsToSafeCharset(p, "test") {
			t.Errorf("strict preg_match body %q must be ACCEPTED by charset proof", p)
		}
	}
}

// RECALL: a ctype/charset guard is category-scoped — it sanitizes only the
// safe-charset injection categories, NEVER deserialization (a numeric string is
// still a valid serialized gadget payload). The pre-existing wholesale allowlist
// would DELETE the variable and silence this flow; the category-scoped barrier
// guard (which runs first and returns) preserves it. This is a recall FIX.
func TestBG_PHP_CtypeGuard_PreservesDeser(t *testing.T) {
	code := `<?php
function handler() {
    $blob = $_GET["blob"];
    if (ctype_digit($blob)) {
        $obj = unserialize($blob);
    }
}
?>`
	if !bgHasCat(Analyze(code, "/app/h.php", rules.LangPHP), taint.SnkDeserialize) {
		t.Error("ctype_digit guard MUST NOT sanitize deserialize — flow must still fire")
	}
}

func TestBG_PHP_IsNumeric_Guarded_Silent(t *testing.T) {
	code := `<?php
function handler($db) {
    $id = $_GET["id"];
    if (is_numeric($id)) {
        $db->query("SELECT * FROM t WHERE id=" . $id);
    }
}
?>`
	if bgHasSQL(Analyze(code, "/app/h.php", rules.LangPHP)) {
		t.Error("PHP is_numeric() guard should be SILENT")
	}
}

func TestBG_PHP_CtypeAlnum_Command_Silent(t *testing.T) {
	code := `<?php
function handler() {
    $cmd = $_GET["cmd"];
    if (ctype_alnum($cmd)) {
        system("tool " . $cmd);
    }
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if bgHasCat(flows, taint.SnkCommand) {
		t.Error("PHP ctype_alnum guard should sanitize COMMAND category")
	}
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

func TestBG_Ruby_Match_Guarded_Silent(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  if id.match?(/\A[0-9]+\z/)
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby match?(/\\A[0-9]+\\z/) guard should be SILENT")
	}
}

func TestBG_Ruby_Unguarded_Fires(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  db.execute("SELECT * FROM t WHERE id=#{id}")
end
`
	if !bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby unguarded use MUST fire")
	}
}

func TestBG_Ruby_WrongVar_Fires(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  other = params[:other]
  if other.match?(/\A[0-9]+\z/)
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if !bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby guard on different var MUST still fire on tainted id")
	}
}

func TestBG_Ruby_LooseRegex_Fires(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  if id.match?(/id=.*/)
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if !bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby loose regex MUST still fire")
	}
}

// Unanchored Ruby regex (no \A...\z) proves only CONTAINS — MUST fire.
func TestBG_Ruby_Unanchored_Fires(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  if id.match?(/[0-9]+/)
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if !bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby unanchored regex MUST still fire")
	}
}

func TestBG_Ruby_MatchOp_Guarded_Silent(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  if id =~ /\A\d+\z/
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby =~ strict-charset match op should be SILENT")
	}
}

func TestBG_Ruby_IntegerCoerce_Guarded_Silent(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  if Integer(id) > 0
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby Integer(id) coercion guard should be SILENT")
	}
}

func TestBG_Ruby_ToI_Comparison_Guarded_Silent(t *testing.T) {
	code := `
def search(params, db)
  id = params[:id]
  if id.to_i > 0
    db.execute("SELECT * FROM t WHERE id=#{id}")
  end
end
`
	if bgHasSQL(Analyze(code, "/app/s.rb", rules.LangRuby)) {
		t.Error("Ruby id.to_i > 0 numeric comparison guard should be SILENT")
	}
}

// RECALL: a Ruby match?/charset guard is category-scoped — it must NOT
// sanitize deserialization. A `\A\d+\z` constraint on the value does not make
// Marshal.load safe (a numeric string is a valid gadget payload). Flow must
// still fire.
func TestBG_Ruby_MatchGuard_PreservesDeser(t *testing.T) {
	code := `
def search(params)
  blob = params[:blob]
  if blob.match?(/\A[0-9]+\z/)
    obj = Marshal.load(blob)
  end
end
`
	if !bgHasCat(Analyze(code, "/app/s.rb", rules.LangRuby), taint.SnkDeserialize) {
		t.Error("Ruby match? guard MUST NOT sanitize deserialize — flow must still fire")
	}
}

func TestBG_Ruby_Match_Command_Silent(t *testing.T) {
	code := `
def run(params)
  cmd = params[:cmd]
  if cmd.match?(/\A[a-zA-Z0-9_]+\z/)
    system("tool #{cmd}")
  end
end
`
	flows := Analyze(code, "/app/s.rb", rules.LangRuby)
	if bgHasCat(flows, taint.SnkCommand) {
		t.Error("Ruby alphanumeric match? guard should sanitize COMMAND category")
	}
}

// ---------------------------------------------------------------------------
// Unit: Ruby regex-literal body extraction + PHP delimiter unwrap
// ---------------------------------------------------------------------------

func TestBG_PHP_DelimiterUnwrap(t *testing.T) {
	cases := map[string]string{
		`/^[0-9]+$/`: "^[0-9]+$",
		`#^\d+$#`:    `^\d+$`,
		`~^[a-z]+$~`: "^[a-z]+$",
		`{^[0-9]+$}`: "^[0-9]+$",
	}
	for in, want := range cases {
		if got := unwrapPHPRegexDelimiters(in); got != want {
			t.Errorf("unwrapPHPRegexDelimiters(%q) = %q, want %q", in, got, want)
		}
	}
	// Case-insensitive / multiline modifiers fail closed.
	for _, in := range []string{`/^[0-9]+$/i`, `/^a+$/m`, `nodelim`, ``} {
		if got := unwrapPHPRegexDelimiters(in); got != "" {
			t.Errorf("unwrapPHPRegexDelimiters(%q) = %q, want \"\" (fail closed)", in, got)
		}
	}
}
