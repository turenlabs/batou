package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP file-inclusion (LFI/RFI, CWE-98) sink tests.
//
// `include`/`require`/`include_once`/`require_once` are PHP language
// constructs that tree-sitter-php parses as dedicated *_expression nodes
// (include_expression, require_expression, ...), NOT function_call_expression.
// The generic call-sink path therefore never reached them and the catalog
// php.include / php.require sinks were dead in the dataflow engine (matched
// only via the Layer-1 regex tier). processPHPIncludeSink routes these
// constructs as CWE-98 sinks. This is the bWAPP rlfi.php shape:
//   $language = $_GET["language"]; include($language);
// =========================================================================

// include($p) where $p derives from $_GET — the canonical RFI/LFI flow.
func TestPHP_Include_TaintedVariable(t *testing.T) {
	code := `<?php
function load_lang() {
    $language = $_GET["language"];
    include($language);
}
?>`
	flows := Analyze(code, "/app/rlfi.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("expected file-inclusion (CWE-98) flow for $_GET -> include($language)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// require $p — the no-parens statement form parses as require_expression with a
// direct child (no parenthesized_expression wrapper).
func TestPHP_Require_NoParens(t *testing.T) {
	code := `<?php
function boot() {
    $tpl = $_REQUEST["tpl"];
    require $tpl;
}
?>`
	flows := Analyze(code, "/app/boot.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("expected CWE-98 flow for $_REQUEST -> require $tpl")
	}
}

// include_once / require_once also route.
func TestPHP_IncludeOnce_Tainted(t *testing.T) {
	code := `<?php
function load() {
    $m = $_POST["module"];
    include_once($m);
}
?>`
	flows := Analyze(code, "/app/load.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("expected CWE-98 flow for $_POST -> include_once")
	}
}

func TestPHP_RequireOnce_Tainted(t *testing.T) {
	code := `<?php
function load() {
    require_once($_GET["page"]);
}
?>`
	flows := Analyze(code, "/app/load.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("expected CWE-98 flow for inline $_GET -> require_once")
	}
}

// Inline superglobal directly in the include with no intervening assignment.
func TestPHP_Include_InlineSuperglobal(t *testing.T) {
	code := `<?php
include($_GET["file"]);
?>`
	flows := Analyze(code, "/app/index.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("expected CWE-98 flow for inline include($_GET['file'])")
	}
}

// ---- Safe / negative cases: must NOT produce a CWE-98 flow ----

// Hardcoded constant path is not user-controlled.
func TestPHP_Include_HardcodedPath_Safe(t *testing.T) {
	code := `<?php
include("header.php");
require_once("config.php");
?>`
	flows := Analyze(code, "/app/index.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("hardcoded include path should not produce a CWE-98 flow")
	}
}

// basename() strips the directory component — the canonical LFI mitigation;
// php.basename neutralizes SnkFileWrite, so the wrapped path stays clean.
func TestPHP_Include_BasenameSanitized_Safe(t *testing.T) {
	code := `<?php
function load_lang() {
    $language = $_GET["language"];
    include(basename($language));
}
?>`
	flows := Analyze(code, "/app/rlfi.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("basename()-wrapped include path should not produce a CWE-98 flow")
	}
}

// Allowlist guard (in_array) before the include — bWAPP rlfi.php security
// level 2. applyAllowlistClear clears the taint inside the guarded branch.
func TestPHP_Include_AllowlistGuard_Safe(t *testing.T) {
	code := `<?php
function load_lang() {
    $language = $_GET["language"];
    $available = array("lang_en.php", "lang_fr.php", "lang_nl.php");
    if (in_array($language, $available)) {
        include($language);
    }
}
?>`
	flows := Analyze(code, "/app/rlfi.php", rules.LangPHP)
	if hasTaintFlowCWE(flows, "CWE-98") {
		t.Error("in_array-allowlisted include path should not produce a CWE-98 flow")
		for _, f := range flows {
			if f.Sink.CWEID == "CWE-98" {
				t.Logf("  unexpected flow: %s -> %s line=%d", f.Source.Category, f.Sink.ID, f.SinkLine)
			}
		}
	}
}

// Sanity: ensure the resolved sink really is the file-inclusion catalog entry,
// not some collateral category.
func TestPHP_Include_SinkIdentity(t *testing.T) {
	code := `<?php
$p = $_GET["x"];
include($p);
?>`
	flows := Analyze(code, "/app/index.php", rules.LangPHP)
	var found bool
	for _, f := range flows {
		if f.Sink.CWEID == "CWE-98" && f.Sink.Category == taint.SnkFileWrite {
			found = true
		}
	}
	if !found {
		t.Error("expected a CWE-98 SnkFileWrite include sink flow")
	}
}
