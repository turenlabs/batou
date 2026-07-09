package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP sanitizer tests — redirect, header, LDAP, deserialize
// New entries added in this cycle.
// =========================================================================

// --- Redirect sanitizers ---

func TestPHP_Redirect_Sanitized_ParseUrl(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["next"];
    $parts = parse_url($url);
    header("Location: " . $parts["path"]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("parse_url() should neutralize redirect taint flow")
	}
}

func TestPHP_Redirect_Unsanitized_Direct(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["next"];
    header("Location: " . $url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	// header("Location: " . <tainted>) is an open redirect (CWE-601 /
	// SnkRedirect) — the php.header.location sink classifies it more specifically
	// than the generic CWE-113 php.header header-injection sink.
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for $_GET -> header(\"Location: \")")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redirect_Sanitized_Rawurlencode(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["next"];
    $safe = rawurlencode($url);
    redirect($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("rawurlencode() should neutralize redirect taint flow")
	}
}

func TestPHP_Redirect_Sanitized_WpValidateRedirect(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["redirect_to"];
    $safe = wp_validate_redirect($url, "/default");
    wp_redirect($safe);
    exit;
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("wp_validate_redirect() should neutralize redirect taint flow")
	}
}

// --- Header sanitizers ---

func TestPHP_Header_Sanitized_Rawurlencode(t *testing.T) {
	code := `<?php
function handler() {
    $val = $_GET["name"];
    $safe = rawurlencode($val);
    header("X-Custom: " . $safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("rawurlencode() should neutralize header injection taint flow")
	}
}

func TestPHP_Header_Unsanitized_Direct(t *testing.T) {
	code := `<?php
function handler() {
    $val = $_GET["name"];
    setcookie("user", $val);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header flow for $_GET -> setcookie")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Deserialize sink tests (verify existing sinks work) ---

func TestPHP_Deserialize_Unsanitized_Unserialize(t *testing.T) {
	code := `<?php
function handler() {
    $data = $_POST["data"];
    $obj = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for $_POST -> unserialize")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
