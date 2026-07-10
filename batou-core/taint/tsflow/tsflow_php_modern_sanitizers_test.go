package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP modern sanitizer tests — libsodium AEAD/MAC/sig verify, intl IDN,
// WordPress esc_xml / sanitize_html_class / sanitize_mime_type / kses filters
// / wp_check_password.
// Per-feature file (not appended to tsflow_test.go) to avoid sibling-PR
// merge conflicts.
// =========================================================================

// --- libsodium MAC / signature / AEAD verification (SnkCrypto) ---

func TestPHP_Sodium_AuthVerify_NeutralizesCrypto(t *testing.T) {
	code := `<?php
function handler() {
    $mac = $_POST["mac"];
    $verified = sodium_crypto_auth_verify($mac, $msg, $key);
    md5($verified);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_crypto_auth_verify() should neutralize SnkCrypto taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Sodium_SignVerifyDetached_NeutralizesCrypto(t *testing.T) {
	code := `<?php
function handler() {
    $sig = $_POST["sig"];
    $ok = sodium_crypto_sign_verify_detached($sig, $msg, $pubkey);
    md5($ok);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_crypto_sign_verify_detached() should neutralize SnkCrypto taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Sodium_Compare_NeutralizesCrypto(t *testing.T) {
	code := `<?php
function handler() {
    $candidate = $_POST["token"];
    $cmp = sodium_compare($candidate, $expected);
    sha1($cmp);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_compare() should neutralize SnkCrypto taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Sodium_BoxOpen_NeutralizesCrypto(t *testing.T) {
	code := `<?php
function handler() {
    $ct = $_POST["ciphertext"];
    $plain = sodium_crypto_box_open($ct, $nonce, $kp);
    md5($plain);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_crypto_box_open() should neutralize SnkCrypto taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Sodium_SecretboxOpen_NeutralizesCrypto(t *testing.T) {
	code := `<?php
function handler() {
    $ct = $_POST["ciphertext"];
    $plain = sodium_crypto_secretbox_open($ct, $nonce, $key);
    sha1($plain);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_crypto_secretbox_open() should neutralize SnkCrypto taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- intl IDN normalization (SnkURLFetch / SnkRedirect) ---

func TestPHP_Intl_IdnToAscii_NeutralizesURLFetch(t *testing.T) {
	code := `<?php
function fetch() {
    $host = $_GET["host"];
    $ascii = idn_to_ascii($host);
    file_get_contents("https://" . $ascii . "/api");
}
?>`
	flows := Analyze(code, "/app/fetch.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("idn_to_ascii() should neutralize SnkURLFetch taint flow (anti-homograph)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Intl_IdnToAscii_NeutralizesRedirect(t *testing.T) {
	code := `<?php
function go() {
    $host = $_GET["host"];
    $ascii = idn_to_ascii($host);
    header("Location: https://" . $ascii);
}
?>`
	flows := Analyze(code, "/app/go.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("idn_to_ascii() should neutralize SnkRedirect taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- WordPress sanitizer gaps ---

func TestPHP_Wordpress_EscXml_NeutralizesXSS(t *testing.T) {
	code := `<?php
function rss_item() {
    $title = $_GET["title"];
    $safe = esc_xml($title);
    echo "<title>" . $safe . "</title>";
}
?>`
	flows := Analyze(code, "/app/rss.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("esc_xml() should neutralize SnkHTMLOutput taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Wordpress_SanitizeHtmlClass_NeutralizesXSS(t *testing.T) {
	code := `<?php
function render() {
    $cls = $_GET["cls"];
    $safe = sanitize_html_class($cls);
    echo "<div class='" . $safe . "'>x</div>";
}
?>`
	flows := Analyze(code, "/app/render.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("sanitize_html_class() should neutralize SnkHTMLOutput taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Wordpress_SanitizeMimeType_NeutralizesHeader(t *testing.T) {
	code := `<?php
function serve() {
    $mime = $_GET["mime"];
    $safe = sanitize_mime_type($mime);
    header("Content-Type: " . $safe);
}
?>`
	flows := Analyze(code, "/app/serve.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("sanitize_mime_type() should neutralize SnkHeader taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Wordpress_WpFilterNohtmlKses_NeutralizesXSS(t *testing.T) {
	code := `<?php
function comment() {
    $body = $_POST["body"];
    $safe = wp_filter_nohtml_kses($body);
    echo $safe;
}
?>`
	flows := Analyze(code, "/app/comment.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("wp_filter_nohtml_kses() should neutralize SnkHTMLOutput taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Wordpress_WpFilterPostKses_NeutralizesXSS(t *testing.T) {
	code := `<?php
function post() {
    $content = $_POST["content"];
    $safe = wp_filter_post_kses($content);
    echo $safe;
}
?>`
	flows := Analyze(code, "/app/post.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("wp_filter_post_kses() should neutralize SnkHTMLOutput taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Wordpress_WpCheckPassword_NeutralizesCrypto(t *testing.T) {
	code := `<?php
function login() {
    $pwd = $_POST["password"];
    $ok = wp_check_password($pwd, $stored_hash, $user_id);
    md5($ok);
}
?>`
	flows := Analyze(code, "/app/login.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("wp_check_password() should neutralize SnkCrypto taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative regression: constant-string args do not produce spurious flows ---

func TestPHP_ModernSanitizers_NoSpuriousFlow_ConstantString(t *testing.T) {
	code := `<?php
function constants() {
    $a = sodium_crypto_auth_verify("static-mac", "static-msg", "static-key");
    $b = idn_to_ascii("example.com");
    $c = esc_xml("static");
    $d = sanitize_html_class("static");
    $e = sanitize_mime_type("text/plain");
    $f = wp_filter_nohtml_kses("static");
    $g = wp_filter_post_kses("static");
    $h = wp_check_password("static", "hash", 1);
    $i = sodium_compare("a", "b");
    $j = sodium_crypto_box_open("ct", "nonce", "kp");
    $k = sodium_crypto_secretbox_open("ct", "nonce", "key");
    $l = sodium_crypto_sign_verify_detached("sig", "msg", "pk");
    md5($a);
    md5($b);
    md5($c);
}
?>`
	flows := Analyze(code, "/app/const.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) || hasTaintFlow(flows, taint.SnkHTMLOutput) ||
		hasTaintFlow(flows, taint.SnkRedirect) || hasTaintFlow(flows, taint.SnkURLFetch) ||
		hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("constant-string args to new sanitizers should not produce spurious taint flows")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
