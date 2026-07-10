package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP crypto sink tests — uniqid, crc32, lcg_value, mhash (CWE-328/338)
// =========================================================================

func TestPHP_Crypto_Uniqid_TaintedPrefix(t *testing.T) {
	code := `<?php
function handler() {
    $prefix = $_POST["prefix"];
    $token = uniqid($prefix, true);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for uniqid() with tainted prefix (weak randomness)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Crypto_Crc32_TaintedInput(t *testing.T) {
	code := `<?php
function handler() {
    $input = $_POST["password"];
    $digest = crc32($input);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for crc32() with tainted input (weak hash)")
	}
}

func TestPHP_Crypto_LcgValue_Exists(t *testing.T) {
	// lcg_value() is usage-based (DangerousArgs: -1) — the mere call is weak PRNG.
	// Verify the catalog entry exists and the pattern matches.
	cat := taint.GetCatalog(rules.LangPHP)
	if cat == nil {
		t.Fatal("no catalog for PHP")
	}
	found := false
	for _, s := range cat.Sinks() {
		if s.ID == "php.crypto.lcg_value" {
			found = true
			if s.Category != taint.SnkCrypto {
				t.Errorf("expected SnkCrypto category, got %s", s.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected sink entry for php.crypto.lcg_value")
	}
}

func TestPHP_Crypto_Mhash_TaintedInput(t *testing.T) {
	code := `<?php
function handler() {
    $data = $_POST["data"];
    $digest = mhash(MHASH_MD5, $data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for mhash() with tainted data")
	}
}

func TestPHP_Crypto_SafeRandomBytes_NoFlow(t *testing.T) {
	// random_bytes() is registered as a sanitizer for SnkCrypto — verify our
	// new sinks don't shadow it.
	code := `<?php
function handler() {
    $token = bin2hex(random_bytes(32));
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.ID == "php.crypto.uniqid" || f.Sink.ID == "php.crypto.crc32" ||
			f.Sink.ID == "php.crypto.lcg_value" || f.Sink.ID == "php.crypto.mhash" {
			t.Errorf("random_bytes path should not trigger new crypto sinks, got: %s", f.Sink.ID)
		}
	}
}
