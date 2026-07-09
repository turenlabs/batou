package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP in-memory user-cache read sources — second-order taint coverage.
//
// APCu / APC / WinCache / XCache user caches store arbitrary, frequently
// attacker-influenced application data. Reading that data back out into a
// SQL / command / eval / deserialization sink is second-order injection,
// the same pattern already modeled for Redis and Memcached read sources.
// These are plain global functions (no receiver), so the distinctive names
// alone scope the match.
// =========================================================================

func TestPHP_APCu_Fetch_Deserialization(t *testing.T) {
	code := `<?php
function load_profile() {
    $blob = apcu_fetch('user_profile');
    $obj = unserialize($blob);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from apcu_fetch() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_APCu_Entry_Command(t *testing.T) {
	code := `<?php
function run_cached_job() {
    $cmd = apcu_entry('job_cmd', function () { return 'noop'; });
    system($cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from apcu_entry() to system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_APC_Fetch_Eval(t *testing.T) {
	code := `<?php
function eval_cached() {
    $code = apc_fetch('script_blob');
    eval($code);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from apc_fetch() to eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_WinCache_Get_Command(t *testing.T) {
	code := `<?php
function run_winjob() {
    $cmd = wincache_ucache_get('queued_cmd');
    exec($cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from wincache_ucache_get() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_XCache_Get_Deserialization(t *testing.T) {
	code := `<?php
function load_xcached() {
    $blob = xcache_get('cached_obj');
    $obj = unserialize($blob);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from xcache_get() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative regression: a constant string passed into unserialize must NOT
// produce a flow attributed to any of the new user-cache sources. Guards
// against an over-broad source pattern firing on non-cache call sites.
func TestPHP_UserCache_LiteralNotASource(t *testing.T) {
	code := `<?php
function constant_only() {
    $payload = "a:0:{}";
    $obj = unserialize($payload);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		switch f.Source.ID {
		case "php.apcu.fetch",
			"php.apc.fetch",
			"php.wincache.get",
			"php.xcache.get":
			t.Errorf("source %s fired on constant string (over-broad pattern)", f.Source.ID)
		}
	}
}
