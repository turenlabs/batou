package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP Redis additional read sources — second-order taint coverage
// (phpredis / Predis APIs: hKeys, hVals, hMGet, lIndex, sRandMember,
//  zRevRange, zRevRangeByScore, getRange)
// =========================================================================

func TestPHP_Redis_HKeys_Deserialization(t *testing.T) {
	code := `<?php
function load_keys() {
    $names = $redis->hKeys('user_session_index');
    $obj = unserialize($names);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->hKeys() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_HVals_Deserialization(t *testing.T) {
	code := `<?php
function load_vals() {
    $vals = $redis->hVals('cached_objects');
    $obj = unserialize($vals);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->hVals() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_HMGet_Command(t *testing.T) {
	code := `<?php
function exec_cached_jobs() {
    $cmds = $redis->hMGet('jobs', ['job1', 'job2']);
    exec($cmds[0]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from $redis->hMGet() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_LIndex_Deserialization(t *testing.T) {
	code := `<?php
function process_first() {
    $item = $redis->lIndex('queue', 0);
    $task = unserialize($item);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->lIndex() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_LGet_Deserialization(t *testing.T) {
	code := `<?php
function process_at() {
    $item = $redis->lGet('queue', 1);
    $task = unserialize($item);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->lGet() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_SRandMember_Command(t *testing.T) {
	code := `<?php
function pick_and_run() {
    $cmd = $redis->sRandMember('cmd_pool');
    system($cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from $redis->sRandMember() to system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_ZRevRange_Deserialization(t *testing.T) {
	code := `<?php
function load_top() {
    $top = $redis->zRevRange('leaderboard', 0, 9);
    $entry = unserialize($top[0]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->zRevRange() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_ZRevRangeByScore_Deserialization(t *testing.T) {
	code := `<?php
function load_by_score() {
    $items = $redis->zRevRangeByScore('events', '+inf', '-inf');
    $obj = unserialize($items[0]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from $redis->zRevRangeByScore() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redis_GetRange_Eval(t *testing.T) {
	code := `<?php
function eval_substring() {
    $code = $redis->getRange('script_blob', 0, 1024);
    eval($code);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from $redis->getRange() to eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative regression: literal string passed to unserialize must NOT
// produce a Redis-source flow. Guards against an over-broad source pattern
// where the entry would somehow fire on non-Redis call sites.
func TestPHP_Redis_LiteralNotASource(t *testing.T) {
	code := `<?php
function constant_only() {
    $payload = "a:0:{}";
    $obj = unserialize($payload);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		// We only care that none of the *new* Redis sources are firing on
		// constant strings. A flow from a different source category (e.g.
		// nothing) is fine — just guard against the new IDs.
		switch f.Source.ID {
		case "php.redis.hkeys",
			"php.redis.hmget",
			"php.redis.lindex",
			"php.redis.srandmember",
			"php.redis.zrevrange",
			"php.redis.getrange":
			t.Errorf("source %s fired on constant string (over-broad pattern)", f.Source.ID)
		}
	}
}
