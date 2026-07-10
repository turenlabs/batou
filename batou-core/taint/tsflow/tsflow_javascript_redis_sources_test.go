package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// JavaScript/TypeScript — node-redis v4 / ioredis additional read sources for
// second-order taint (CWE-94 Lua-script injection demonstrated end-to-end).
//
// User input written to Redis on one request and read back by a later request
// flows through the data layer; without these sources the downstream sink
// (here js.redis.eval — Redis EVAL Lua-script injection) would not fire.
// Each test wires a Redis read (hGetAll / hKeys / lRange / sMembers / zRange /
// ...) through to redis.eval() and asserts a SnkEval flow originating from the
// new source. node-redis v4 uses camelCase method names; ioredis and
// node-redis v3/legacy use all-lowercase — both case variants are packed into
// each entry's MethodName, so both are exercised here.
//
// Mirrors java.jedis.* (PR #641), go.redis.* (PR #647), python redis-py reads
// (PR #685), csharp.redis.* read sources, and the multi-language Redis-source
// addition cycle.
// ===========================================================================

// flowFromSourceToEval reports whether any flow originates from the given
// source ID and terminates at an eval/code-execution sink. (A `redis.eval(...)`
// call matches both the scoped js.redis.eval sink and the generic js.eval sink;
// the reported sink ID can be either, so we assert on the source ID and the
// SnkEval category rather than a fixed sink ID.)
func flowFromSourceToEval(flows []taint.TaintFlow, srcID string) bool {
	for _, f := range flows {
		if f.Source.ID == srcID && f.Sink.Category == taint.SnkEval {
			return true
		}
	}
	return false
}

func TestJS_RedisSource_HGetAll_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function replay(req, res) {
    const cfg = await redis.hGetAll('scripts:dynamic');
    await redis.eval(cfg.body);
}
`
	flows := Analyze(code, "/app/handlers/replay.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) || !flowFromSourceToEval(flows, "js.redis.hgetall") {
		t.Error("expected js.redis.hgetall -> js.redis.eval SnkEval flow")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

func TestJS_RedisSource_HGet_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const script = await redis.hGet('cfg', 'script');
    await redis.eval(script);
}
`
	flows := Analyze(code, "/app/handlers/run.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.hget") {
		t.Error("expected js.redis.hget -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_HKeys_ToEval(t *testing.T) {
	code := `
const redis = require('ioredis').createClient();
async function run(req, res) {
    const keys = await redis.hkeys('cfg');
    await redis.eval(keys.join(','));
}
`
	flows := Analyze(code, "/app/handlers/keys.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.hkeys") {
		t.Error("expected js.redis.hkeys -> js.redis.eval flow (ioredis lowercase)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_HVals_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const vals = await redis.hVals('cfg');
    await redis.eval(vals[0]);
}
`
	flows := Analyze(code, "/app/handlers/vals.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.hvals") {
		t.Error("expected js.redis.hvals -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_HMGet_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const parts = await redis.hmGet('cfg', ['a', 'b']);
    await redis.eval(parts.join(''));
}
`
	flows := Analyze(code, "/app/handlers/hmget.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.hmget") {
		t.Error("expected js.redis.hmget -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_MGet_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const vals = await redis.mGet(['k1', 'k2']);
    await redis.eval(vals[0]);
}
`
	flows := Analyze(code, "/app/handlers/mget.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.mget") {
		t.Error("expected js.redis.mget -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_LRange_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const items = await redis.lRange('queue', 0, -1);
    await redis.eval(items.join(';'));
}
`
	flows := Analyze(code, "/app/handlers/lrange.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.lrange") {
		t.Error("expected js.redis.lrange -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_LIndex_ToEval(t *testing.T) {
	code := `
const redis = require('ioredis').createClient();
async function run(req, res) {
    const head = await redis.lindex('queue', 0);
    await redis.eval(head);
}
`
	flows := Analyze(code, "/app/handlers/lindex.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.lindex") {
		t.Error("expected js.redis.lindex -> js.redis.eval flow (ioredis lowercase)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_LPop_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const job = await redis.lPop('jobs');
    await redis.eval(job);
}
`
	flows := Analyze(code, "/app/handlers/lpop.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.lpop") {
		t.Error("expected js.redis.lpop -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_RPop_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const job = await redis.rPop('jobs');
    await redis.eval(job);
}
`
	flows := Analyze(code, "/app/handlers/rpop.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.rpop") {
		t.Error("expected js.redis.rpop -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_SMembers_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const tags = await redis.sMembers('tags');
    await redis.eval(tags.join(','));
}
`
	flows := Analyze(code, "/app/handlers/smembers.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.smembers") {
		t.Error("expected js.redis.smembers -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_SRandMember_ToEval(t *testing.T) {
	code := `
const redis = require('ioredis').createClient();
async function run(req, res) {
    const tag = await redis.srandmember('tags');
    await redis.eval(tag);
}
`
	flows := Analyze(code, "/app/handlers/srandmember.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.srandmember") {
		t.Error("expected js.redis.srandmember -> js.redis.eval flow (ioredis lowercase)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_SPop_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const tag = await redis.sPop('tags');
    await redis.eval(tag);
}
`
	flows := Analyze(code, "/app/handlers/spop.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.spop") {
		t.Error("expected js.redis.spop -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_ZRange_ToEval(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const board = await redis.zRange('leaderboard', 0, 9);
    await redis.eval(board.join(';'));
}
`
	flows := Analyze(code, "/app/handlers/zrange.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.zrange") {
		t.Error("expected js.redis.zrange -> js.redis.eval flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_RedisSource_ZRangeByScore_ToEval(t *testing.T) {
	code := `
const redis = require('ioredis').createClient();
async function run(req, res) {
    const board = await redis.zrangebyscore('leaderboard', 0, 100);
    await redis.eval(board.join(';'));
}
`
	flows := Analyze(code, "/app/handlers/zrangebyscore.js", rules.LangJavaScript)
	if !flowFromSourceToEval(flows, "js.redis.zrangebyscore") {
		t.Error("expected js.redis.zrangebyscore -> js.redis.eval flow (ioredis lowercase)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: a hardcoded Lua script passed to redis.eval() must not flow, even
// though a Redis read sits in the same function — the read result is not used
// as the script.
func TestJS_RedisSource_NoFlow_HardcodedScript(t *testing.T) {
	code := `
const redis = require('redis').createClient();
async function run(req, res) {
    const _unused = await redis.hGetAll('cfg');
    await redis.eval("return redis.call('GET', KEYS[1])", { keys: ['k'] });
}
`
	flows := Analyze(code, "/app/handlers/safe.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("expected NO SnkEval flow for hardcoded Lua script; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: a generic receiver name (`cache`) is intentionally NOT in the
// RedisClient receiver allowlist, so a Redis-shaped read on it does not taint
// downstream sinks — guards against over-matching non-Redis clients.
func TestJS_RedisSource_NoFlow_NonRedisReceiver(t *testing.T) {
	code := `
const cache = makeSomeCache();
async function run(req, res) {
    const data = await cache.hGetAll('k');
    res.send(data);
}
`
	flows := Analyze(code, "/app/handlers/cache.js", rules.LangJavaScript)
	if flowFromSourceToEval(flows, "js.redis.hgetall") {
		t.Error("did not expect js.redis.hgetall flow for non-Redis receiver `cache`")
	}
	for _, f := range flows {
		if f.Source.ID == "js.redis.hgetall" {
			t.Errorf("did not expect js.redis.hgetall source to fire on `cache.hGetAll(...)`; got sink %s", f.Sink.ID)
		}
	}
}

// Registration check: all 15 new Redis read sources must be present in the
// JavaScript source catalog.
func TestJS_RedisSource_CatalogRegistration(t *testing.T) {
	want := []string{
		"js.redis.hget", "js.redis.hgetall", "js.redis.hkeys", "js.redis.hvals",
		"js.redis.hmget", "js.redis.mget", "js.redis.lrange", "js.redis.lindex",
		"js.redis.lpop", "js.redis.rpop", "js.redis.smembers", "js.redis.srandmember",
		"js.redis.spop", "js.redis.zrange", "js.redis.zrangebyscore",
	}
	have := map[string]bool{}
	for _, s := range taint.SourcesForLanguage(rules.LangJavaScript) {
		have[s.ID] = true
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("missing JS Redis source catalog entry: %s", id)
		}
	}
}
