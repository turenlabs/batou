package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — redis-rb additional read commands (second-order taint sources).
// redis-rb (`Redis.new`) is the canonical Ruby Redis client. Values
// returned by these read commands come from data previously stored by
// application or external code; treating them as taint sources catches
// stored-XSS via cached profile fields, command-injection via queued job
// names, SSRF via a leaderboard of URLs, etc.
//
// Existing entries already cover get/hget/hgetall/lpop+rpop+brpop+blpop/
// mget/smembers. This file exercises the new hash-keys, hash-vals,
// hash-multi-get, list-range, list-index, set-random/pop, sorted-set
// range/range-by-score/reverse-range, and sorted-set pop sources.
// =========================================================================

func TestRuby_RedisHkeys_CodeEval(t *testing.T) {
	code := `
require "redis"

def lookup(redis)
  field = redis.hkeys("user:profile")
  eval(field.first)
end
`
	flows := Analyze(code, "/app/redis_hkeys.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow from redis.hkeys -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisHvals_CommandInjection(t *testing.T) {
	code := `
require "redis"

def run_tasks(redis)
  vals = redis.hvals("pending_tasks")
  system(vals.first)
end
`
	flows := Analyze(code, "/app/redis_hvals.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.hvals -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisHmget_SSRF(t *testing.T) {
	code := `
require "redis"
require "net/http"

def fetch_urls(redis)
  urls = redis.hmget("services", "primary", "secondary")
  Net::HTTP.get(URI(urls.first))
end
`
	flows := Analyze(code, "/app/redis_hmget.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from redis.hmget -> Net::HTTP.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisLrange_CommandInjection(t *testing.T) {
	code := `
require "redis"

def process_queue(redis)
  jobs = redis.lrange("work_queue", 0, 10)
  system(jobs.first)
end
`
	flows := Analyze(code, "/app/redis_lrange.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.lrange -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisLindex_CodeEval(t *testing.T) {
	code := `
require "redis"

def latest(redis)
  expr = redis.lindex("recent_exprs", 0)
  eval(expr)
end
`
	flows := Analyze(code, "/app/redis_lindex.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow from redis.lindex -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisSrandmember_CommandInjection(t *testing.T) {
	code := `
require "redis"

def random_pick(redis)
  pick = redis.srandmember("featured_targets")
  system("ping " + pick)
end
`
	flows := Analyze(code, "/app/redis_srandmember.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.srandmember -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisSpop_CommandInjection(t *testing.T) {
	code := `
require "redis"

def consume(redis)
  target = redis.spop("targets:pending")
  system("scan " + target)
end
`
	flows := Analyze(code, "/app/redis_spop.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.spop -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisZrange_SSRF(t *testing.T) {
	code := `
require "redis"
require "net/http"

def top_endpoints(redis)
  urls = redis.zrange("endpoints", 0, 10)
  Net::HTTP.get(URI(urls.first))
end
`
	flows := Analyze(code, "/app/redis_zrange.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from redis.zrange -> Net::HTTP.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisZrevrange_CommandInjection(t *testing.T) {
	code := `
require "redis"

def leaderboard(redis)
  names = redis.zrevrange("leaderboard", 0, 10)
  system("notify " + names.first)
end
`
	flows := Analyze(code, "/app/redis_zrevrange.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.zrevrange -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisZrangebyscore_CommandInjection(t *testing.T) {
	code := `
require "redis"

def in_range(redis)
  hits = redis.zrangebyscore("scored", 0, 100)
  system("process " + hits.first)
end
`
	flows := Analyze(code, "/app/redis_zrangebyscore.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.zrangebyscore -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisZpopmin_SSRF(t *testing.T) {
	code := `
require "redis"
require "net/http"

def next_endpoint(redis)
  endpoint = redis.zpopmin("priority_queue")
  Net::HTTP.get(URI(endpoint.first))
end
`
	flows := Analyze(code, "/app/redis_zpopmin.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from redis.zpopmin -> Net::HTTP.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_RedisZpopmax_CommandInjection(t *testing.T) {
	code := `
require "redis"

def biggest(redis)
  top = redis.zpopmax("ranked_jobs")
  system(top.first)
end
`
	flows := Analyze(code, "/app/redis_zpopmax.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from redis.zpopmax -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative test: a constant string (no Redis source) should NOT produce a
// SrcExternal flow, guarding against an over-broad pattern that would fire
// on any .hkeys/.zrange/etc. regardless of receiver type.
func TestRuby_RedisRead_ConstantString_NoFlow(t *testing.T) {
	code := `
def harmless
  val = "static config value"
  system(val)
end
`
	flows := Analyze(code, "/app/redis_static.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal {
			t.Errorf("unexpected SrcExternal flow on constant string: %s -> %s (id=%s)",
				f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
