package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ redis-plus-plus (sw::redis::Redis) second-order taint tests.
// Read methods on the Redis client return data previously stored by some
// other code path. If that write path was attacker-controlled, the read
// produces tainted data which can flow to a downstream sink (command
// injection, SQL injection, path traversal, SSRF).
// Receiver name is "redis" — matches ObjectType "sw::redis::Redis" via
// the matcher's lastPart equality (lastPart = "redis").
// =========================================================================

func TestCPP_SwRedis_Get_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.get("cmd");
    std::string cmd = *val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_get.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Mget_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>
#include <vector>

void run(sw::redis::Redis &redis) {
    std::vector<std::string> keys = {"a", "b"};
    std::vector<std::string> vals;
    redis.mget(keys.begin(), keys.end(), std::back_inserter(vals));
    auto data = redis.mget("k");
    system(data.c_str());
}
`
	flows := Analyze(code, "/app/swredis_mget.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.mget -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Hget_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.hget("user:1", "shell");
    std::string cmd = *val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_hget.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.hget -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Hgetall_FileWrite(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdio>

void run(sw::redis::Redis &redis) {
    auto path = redis.hgetall("config");
    fopen(path.c_str(), "w");
}
`
	flows := Analyze(code, "/app/swredis_hgetall.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: redis.hgetall -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Hmget_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.hmget("hash", "f1");
    std::string cmd = val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_hmget.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.hmget -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Hkeys_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.hkeys("hash");
    std::string cmd = val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_hkeys.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.hkeys -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Hvals_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.hvals("hash");
    std::string cmd = val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_hvals.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.hvals -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Lrange_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto items = redis.lrange("queue", 0, -1);
    std::string cmd = items;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_lrange.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.lrange -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Lindex_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.lindex("queue", 0);
    std::string cmd = *val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_lindex.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.lindex -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Lpop_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.lpop("queue");
    std::string cmd = *val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_lpop.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.lpop -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Rpop_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.rpop("queue");
    std::string cmd = *val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_rpop.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.rpop -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Smembers_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto members = redis.smembers("set");
    std::string cmd = members;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_smembers.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.smembers -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Spop_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto val = redis.spop("set");
    std::string cmd = *val;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_spop.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.spop -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Zrange_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto items = redis.zrange("z", 0, -1);
    std::string cmd = items;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_zrange.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.zrange -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_Zrangebyscore_CommandInjection(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    auto items = redis.zrangebyscore("z", 0, 100);
    std::string cmd = items;
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_zrangebyscore.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis.zrangebyscore -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative tests — constant strings should NOT produce flows.
// Guards against over-broad matching (any object's .get / .lrange).
// =========================================================================

func TestCPP_SwRedis_ConstString_NoFlow(t *testing.T) {
	code := `
#include <sw/redis++/redis++.h>
#include <cstdlib>

void run(sw::redis::Redis &redis) {
    redis.get("noop");
    std::string cmd = "echo hello";
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/swredis_const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow: constant string in sink, redis.get result not used")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SwRedis_OtherReceiver_NoFlow(t *testing.T) {
	code := `
#include <memory>
#include <cstdlib>

void run() {
    std::shared_ptr<int> ptr;
    auto val = ptr.get();
    system("echo done");
}
`
	flows := Analyze(code, "/app/swredis_other_receiver.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow: shared_ptr.get is not a Redis source")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
