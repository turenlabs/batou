package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Lettuce (io.lettuce.core.api.sync.RedisCommands) read sources — second-order
// taint tests for Groovy.
//
// Groovy already modeled Jedis read-back sources but had no Lettuce equivalents.
// Lettuce is the DEFAULT Redis client in Spring Boot / Spring Data Redis and is
// at least as common as Jedis in Groovy/Grails and Micronaut apps. Its sync API
// (RedisCommands) uses all-lowercase method names (hgetall, zrangebyscore) that
// mirror the Redis command verbs — distinct from Jedis' camelCase (hgetAll,
// zrangeByScore), so they are genuinely separate catalog entries.
//
// Tests use the canonical receiver name `redisCommands`, which matches
// ObjectType "RedisCommands" directly. The tsflow matcher also accepts `redis`
// via the prefix-abbreviation heuristic (HasPrefix("rediscommands", "redis")).
// Set-returning methods (hkeys/smembers/zrange/zrangebyscore) use direct
// concatenation rather than `.iterator().next()` per the cycle #787 gotcha
// (iterator chains lose taint in tsflow).

// --- RedisCommands.get(key) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Get_SQLInjection(t *testing.T) {
	code := `
def lookupUser(userId) {
    def displayName = redisCommands.get("user:" + userId + ":name")
    sql.execute("SELECT * FROM events WHERE name = '" + displayName + "'")
}
`
	flows := Analyze(code, "/app/UserCache.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.get -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.mget(keys...) → command injection (CWE-78) ---

func TestGroovy_Lettuce_Mget_CommandInjection(t *testing.T) {
	code := `
def runQueued() {
    def values = redisCommands.mget("cmd:1", "cmd:2")
    def cmd = values.get(0)
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/CommandRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for RedisCommands.mget -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.getex(key, args) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Getex_SQLInjection(t *testing.T) {
	code := `
def touch(key) {
    def cached = redisCommands.getex(key, args)
    sql.execute("SELECT * FROM sessions WHERE data = '" + cached + "'")
}
`
	flows := Analyze(code, "/app/SessionCache.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.getex -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.hget(key, field) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Hget_SQLInjection(t *testing.T) {
	code := `
def lookup(userId) {
    def role = redisCommands.hget("roles", userId)
    sql.execute("SELECT * FROM permissions WHERE role = '" + role + "'")
}
`
	flows := Analyze(code, "/app/HashCache.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.hget -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.hgetall(key) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Hgetall_SQLInjection(t *testing.T) {
	code := `
def loadFilter(key) {
    def fields = redisCommands.hgetall(key)
    def filter = fields.get("filter")
    sql.execute("SELECT * FROM rows WHERE val = '" + filter + "'")
}
`
	flows := Analyze(code, "/app/FullHashLoad.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.hgetall -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.hmget(key, fields...) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Hmget_SQLInjection(t *testing.T) {
	code := `
def loadMulti(key) {
    def values = redisCommands.hmget(key, "f1", "f2")
    def first = values.get(0)
    sql.execute("SELECT * FROM t WHERE c = '" + first + "'")
}
`
	flows := Analyze(code, "/app/MultiField.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.hmget -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.hkeys(key) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Hkeys_SQLInjection(t *testing.T) {
	code := `
def listFields(key) {
    def fieldNames = redisCommands.hkeys(key)
    sql.execute("SELECT * FROM t WHERE name IN (" + fieldNames + ")")
}
`
	flows := Analyze(code, "/app/HashKeys.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.hkeys -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.hvals(key) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Hvals_SQLInjection(t *testing.T) {
	code := `
def loadValues(key) {
    def vals = redisCommands.hvals(key)
    def first = vals.get(0)
    sql.execute("SELECT * FROM t WHERE v = '" + first + "'")
}
`
	flows := Analyze(code, "/app/HashVals.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.hvals -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.lrange(key, start, stop) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Lrange_SQLInjection(t *testing.T) {
	code := `
def loadRecent(key) {
    def items = redisCommands.lrange(key, 0, 9)
    def first = items.get(0)
    sql.execute("SELECT * FROM events WHERE tag = '" + first + "'")
}
`
	flows := Analyze(code, "/app/RecentList.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.lrange -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.lindex(key, index) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Lindex_SQLInjection(t *testing.T) {
	code := `
def lookupAt(key, idx) {
    def item = redisCommands.lindex(key, idx)
    sql.execute("SELECT * FROM t WHERE c = '" + item + "'")
}
`
	flows := Analyze(code, "/app/IndexList.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.lindex -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.lpop(key) → command injection (CWE-78) ---

func TestGroovy_Lettuce_Lpop_CommandInjection(t *testing.T) {
	code := `
def runNext(key) {
    def cmd = redisCommands.lpop(key)
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/QueueRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for RedisCommands.lpop -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.rpop(key) → command injection (CWE-78) ---

func TestGroovy_Lettuce_Rpop_CommandInjection(t *testing.T) {
	code := `
def runLast(key) {
    def cmd = redisCommands.rpop(key)
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/TailRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for RedisCommands.rpop -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.smembers(key) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Smembers_SQLInjection(t *testing.T) {
	code := `
def membersOf(key) {
    def tags = redisCommands.smembers(key)
    sql.execute("SELECT * FROM t WHERE tag IN (" + tags + ")")
}
`
	flows := Analyze(code, "/app/SetMembers.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.smembers -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.zrange(key, start, stop) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Zrange_SQLInjection(t *testing.T) {
	code := `
def topN(key) {
    def winners = redisCommands.zrange(key, 0, 9)
    def first = winners.get(0)
    sql.execute("SELECT * FROM t WHERE name = '" + first + "'")
}
`
	flows := Analyze(code, "/app/Leaderboard.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.zrange -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- RedisCommands.zrangebyscore(key, min, max) → SQL injection (CWE-89) ---

func TestGroovy_Lettuce_Zrangebyscore_SQLInjection(t *testing.T) {
	code := `
def filterByScore(key) {
    def items = redisCommands.zrangebyscore(key, 0, 100)
    def first = items.get(0)
    sql.execute("SELECT * FROM t WHERE name = '" + first + "'")
}
`
	flows := Analyze(code, "/app/ScoreFilter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RedisCommands.zrangebyscore -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative test: constant Redis read + constant SQL → no flow (over-broadness regression) ---

func TestGroovy_Lettuce_Safe_ConstantValues(t *testing.T) {
	code := `
def runJob() {
    def hardcoded = "system"
    sql.execute("SELECT * FROM users WHERE name = 'admin'")
    def x = "literal"
}
`
	flows := Analyze(code, "/app/Hardcoded.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow for constant SQL with no Lettuce source involved")
	}
}
