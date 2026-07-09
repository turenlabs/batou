package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Jedis (Redis) read sources — second-order taint tests for Groovy.
//
// Groovy's existing catalog has Cassandra/Mongo/Neo4j/JDBC second-order
// sources but no Redis sources. Jedis is the canonical JVM Redis client and
// is widely used in Groovy/Grails apps for caches, session stores, queues,
// and rate-limiters that all routinely persist attacker-influenced bytes.
//
// Tests use the canonical receiver name `jedis`, matching the existing
// Cassandra/Neo4j source style and redis.io's Jedis examples. The tsflow
// matcher matches `ObjectType: "Jedis"` against `jedis`/`j`/`je`/etc. via
// the prefix-abbreviation heuristic in matcher.go:330.

// --- Jedis.get(key) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Get_SQLInjection(t *testing.T) {
	code := `
def lookupUser(userId) {
    def displayName = jedis.get("user:" + userId + ":name")
    sql.execute("SELECT * FROM events WHERE name = '" + displayName + "'")
}
`
	flows := Analyze(code, "/app/UserCache.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.get -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.mget(keys...) → command injection (CWE-78) ---

func TestGroovy_Jedis_Mget_CommandInjection(t *testing.T) {
	code := `
def runQueued() {
    def commands = jedis.mget("cmd:1", "cmd:2")
    def cmd = commands.get(0)
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/CommandRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Jedis.mget -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hget(key, field) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Hget_SQLInjection(t *testing.T) {
	code := `
def lookup(userId) {
    def role = jedis.hget("roles", userId)
    sql.execute("SELECT * FROM permissions WHERE role = '" + role + "'")
}
`
	flows := Analyze(code, "/app/HashCache.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hget -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hgetAll(key) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_HgetAll_SQLInjection(t *testing.T) {
	code := `
def loadFilter(key) {
    def fields = jedis.hgetAll(key)
    def filter = fields.get("filter")
    sql.execute("SELECT * FROM rows WHERE val = '" + filter + "'")
}
`
	flows := Analyze(code, "/app/FullHashLoad.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hgetAll -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hmget(key, fields...) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Hmget_SQLInjection(t *testing.T) {
	code := `
def loadMulti(key) {
    def values = jedis.hmget(key, "f1", "f2")
    def first = values.get(0)
    sql.execute("SELECT * FROM t WHERE c = '" + first + "'")
}
`
	flows := Analyze(code, "/app/MultiField.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hmget -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hkeys(key) → SQL injection (CWE-89) ---
// Set-returning method: use direct concatenation rather than .iterator().next()
// (per memory cycle #787 — iterator chains lose taint in tsflow).

func TestGroovy_Jedis_Hkeys_SQLInjection(t *testing.T) {
	code := `
def listFields(key) {
    def fieldNames = jedis.hkeys(key)
    sql.execute("SELECT * FROM t WHERE name IN (" + fieldNames + ")")
}
`
	flows := Analyze(code, "/app/HashKeys.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hkeys -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.hvals(key) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Hvals_SQLInjection(t *testing.T) {
	code := `
def loadValues(key) {
    def vals = jedis.hvals(key)
    def first = vals.get(0)
    sql.execute("SELECT * FROM t WHERE v = '" + first + "'")
}
`
	flows := Analyze(code, "/app/HashVals.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.hvals -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.lrange(key, start, stop) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Lrange_SQLInjection(t *testing.T) {
	code := `
def loadRecent(key) {
    def items = jedis.lrange(key, 0, 9)
    def first = items.get(0)
    sql.execute("SELECT * FROM events WHERE tag = '" + first + "'")
}
`
	flows := Analyze(code, "/app/RecentList.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.lrange -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.lindex(key, index) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Lindex_SQLInjection(t *testing.T) {
	code := `
def lookupAt(key, idx) {
    def item = jedis.lindex(key, idx)
    sql.execute("SELECT * FROM t WHERE c = '" + item + "'")
}
`
	flows := Analyze(code, "/app/IndexList.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.lindex -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.lpop(key) → command injection (CWE-78) ---

func TestGroovy_Jedis_Lpop_CommandInjection(t *testing.T) {
	code := `
def runNext(key) {
    def cmd = jedis.lpop(key)
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/QueueRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Jedis.lpop -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.smembers(key) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Smembers_SQLInjection(t *testing.T) {
	code := `
def membersOf(key) {
    def tags = jedis.smembers(key)
    sql.execute("SELECT * FROM t WHERE tag IN (" + tags + ")")
}
`
	flows := Analyze(code, "/app/SetMembers.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.smembers -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.zrange(key, start, stop) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_Zrange_SQLInjection(t *testing.T) {
	code := `
def topN(key) {
    def winners = jedis.zrange(key, 0, 9)
    def first = winners.get(0)
    sql.execute("SELECT * FROM t WHERE name = '" + first + "'")
}
`
	flows := Analyze(code, "/app/Leaderboard.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.zrange -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Jedis.zrangeByScore(key, min, max) → SQL injection (CWE-89) ---

func TestGroovy_Jedis_ZrangeByScore_SQLInjection(t *testing.T) {
	code := `
def filterByScore(key) {
    def items = jedis.zrangeByScore(key, 0, 100)
    def first = items.get(0)
    sql.execute("SELECT * FROM t WHERE name = '" + first + "'")
}
`
	flows := Analyze(code, "/app/ScoreFilter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Jedis.zrangeByScore -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative test: constant Redis read + constant SQL → no flow (over-broadness regression) ---

func TestGroovy_Jedis_Safe_ConstantValues(t *testing.T) {
	code := `
def runJob() {
    def hardcoded = "system"
    sql.execute("SELECT * FROM users WHERE name = 'admin'")
    def x = "literal"
}
`
	flows := Analyze(code, "/app/Hardcoded.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow for constant SQL with no Jedis source involved")
	}
}
