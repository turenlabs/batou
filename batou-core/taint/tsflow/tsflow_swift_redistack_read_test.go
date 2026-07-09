package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Swift RediStack additional read sources — second-order taint tests.
//
// Swift's catalog already had a single lumped swift.redistack.get source
// covering get/hget/hmget/hgetall/lpop/rpop/lrange but did not match many
// other idiomatic RediStack reads (mget, hkeys/hvals, smembers/srandmember/
// spop, zrange/zrangebyscore, lindex). Redis-backed caches, session stores
// and queues routinely persist attacker-controlled values; reading them
// back without sanitization is a real second-order injection path.
//
// Each test plumbs a RediStack read into SQLite.swift's Connection.execute
// (swift.sqliteswift.execute, DangerousArgs [0], ObjectType "Connection"
// matched against receiver "db" via the Connection heuristic in
// matcher.go:273-277). SQL/Query keywords are intentionally absent from the
// function bodies to avoid the isWebHandlerFunc auto-taint trigger
// (walker.go:1855 — substrings like "Query(", "Path(", "GET", "POST",
// "DELETE" etc. flag the function as a web handler and seed all params
// as tainted, which would mask whether the new source actually fires).

// --- Mget --------------------------------------------------------------

func TestSwift_RediStack_Mget_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func cacheReplay(redis: RedisClient, db: Connection) throws {
    let cached = redis.mget(["k1", "k2"], as: String.self)
    let sql = "SELECT * FROM events WHERE id IN ('\(cached)')"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/CacheReplay.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.mget -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Hkeys -------------------------------------------------------------

func TestSwift_RediStack_Hkeys_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func dumpHashKeys(redis: RedisClient, db: Connection) throws {
    let fields = redis.hkeys(in: "user:profile")
    let sql = "SELECT * FROM audit WHERE field = '\(fields)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/DumpHashKeys.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.hkeys -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Hvals -------------------------------------------------------------

func TestSwift_RediStack_Hvals_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func dumpHashValues(redis: RedisClient, db: Connection) throws {
    let values = redis.hvals(in: "settings", as: String.self)
    let sql = "SELECT * FROM audit WHERE val = '\(values)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/DumpHashValues.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.hvals -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Smembers ----------------------------------------------------------

func TestSwift_RediStack_Smembers_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func tagLookup(redis: RedisClient, db: Connection) throws {
    let tags = redis.smembers(of: "tags:user:42", as: String.self)
    let sql = "SELECT * FROM articles WHERE tag = '\(tags)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/TagLookup.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.smembers -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Srandmember ------------------------------------------------------

func TestSwift_RediStack_Srandmember_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func pickRandom(redis: RedisClient, db: Connection) throws {
    let pick = redis.srandmember(from: "candidates", as: String.self)
    let sql = "SELECT * FROM users WHERE name = '\(pick)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/PickRandom.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.srandmember -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Spop --------------------------------------------------------------

func TestSwift_RediStack_Spop_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func popQueue(redis: RedisClient, db: Connection) throws {
    let job = redis.spop(from: "jobs", as: String.self)
    let sql = "SELECT * FROM job_log WHERE name = '\(job)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/PopQueue.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.spop -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Zrange ------------------------------------------------------------

func TestSwift_RediStack_Zrange_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func leaderboard(redis: RedisClient, db: Connection) throws {
    let top = redis.zrange(from: "leaderboard", firstIndex: 0, lastIndex: 9, as: String.self)
    let sql = "SELECT * FROM users WHERE handle IN ('\(top)')"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Leaderboard.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.zrange -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Zrangebyscore -----------------------------------------------------

func TestSwift_RediStack_Zrangebyscore_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func scoredLookup(redis: RedisClient, db: Connection) throws {
    let winners = redis.zrangebyscore(from: "scores", withMinimumScoreOf: 100, withMaximumScoreOf: 200, as: String.self)
    let sql = "SELECT * FROM users WHERE name IN ('\(winners)')"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ScoredLookup.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.zrangebyscore -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Lindex ------------------------------------------------------------

func TestSwift_RediStack_Lindex_SQLi(t *testing.T) {
	code := `
import RediStack
import SQLite

func nthMessage(redis: RedisClient, db: Connection) throws {
    let entry = redis.lindex(0, from: "messages", as: String.self)
    let sql = "SELECT * FROM message_log WHERE body = '\(entry)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/NthMessage.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for redis.lindex -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: constant SQL, no flow even though redis read fires ------
//
// Verifies that the new source entries don't produce spurious SnkSQLQuery
// flows when the redis read result is discarded and the SQL is a literal.

func TestSwift_RediStack_Read_NoFlow_OnConstantSQL(t *testing.T) {
	code := `
import RediStack
import SQLite

func warmCache(redis: RedisClient, db: Connection) throws {
    _ = redis.mget(["k1"], as: String.self)
    _ = redis.smembers(of: "tags", as: String.self)
    _ = redis.zrange(from: "leaderboard", firstIndex: 0, lastIndex: 9, as: String.self)
    let sql = "SELECT 1"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/WarmCache.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL injection flow for unused redis reads + constant SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
