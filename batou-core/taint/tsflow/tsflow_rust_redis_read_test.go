package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Second-order taint coverage for redis-rs Commands / AsyncCommands trait.
// Pattern: untrusted data is read from a shared Redis cache (any writer
// could have stored attacker input) and reaches a SQL injection sink via
// format!(). The SQL sink used throughout is sqlx::query(&sql) because its
// ObjectType "sqlx" reliably matches the scoped_identifier receiver.

// --- Hash commands ---

func TestRust_Redis_HGetAll_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let user: std::collections::HashMap<String, String> = con.hgetall("user:42").unwrap();
    let name = user.get("name").cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM orders WHERE customer = '{}'", name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis hgetall -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_HKeys_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let keys: Vec<String> = con.hkeys("session_index").unwrap();
    let key = keys.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM sessions WHERE id = '{}'", key);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis hkeys -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_HVals_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let vals: Vec<String> = con.hvals("user_emails").unwrap();
    let email = vals.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM contacts WHERE email = '{}'", email);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis hvals -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_HMGet_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let fields: Vec<String> = con.hmget("user:42", &["name", "email"]).unwrap();
    let name = fields.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM orders WHERE customer = '{}'", name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis hmget -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- String commands ---

func TestRust_Redis_MGet_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let vals: Vec<String> = con.mget(&["k1", "k2"]).unwrap();
    let v = vals.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM cache_lookups WHERE token = '{}'", v);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis mget -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- List commands ---

func TestRust_Redis_LRange_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let items: Vec<String> = con.lrange("recent_searches", 0, 10).unwrap();
    let term = items.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM products WHERE name LIKE '%{}%'", term);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis lrange -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_LIndex_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let item: String = con.lindex("history", 0).unwrap();
    let sql = format!("SELECT * FROM audit WHERE actor = '{}'", item);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis lindex -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_LPop_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let item: String = con.lpop("queue", None).unwrap();
    let sql = format!("UPDATE jobs SET state='done' WHERE id = '{}'", item);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis lpop -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_RPop_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let item: String = con.rpop("backlog", None).unwrap();
    let sql = format!("UPDATE jobs SET state='done' WHERE id = '{}'", item);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis rpop -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Set commands ---

func TestRust_Redis_SMembers_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let members: Vec<String> = con.smembers("admins").unwrap();
    let m = members.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", m);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis smembers -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_SRandMember_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let member: String = con.srandmember("active_users").unwrap();
    let sql = format!("SELECT * FROM profiles WHERE handle = '{}'", member);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis srandmember -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_SPop_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let member: String = con.spop("pending_users").unwrap();
    let sql = format!("DELETE FROM queue WHERE token = '{}'", member);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis spop -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sorted-set commands ---

func TestRust_Redis_ZRange_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let entries: Vec<String> = con.zrange("leaderboard", 0, 10).unwrap();
    let top = entries.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM player_stats WHERE name = '{}'", top);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis zrange -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_ZRevRange_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let entries: Vec<String> = con.zrevrange("leaderboard", 0, 10).unwrap();
    let top = entries.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM player_stats WHERE name = '{}'", top);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis zrevrange -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Redis_ZRangeByScore_To_SQLInjection(t *testing.T) {
	code := `
use redis::Commands;
use sqlx::PgPool;

async fn handler(pool: &PgPool, mut con: redis::Connection) {
    let entries: Vec<String> = con.zrangebyscore("scores", 100, 200).unwrap();
    let top = entries.first().cloned().unwrap_or_default();
    let sql = format!("SELECT * FROM users WHERE handle = '{}'", top);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: redis zrangebyscore -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: literal SQL (no Redis source) should NOT flag.
// Guards against the Redis sources being too broad. ---

func TestRust_Redis_Literal_NoSource_NoFlag(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let sql = "SELECT * FROM users WHERE id = 1".to_string();
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("hardcoded SQL with no Redis source should not flag: source=%s sink=%s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
