package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Kotlin Lettuce (io.lettuce.core.api.sync.RedisCommands) read sources for
// second-order taint. A previous request may have written attacker-controlled
// data into Redis; reading it back produces tainted values that must propagate
// to downstream SQL/command/log/eval sinks.
//
// Receiver "redis" matches ObjectType "RedisCommands" via the matcher's
// prefix-abbreviation heuristic (HasPrefix("rediscommands", "redis") = true).
// All tests use string concatenation with the read value flowing into
// kotlin.jdbc.executeupdate to demonstrate the second-order SQLi pattern.
//
// Test fixtures intentionally:
//   - use `executeUpdate` (NOT `executeQuery`) to avoid the `Query(` substring
//     trigger in tsflow.isWebHandlerFunc that auto-taints all parameters.
//   - use `UPDATE` SQL (NOT `DELETE`/`POST`/`GET`/`PUT`/`PATCH`) for the same
//     reason — those are HTTP methods on the webHandlerAnnotations list.
//   - For Set-returning methods (hkeys/smembers/zrange/zrangebyscore), use
//     direct string concatenation rather than `.iterator().next()` because the
//     tsflow walker doesn't propagate taint through chained iterator calls
//     (verified gotcha from cycle #787 / Java Jedis).

func runLettuceSourceTest(t *testing.T, code, sourceID string) {
	t.Helper()
	flows := Analyze(code, "/app/CustomerDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Source.ID == sourceID && f.Sink.Category == taint.SnkSQLQuery {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected second-order SQLi flow from source %q to a SQL sink; got flows: %+v", sourceID, flows)
	}
}

// ---------- String reads ----------

func TestKotlin_Lettuce_Get_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val cached = redis.get("user:42:name")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET nickname='" + cached + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.get")
}

func TestKotlin_Lettuce_Mget_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val values = redis.mget("u:1", "u:2")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + values + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.mget")
}

func TestKotlin_Lettuce_Getex_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import io.lettuce.core.GetExArgs
import java.sql.DriverManager

fun touch(redis: RedisCommands<String, String>) {
    val cached = redis.getex("session:abc", GetExArgs.Builder.ex(60))
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE sessions SET data='" + cached + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.getex")
}

// ---------- Hash reads ----------

func TestKotlin_Lettuce_Hget_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val name = redis.hget("user:42", "name")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET nickname='" + name + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.hget")
}

func TestKotlin_Lettuce_Hgetall_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val all = redis.hgetall("user:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + all + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.hgetall")
}

func TestKotlin_Lettuce_Hmget_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val fields = redis.hmget("user:42", "name", "email")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + fields + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.hmget")
}

func TestKotlin_Lettuce_Hkeys_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val keys = redis.hkeys("user:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + keys + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.hkeys")
}

func TestKotlin_Lettuce_Hvals_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val vals = redis.hvals("user:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + vals + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.hvals")
}

// ---------- List reads ----------

func TestKotlin_Lettuce_Lrange_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val items = redis.lrange("orders:42", 0, -1)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + items + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.lrange")
}

func TestKotlin_Lettuce_Lindex_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val first = redis.lindex("orders:42", 0)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + first + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.lindex")
}

func TestKotlin_Lettuce_Lpop_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val item = redis.lpop("queue:tasks")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + item + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.lpop")
}

func TestKotlin_Lettuce_Rpop_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val item = redis.rpop("queue:tasks")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + item + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.rpop")
}

// ---------- Set reads ----------
// Per cycle #787 gotcha: Set-returning reads use direct string concat.

func TestKotlin_Lettuce_Smembers_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val tags = redis.smembers("tags:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET tags='" + tags + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.smembers")
}

// ---------- Sorted-set reads ----------

func TestKotlin_Lettuce_Zrange_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val members = redis.zrange("leaderboard", 0, 9)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + members + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.zrange")
}

func TestKotlin_Lettuce_Zrangebyscore_SecondOrderSQLi(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import io.lettuce.core.Range
import java.sql.DriverManager

fun lookup(redis: RedisCommands<String, String>) {
    val members = redis.zrangebyscore("leaderboard", Range.create(0.0, 100.0))
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + members + "' WHERE id=1")
}
`
	runLettuceSourceTest(t, code, "kotlin.lettuce.zrangebyscore")
}

// ---------- Negative control: constant Redis read with constant SQL ----------
// Verifies the new sources don't fire on unrelated constant flows.

func TestKotlin_Lettuce_NoFlow_OnConstantSQL(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import java.sql.DriverManager

fun warm(redis: RedisCommands<String, String>) {
    val cached = redis.get("warmup:key")
    println("loaded: " + cached)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE warmup_marker SET v=1 WHERE id=1")
}
`
	flows := Analyze(code, "/app/CustomerDao.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Source.ID == "kotlin.lettuce.get" && f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("Did not expect SQL flow from kotlin.lettuce.get when downstream SQL is constant; got %+v", f)
		}
	}
}
