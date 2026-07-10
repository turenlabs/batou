package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Kotlin second-order taint read sources:
//   - Jedis (redis.clients.jedis.Jedis) hash/list/set/sorted-set read methods
//     that the existing kotlin.jedis.get entry (get/hget/mget/lrange) didn't
//     cover.
//   - MongoDB org.bson.Document field getters + MongoCursor.tryNext().
//
// A previous request may have written attacker-controlled data into Redis /
// MongoDB; reading it back produces tainted values that must propagate to
// downstream SQL/command/log/eval sinks.
//
// Matcher facts exercised here:
//   - receiver `jedis` matches ObjectType "redis.clients.jedis.Jedis" via the
//     prefix-abbreviation heuristic against the last component "jedis".
//   - receiver `doc` matches ObjectType "org.bson.Document" via the prefix
//     heuristic against "document".
//   - receiver `cursor` matches ObjectType "com.mongodb.client.MongoCursor"
//     because the ObjectType contains the substring "cursor".
//
// Test fixtures intentionally:
//   - use `executeUpdate` (NOT `executeQuery`) to avoid the `Query(` substring
//     trigger in tsflow.isWebHandlerFunc that auto-taints all parameters.
//   - use `UPDATE` SQL (NOT `DELETE`/`GET`/`POST`/`PUT`/`PATCH`) for the same
//     reason — those are HTTP methods on the webHandlerAnnotations list.
//   - use direct string concatenation rather than `.iterator().next()` for
//     Set/List/Map-returning methods (the tsflow walker doesn't propagate taint
//     through chained iterator calls — verified gotcha from cycle #787).

func runKotlinSecondOrderSQLiTest(t *testing.T, code, sourceID string) {
	t.Helper()
	flows := Analyze(code, "/app/StoreDao.kt", rules.LangKotlin)
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

// ---------- Jedis additional read sources ----------

func TestKotlin_Jedis_GetDel_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val cached = jedis.getDel("user:42:name")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET nickname='" + cached + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.getdel")
}

func TestKotlin_Jedis_HgetAll_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val profile = jedis.hgetAll("user:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + profile + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.hgetall")
}

func TestKotlin_Jedis_Hmget_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val values = jedis.hmget("user:42", "name", "email")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + values + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.hmget")
}

func TestKotlin_Jedis_Hkeys_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val fields = jedis.hkeys("user:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + fields + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.hkeys")
}

func TestKotlin_Jedis_Hvals_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val vals = jedis.hvals("user:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + vals + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.hvals")
}

func TestKotlin_Jedis_Lindex_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val item = jedis.lindex("queue:42", 0)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + item + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.lindex")
}

func TestKotlin_Jedis_Lpop_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val item = jedis.lpop("queue:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + item + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.lpop")
}

func TestKotlin_Jedis_Rpop_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val item = jedis.rpop("queue:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + item + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.rpop")
}

func TestKotlin_Jedis_Smembers_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val tags = jedis.smembers("tags:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + tags + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.smembers")
}

func TestKotlin_Jedis_Srandmember_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val pick = jedis.srandmember("tags:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + pick + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.srandmember")
}

func TestKotlin_Jedis_Spop_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val pick = jedis.spop("tags:42")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + pick + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.spop")
}

func TestKotlin_Jedis_Zrange_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val members = jedis.zrange("leaderboard", 0, 9)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + members + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.zrange")
}

func TestKotlin_Jedis_Zrevrange_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val members = jedis.zrevrange("leaderboard", 0, 9)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + members + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.zrevrange")
}

func TestKotlin_Jedis_ZrangeByScore_SecondOrderSQLi(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun lookup(jedis: Jedis) {
    val members = jedis.zrangeByScore("leaderboard", 0.0, 100.0)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + members + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.jedis.zrangebyscore")
}

// ---------- MongoDB BSON Document / cursor read sources ----------

func TestKotlin_Mongo_DocumentGet_SecondOrderSQLi(t *testing.T) {
	code := `
import org.bson.Document
import java.sql.DriverManager

fun lookup(doc: Document) {
    val name = doc.get("name")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET nickname='" + name + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.mongo.document.get")
}

func TestKotlin_Mongo_DocumentGetString_SecondOrderSQLi(t *testing.T) {
	code := `
import org.bson.Document
import java.sql.DriverManager

fun lookup(doc: Document) {
    val name = doc.getString("name")
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET nickname='" + name + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.mongo.document.getstring")
}

func TestKotlin_Mongo_DocumentGetList_SecondOrderSQLi(t *testing.T) {
	code := `
import org.bson.Document
import java.sql.DriverManager

fun lookup(doc: Document) {
    val roles = doc.getList("roles", String::class.java)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + roles + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.mongo.document.getlist")
}

func TestKotlin_Mongo_DocumentGetEmbedded_SecondOrderSQLi(t *testing.T) {
	code := `
import org.bson.Document
import java.sql.DriverManager

fun lookup(doc: Document) {
    val city = doc.getEmbedded(listOf("address", "city"), String::class.java)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET city='" + city + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.mongo.document.getembedded")
}

func TestKotlin_Mongo_CursorTryNext_SecondOrderSQLi(t *testing.T) {
	code := `
import com.mongodb.client.MongoCursor
import org.bson.Document
import java.sql.DriverManager

fun lookup(cursor: MongoCursor<Document>) {
    val next = cursor.tryNext()
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE customers SET data='" + next + "' WHERE id=1")
}
`
	runKotlinSecondOrderSQLiTest(t, code, "kotlin.mongo.cursor.trynext")
}

// ---------- Negative control ----------
// Constant Redis/Mongo reads with constant SQL must not produce a flow.

func TestKotlin_MongoJedis_NoFlow_OnConstantSQL(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import org.bson.Document
import java.sql.DriverManager

fun warm(jedis: Jedis, doc: Document) {
    val cached = jedis.smembers("warmup:keys")
    val field = doc.getString("warmup")
    println("loaded: " + cached + field)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE warmup_marker SET v=1 WHERE id=1")
}
`
	flows := Analyze(code, "/app/StoreDao.kt", rules.LangKotlin)
	for _, f := range flows {
		if (f.Source.ID == "kotlin.jedis.smembers" || f.Source.ID == "kotlin.mongo.document.getstring") && f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("Did not expect a SQL flow when downstream SQL is constant; got %+v", f)
		}
	}
}

// ---------- Catalog registration ----------

func TestKotlin_MongoJedisSources_Registered(t *testing.T) {
	want := map[string]taint.SourceCategory{
		"kotlin.jedis.getdel":               taint.SrcExternal,
		"kotlin.jedis.hgetall":              taint.SrcExternal,
		"kotlin.jedis.hmget":                taint.SrcExternal,
		"kotlin.jedis.hkeys":                taint.SrcExternal,
		"kotlin.jedis.hvals":                taint.SrcExternal,
		"kotlin.jedis.lindex":               taint.SrcExternal,
		"kotlin.jedis.lpop":                 taint.SrcExternal,
		"kotlin.jedis.rpop":                 taint.SrcExternal,
		"kotlin.jedis.smembers":             taint.SrcExternal,
		"kotlin.jedis.srandmember":          taint.SrcExternal,
		"kotlin.jedis.spop":                 taint.SrcExternal,
		"kotlin.jedis.zrange":               taint.SrcExternal,
		"kotlin.jedis.zrevrange":            taint.SrcExternal,
		"kotlin.jedis.zrangebyscore":        taint.SrcExternal,
		"kotlin.mongo.document.get":         taint.SrcDatabase,
		"kotlin.mongo.document.getstring":   taint.SrcDatabase,
		"kotlin.mongo.document.getlist":     taint.SrcDatabase,
		"kotlin.mongo.document.getembedded": taint.SrcDatabase,
		"kotlin.mongo.cursor.trynext":       taint.SrcDatabase,
	}
	cat := taint.GetCatalog(rules.LangKotlin)
	if cat == nil {
		t.Fatal("Kotlin catalog not loaded")
	}
	got := map[string]taint.SourceCategory{}
	for _, s := range cat.Sources() {
		if _, ok := want[s.ID]; ok {
			got[s.ID] = s.Category
		}
	}
	for id, wantCat := range want {
		gotCat, ok := got[id]
		if !ok {
			t.Errorf("source %q not registered in Kotlin catalog", id)
			continue
		}
		if gotCat != wantCat {
			t.Errorf("source %q: want category %q, got %q", id, wantCat, gotCat)
		}
	}
}
