package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Kotlin DataStax Cassandra Row read sources — second-order taint tests.
//
// Kotlin uses the same DataStax Java driver as Java (Row getter API) plus
// Spring Data Cassandra, but the Kotlin catalog had no Cassandra SOURCES, so
// attacker bytes written to a table on one request and read back via
// `row.getString(...)` later did not propagate taint. These fixtures read a
// column value out of a Cassandra Row and flow it, unsanitized, into a JDBC SQL
// sink (second-order CQL/SQL injection).
//
// All fixtures use the canonical receiver name `row` (from `val row = rs.one()`
// or `for (row in rs)`), which anchors to ObjectType "Row" via the matcher's
// direct/last-part name match. Fixtures intentionally:
//   - use `executeUpdate` (NOT `executeQuery`) and `UPDATE` SQL to avoid the
//     `Query(` / HTTP-method substring triggers in tsflow.isWebHandlerFunc that
//     auto-taint all parameters (cycle #759 gotcha).
//   - take no method parameters, so the only taint source is the Row read.
//   - use `+` string concatenation (the proven taint-propagation path) for both
//     scalar and collection getters, rather than index/iterator chains which can
//     lose taint on a freshly returned object (cycle #787 gotcha).
// =========================================================================

func runKotlinCassandraRowSourceTest(t *testing.T, code, sourceID string) {
	t.Helper()
	flows := Analyze(code, "/app/ProfileDao.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Source.ID == sourceID && f.Sink.Category == taint.SnkSQLQuery {
			return
		}
	}
	t.Errorf("expected SQL injection flow from %s -> SnkSQLQuery", sourceID)
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
	}
}

func TestKotlin_CassandraRowSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangKotlin)
	if cat == nil {
		t.Fatal("Kotlin catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"kotlin.cassandra.row.getstring",
		"kotlin.cassandra.row.getobject",
		"kotlin.cassandra.row.getlist",
		"kotlin.cassandra.row.getset",
		"kotlin.cassandra.row.getmap",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

func TestKotlin_CassandraRowSource_GetString_SQLi(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession
import java.sql.Connection

class ProfileDao(private val conn: Connection, private val session: CqlSession) {
    fun render() {
        val rs = session.execute("SELECT display_name FROM users LIMIT 1")
        val row = rs.one()
        val displayName = row.getString("display_name")
        val stmt = conn.createStatement()
        stmt.executeUpdate("UPDATE events SET label = '" + displayName + "' WHERE id = 1")
    }
}
`
	runKotlinCassandraRowSourceTest(t, code, "kotlin.cassandra.row.getstring")
}

func TestKotlin_CassandraRowSource_GetObject_SQLi(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession
import java.sql.Connection

class ProfileDao(private val conn: Connection, private val session: CqlSession) {
    fun render() {
        val rs = session.execute("SELECT meta FROM users LIMIT 1")
        val row = rs.one()
        val meta = row.getObject("meta")
        val stmt = conn.createStatement()
        stmt.executeUpdate("UPDATE events SET label = '" + meta + "' WHERE id = 1")
    }
}
`
	runKotlinCassandraRowSourceTest(t, code, "kotlin.cassandra.row.getobject")
}

func TestKotlin_CassandraRowSource_GetList_SQLi(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession
import java.sql.Connection

class ProfileDao(private val conn: Connection, private val session: CqlSession) {
    fun render() {
        val rs = session.execute("SELECT tags FROM users LIMIT 1")
        val row = rs.one()
        val tags = row.getList("tags", String::class.java)
        val stmt = conn.createStatement()
        stmt.executeUpdate("UPDATE events SET label = '" + tags + "' WHERE id = 1")
    }
}
`
	runKotlinCassandraRowSourceTest(t, code, "kotlin.cassandra.row.getlist")
}

func TestKotlin_CassandraRowSource_GetSet_SQLi(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession
import java.sql.Connection

class ProfileDao(private val conn: Connection, private val session: CqlSession) {
    fun render() {
        val rs = session.execute("SELECT roles FROM users LIMIT 1")
        val row = rs.one()
        val roles = row.getSet("roles", String::class.java)
        val stmt = conn.createStatement()
        stmt.executeUpdate("UPDATE events SET label = '" + roles + "' WHERE id = 1")
    }
}
`
	runKotlinCassandraRowSourceTest(t, code, "kotlin.cassandra.row.getset")
}

func TestKotlin_CassandraRowSource_GetMap_SQLi(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession
import java.sql.Connection

class ProfileDao(private val conn: Connection, private val session: CqlSession) {
    fun render() {
        val rs = session.execute("SELECT attrs FROM users LIMIT 1")
        val row = rs.one()
        val attrs = row.getMap("attrs", String::class.java, String::class.java)
        val stmt = conn.createStatement()
        stmt.executeUpdate("UPDATE events SET label = '" + attrs + "' WHERE id = 1")
    }
}
`
	runKotlinCassandraRowSourceTest(t, code, "kotlin.cassandra.row.getmap")
}

// Negative control: a hardcoded constant read into the same sink must NOT
// produce a flow (the Row getter is the only intended taint source).
func TestKotlin_CassandraRowSource_Constant_NoFlow(t *testing.T) {
	code := `
import java.sql.Connection

class ProfileDao(private val conn: Connection) {
    fun render() {
        val displayName = "static-label"
        val stmt = conn.createStatement()
        stmt.executeUpdate("UPDATE events SET label = '" + displayName + "' WHERE id = 1")
    }
}
`
	flows := Analyze(code, "/app/ProfileDao.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Source.ID == "kotlin.cassandra.row.getstring" {
			t.Error("expected NO SQL flow when value is a hardcoded constant")
		}
	}
}
