package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java DataStax Cassandra Row read sources — second-order taint tests.
//
// Java's catalog already had Cassandra SINKS (java.cassandra.cqlsession.execute,
// .executeAsync, java.cassandra.simplestatement.newinstance/.builder,
// java.spring.cassandratemplate.select) but no Cassandra SOURCES, so attacker
// bytes written to a table on one request and read back via `row.getString(...)`
// later did not propagate taint. These fixtures read a column value out of a
// Cassandra Row and flow it, unsanitized, into a SQL / CQL / command sink.
//
// All fixtures use the canonical receiver name `row` (from `Row row = rs.one()`
// or `for (Row row : rs)`), which anchors to ObjectType "Row" via the matcher's
// prefix-abbreviation heuristic. The `private Connection conn;` field +
// `Statement stmt = conn.createStatement();` shape mirrors
// tsflow_java_mongodb_sources_test.go — `executeQuery(` trips isWebHandlerFunc
// but the handler methods take no parameters, so nothing is auto-seeded and the
// only taint source is the Row read under test.
//
// Collection getters follow the Java Set/iterator propagation rules: List uses
// `.get(0)` (propagates), Set/Map use direct string concatenation (implicit
// toString() goes through the `+` operator taint path) rather than
// `.iterator().next()` which loses taint on the fresh iterator object.
// =========================================================================

func TestJava_CassandraRowSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"java.cassandra.row.getstring",
		"java.cassandra.row.getobject",
		"java.cassandra.row.getlist",
		"java.cassandra.row.getset",
		"java.cassandra.row.getmap",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// ---------- Row.getString(name) → SQL injection (CWE-89) ----------

func TestJava_CassandraRow_GetString_SQLInjection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;
import java.sql.*;

public class ProfileRepo {
    private Connection conn;
    private CqlSession session;

    public void render() throws Exception {
        ResultSet rs = session.execute("SELECT display_name FROM users LIMIT 1");
        Row row = rs.one();
        String displayName = row.getString("display_name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE name = '" + displayName + "'");
    }
}
`
	flows := Analyze(code, "/app/ProfileRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getString -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Row.getObject(index) → CQL injection (CWE-943) ----------

func TestJava_CassandraRow_GetObject_CQLInjection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;

public class TenantRepo {
    private CqlSession session;

    public void lookup() throws Exception {
        ResultSet rs = session.execute("SELECT tenant FROM ctx LIMIT 1");
        Row row = rs.one();
        Object tenant = row.getObject(0);
        session.execute("SELECT * FROM data WHERE tenant = '" + tenant + "'");
    }
}
`
	flows := Analyze(code, "/app/TenantRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for Row.getObject -> CqlSession.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Row.getList(name, clazz) → command injection (CWE-78) ----------

func TestJava_CassandraRow_GetList_CommandInjection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;
import java.util.List;

public class JobRepo {
    private CqlSession session;

    public void runQueued() throws Exception {
        ResultSet rs = session.execute("SELECT commands FROM jobs LIMIT 1");
        Row row = rs.one();
        List<String> commands = row.getList("commands", String.class);
        String cmd = commands.get(0);
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/JobRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Row.getList -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Row.getSet(name, clazz) → SQL injection (CWE-89) ----------

func TestJava_CassandraRow_GetSet_SQLInjection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;
import java.util.Set;
import java.sql.*;

public class TagRepo {
    private Connection conn;
    private CqlSession session;

    public void report() throws Exception {
        ResultSet rs = session.execute("SELECT tags FROM articles LIMIT 1");
        Row row = rs.one();
        Set<String> tags = row.getSet("tags", String.class);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM tag_stats WHERE tag IN (" + tags + ")");
    }
}
`
	flows := Analyze(code, "/app/TagRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getSet -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Row.getMap(name, k, v) → SQL injection (CWE-89) ----------

func TestJava_CassandraRow_GetMap_SQLInjection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;
import java.util.Map;
import java.sql.*;

public class MetaRepo {
    private Connection conn;
    private CqlSession session;

    public void dump() throws Exception {
        ResultSet rs = session.execute("SELECT meta FROM docs LIMIT 1");
        Row row = rs.one();
        Map<String, String> meta = row.getMap("meta", String.class, String.class);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("INSERT INTO meta_mirror(body) VALUES ('" + meta + "')");
    }
}
`
	flows := Analyze(code, "/app/MetaRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getMap -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Negative control: constant CQL read, no tainted column value ----------

func TestJava_CassandraRow_ConstantValue_NoFlow(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession;
import java.sql.*;

public class StaticRepo {
    private Connection conn;
    private CqlSession session;

    public void render() throws Exception {
        String displayName = "anonymous";
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE name = '" + displayName + "'");
    }
}
`
	flows := Analyze(code, "/app/StaticRepo.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a constant display name (no Row read)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
