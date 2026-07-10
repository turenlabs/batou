package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// DataStax Cassandra / ScyllaDB CQL-injection sinks for Java.
// CqlSession (driver 4.x) and Session (legacy 3.x) accept raw CQL strings
// as their first argument, so tainted servlet input flowing into arg 0
// is CWE-943. Spring Data Cassandra's CqlTemplate/CassandraTemplate wrap
// the driver and expose the same String-arg surface.

// --- DataStax driver: CqlSession.execute ---

func TestJava_Cassandra_CqlSession_Execute_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;

public class Handler extends HttpServlet {
    private CqlSession cqlSession;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("id");
        String cql = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = cqlSession.execute(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.cassandra.cqlsession.execute") {
		t.Error("expected java.cassandra.cqlsession.execute finding for getParameter -> CqlSession.execute")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- DataStax driver: CqlSession.executeAsync ---

func TestJava_Cassandra_CqlSession_ExecuteAsync_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.AsyncResultSet;
import java.util.concurrent.CompletionStage;

public class Handler extends HttpServlet {
    private CqlSession cqlSession;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String cql = "SELECT * FROM accounts WHERE name = '" + name + "'";
        CompletionStage<AsyncResultSet> stage = cqlSession.executeAsync(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.cassandra.cqlsession.executeasync") {
		t.Error("expected java.cassandra.cqlsession.executeasync finding for getParameter -> CqlSession.executeAsync")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- DataStax driver: SimpleStatement.newInstance (static) ---

func TestJava_Cassandra_SimpleStatement_NewInstance_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String table = request.getParameter("table");
        String cql = "SELECT * FROM " + table + " LIMIT 100";
        SimpleStatement stmt = SimpleStatement.newInstance(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.cassandra.simplestatement.newinstance") {
		t.Error("expected java.cassandra.simplestatement.newinstance finding for getParameter -> SimpleStatement.newInstance")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- DataStax driver: SimpleStatement.builder (static) ---

func TestJava_Cassandra_SimpleStatement_Builder_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.datastax.oss.driver.api.core.cql.SimpleStatementBuilder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("id");
        String cql = "SELECT * FROM users WHERE id = '" + userId + "'";
        SimpleStatementBuilder b = SimpleStatement.builder(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.cassandra.simplestatement.builder") {
		t.Error("expected java.cassandra.simplestatement.builder finding for getParameter -> SimpleStatement.builder")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Spring Data Cassandra: CqlTemplate.execute ---

func TestJava_Cassandra_SpringCqlTemplate_Execute_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.data.cassandra.core.cql.CqlTemplate;

public class Handler extends HttpServlet {
    private CqlTemplate cqlTemplate;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tableName = request.getParameter("table");
        String cql = "TRUNCATE " + tableName;
        cqlTemplate.execute(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.spring.cqltemplate.execute") {
		t.Error("expected java.spring.cqltemplate.execute finding for getParameter -> CqlTemplate.execute")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Spring Data Cassandra: CqlTemplate.query ---

func TestJava_Cassandra_SpringCqlTemplate_Query_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.util.List;
import org.springframework.data.cassandra.core.cql.CqlTemplate;
import org.springframework.jdbc.core.RowMapper;

public class Handler extends HttpServlet {
    private CqlTemplate cqlTemplate;
    private RowMapper<String> mapper;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String cql = "SELECT email FROM users WHERE name = '" + name + "'";
        List<String> emails = cqlTemplate.query(cql, mapper);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.spring.cqltemplate.query") {
		t.Error("expected java.spring.cqltemplate.query finding for getParameter -> CqlTemplate.query")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Spring Data Cassandra: CqlTemplate.queryForObject ---

func TestJava_Cassandra_SpringCqlTemplate_QueryForObject_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.data.cassandra.core.cql.CqlTemplate;

public class Handler extends HttpServlet {
    private CqlTemplate cqlTemplate;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("id");
        String cql = "SELECT email FROM users WHERE id = '" + userId + "'";
        String email = cqlTemplate.queryForObject(cql, String.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.spring.cqltemplate.queryforobject") {
		t.Error("expected java.spring.cqltemplate.queryforobject finding for getParameter -> CqlTemplate.queryForObject")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Spring Data Cassandra: CassandraTemplate.select(String cql, ...) ---

func TestJava_Cassandra_SpringCassandraTemplate_Select_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.util.List;
import org.springframework.data.cassandra.core.CassandraTemplate;

public class Handler extends HttpServlet {
    private CassandraTemplate cassandraTemplate;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String cql = "SELECT * FROM users WHERE name = '" + name + "'";
        List<Object> rows = cassandraTemplate.select(cql, Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.spring.cassandratemplate.select") {
		t.Error("expected java.spring.cassandratemplate.select finding for getParameter -> CassandraTemplate.select")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Safe: hardcoded CQL string with no user input in arg 0 ---
// Tainted user input is logged elsewhere but never reaches the CQL string
// itself. The new Cassandra sinks must NOT fire on a constant CQL.

func TestJava_Cassandra_ConstantCql_Safe(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.util.logging.Logger;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;

public class Handler extends HttpServlet {
    private CqlSession cqlSession;
    private static final Logger log = Logger.getLogger("h");
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        log.info("requested by " + name);
        ResultSet rs = cqlSession.execute("SELECT * FROM activity WHERE day = '2026-04-30'");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		switch f.Sink.ID {
		case "java.cassandra.cqlsession.execute",
			"java.cassandra.cqlsession.executeasync",
			"java.cassandra.simplestatement.newinstance",
			"java.cassandra.simplestatement.builder",
			"java.spring.cqltemplate.execute",
			"java.spring.cqltemplate.query",
			"java.spring.cqltemplate.queryforobject",
			"java.spring.cassandratemplate.select":
			t.Errorf("unexpected finding on constant CQL string: sink=%s", f.Sink.ID)
		}
	}
}

// --- Header-source: HttpServletRequest.getHeader -> CqlSession.execute ---
// Verifies a non-getParameter source (HTTP header) also flows into the
// new Cassandra sinks. Different source category, same SnkSQLQuery sink.

func TestJava_Cassandra_HeaderSource_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.datastax.oss.driver.api.core.CqlSession;

public class Handler extends HttpServlet {
    private CqlSession cqlSession;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tenant = request.getHeader("X-Tenant");
        cqlSession.execute("SELECT * FROM data_" + tenant + " LIMIT 100");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.cassandra.cqlsession.execute") {
		t.Error("expected java.cassandra.cqlsession.execute finding for getHeader -> CqlSession.execute")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}
