package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Neo4j Cypher injection sinks (CWE-943).
// Neo4j executes Cypher via Session/Transaction/Neo4jClient.run|query; if the
// Cypher string is built from user input, attackers can alter graph semantics.
// Safe code passes values as a Map<String, Object> parameter argument.

// --- Neo4j direct driver: Session.run ---

func TestJava_Neo4j_Session_Run_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;

public class Handler extends HttpServlet {
    private Session session;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String cypher = "MATCH (n:User {name: '" + name + "'}) RETURN n";
        Result result = session.run(cypher);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for getParameter -> Session.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Neo4j direct driver: Transaction.run (explicit begin/commit) ---

func TestJava_Neo4j_Tx_Run_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.neo4j.driver.Session;
import org.neo4j.driver.Transaction;

public class Handler extends HttpServlet {
    private Session session;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String label = request.getParameter("label");
        String cypher = "CREATE (:" + label + " {id: 1})";
        Transaction tx = session.beginTransaction();
        tx.run(cypher);
        tx.commit();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for getParameter -> Transaction.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Neo4j AsyncSession.runAsync ---

func TestJava_Neo4j_AsyncSession_RunAsync_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.neo4j.driver.async.AsyncSession;

public class Handler extends HttpServlet {
    private AsyncSession asyncSession;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        String cypher = "MATCH (n) WHERE id(n) = " + id + " RETURN n";
        asyncSession.runAsync(cypher);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for getParameter -> AsyncSession.runAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring Data Neo4j: Neo4jClient.query ---

func TestJava_Neo4j_Neo4jClient_Query_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.data.neo4j.core.Neo4jClient;

public class Handler extends HttpServlet {
    private Neo4jClient neo4jClient;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String title = request.getParameter("title");
        String cypher = "MATCH (p:Post) WHERE p.title = '" + title + "' RETURN p";
        neo4jClient.query(cypher).fetch().all();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for getParameter -> Neo4jClient.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: parameterized Cypher ---

func TestJava_Neo4j_Session_Run_Parameterized_NoFlow(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.util.Map;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;

public class Handler extends HttpServlet {
    private Session session;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        Result result = session.run("MATCH (n:User {name: $name}) RETURN n", Map.of("name", name));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO Cypher-injection flow when Cypher is a literal and values are passed via parameters map")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink pattern: %s)", f.Source.Category, f.Sink.Category, f.Sink.Pattern)
		}
	}
}

// --- Safe: hardcoded Cypher ---

func TestJava_Neo4j_Session_Run_Hardcoded_NoFlow(t *testing.T) {
	code := `
import org.neo4j.driver.Session;

public class Handler {
    private Session session;
    public void run() {
        session.run("MATCH (n:User {name: 'bob'}) RETURN n");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO Cypher-injection flow for hardcoded Cypher literal")
	}
}
