package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- GraphQL DataFetchingEnvironment sources (graphql-java / Netflix DGS / Spring GraphQL) ---

func TestJava_GraphQL_GetArgument_SQLInjection(t *testing.T) {
	code := `
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class UserResolver {
    public String fetchUser(DataFetchingEnvironment env) throws Exception {
        String name = env.getArgument("name");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        return name;
    }
}
`
	flows := Analyze(code, "/app/UserResolver.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getArgument to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_GraphQL_GetArguments_SQLInjection(t *testing.T) {
	code := `
import graphql.schema.DataFetchingEnvironment;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class ArgsResolver {
    public String lookup(DataFetchingEnvironment env) throws Exception {
        String args = env.getArguments();
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM items WHERE data = '" + args + "'");
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/ArgsResolver.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getArguments to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_GraphQL_GetVariables_SQLInjection(t *testing.T) {
	code := `
import graphql.schema.DataFetchingEnvironment;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Map;

public class VarResolver {
    public String lookup(DataFetchingEnvironment env) throws Exception {
        Map<String, Object> vars = env.getVariables();
        String id = (String) vars.get("id");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM items WHERE id = " + id);
        return id;
    }
}
`
	flows := Analyze(code, "/app/VarResolver.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getVariables to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJava_GraphQL_GetSource_SQLInjection(t *testing.T) {
	code := `
import graphql.schema.DataFetchingEnvironment;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class PostResolver {
    public String title(DataFetchingEnvironment env) throws Exception {
        String parent = env.getSource();
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT title FROM posts WHERE id = '" + parent + "'");
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/PostResolver.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getSource() to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (conf: %.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}
