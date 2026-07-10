package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ClickHouse SQL-injection sinks for Java.
//
// Two distinct APIs are covered:
//
//  1. clickhouse-java client-v2 (com.clickhouse.client.api.Client) — exposes
//     queryAll(sql), queryRecords(sql), and getTableSchemaFromQuery(sql) that
//     take raw SQL strings; the parameterized overload requires
//     query(sql, Map<String,Object> params, QuerySettings).
//
//  2. Legacy clickhouse-jdbc driver (ru.yandex.clickhouse / com.clickhouse.jdbc
//     ClickHouseStatement) — extends Statement with executeQueryClickhouse-
//     Response, executeQueryClickhouseRowBinaryStream, and sendRowBinaryStream
//     that bypass JDBC PreparedStatement entirely.
//
// All listed method names are unique to ClickHouse so an empty ObjectType is
// safe; tainted servlet input flowing into arg 0 is CWE-89.

// --- client-v2: Client.queryAll ---

func TestJava_ClickHouse_Client_QueryAll_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.clickhouse.client.api.Client;
import com.clickhouse.data.value.GenericRecord;
import java.util.List;

public class Handler extends HttpServlet {
    private Client client;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("id");
        String sql = "SELECT id, name FROM users WHERE id = '" + userId + "'";
        List<GenericRecord> rows = client.queryAll(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.clickhouse.client.queryall") {
		t.Error("expected java.clickhouse.client.queryall finding for getParameter -> Client.queryAll")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- client-v2: Client.queryRecords ---

func TestJava_ClickHouse_Client_QueryRecords_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.clickhouse.client.api.Client;
import com.clickhouse.client.api.query.Records;

public class Handler extends HttpServlet {
    private Client client;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String table = request.getParameter("table");
        String sql = "SELECT * FROM " + table + " ORDER BY ts DESC";
        Records records = client.queryRecords(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.clickhouse.client.queryrecords") {
		t.Error("expected java.clickhouse.client.queryrecords finding for getParameter -> Client.queryRecords")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- client-v2: Client.getTableSchemaFromQuery ---

func TestJava_ClickHouse_Client_GetTableSchemaFromQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.clickhouse.client.api.Client;
import com.clickhouse.client.api.metadata.TableSchema;

public class Handler extends HttpServlet {
    private Client client;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filter = request.getParameter("filter");
        String sql = "SELECT * FROM events WHERE region = '" + filter + "' LIMIT 0";
        TableSchema schema = client.getTableSchemaFromQuery(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.clickhouse.client.gettableschemafromquery") {
		t.Error("expected java.clickhouse.client.gettableschemafromquery finding for getParameter -> Client.getTableSchemaFromQuery")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- legacy yandex JDBC: ClickHouseStatement.executeQueryClickhouseResponse ---

func TestJava_ClickHouse_Statement_ExecuteQueryClickhouseResponse_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import ru.yandex.clickhouse.ClickHouseStatement;
import ru.yandex.clickhouse.response.ClickHouseResponse;

public class Handler extends HttpServlet {
    private ClickHouseStatement stmt;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String col = request.getParameter("col");
        String sql = "SELECT " + col + " FROM big_table";
        ClickHouseResponse resp = stmt.executeQueryClickhouseResponse(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.clickhouse.statement.executequeryclickhouseresponse") {
		t.Error("expected java.clickhouse.statement.executequeryclickhouseresponse finding for getParameter -> ClickHouseStatement.executeQueryClickhouseResponse")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- legacy yandex JDBC: ClickHouseStatement.executeQueryClickhouseRowBinaryStream ---

func TestJava_ClickHouse_Statement_ExecuteQueryClickhouseRowBinaryStream_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import ru.yandex.clickhouse.ClickHouseStatement;
import ru.yandex.clickhouse.response.ClickHouseRowBinaryInputStream;

public class Handler extends HttpServlet {
    private ClickHouseStatement stmt;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tbl = request.getParameter("t");
        String sql = "SELECT * FROM " + tbl;
        ClickHouseRowBinaryInputStream is = stmt.executeQueryClickhouseRowBinaryStream(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.clickhouse.statement.executequeryclickhouserowbinarystream") {
		t.Error("expected java.clickhouse.statement.executequeryclickhouserowbinarystream finding for getParameter -> ClickHouseStatement.executeQueryClickhouseRowBinaryStream")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- legacy yandex JDBC: ClickHouseStatement.sendRowBinaryStream ---

func TestJava_ClickHouse_Statement_SendRowBinaryStream_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import ru.yandex.clickhouse.ClickHouseStatement;
import ru.yandex.clickhouse.util.ClickHouseStreamCallback;

public class Handler extends HttpServlet {
    private ClickHouseStatement stmt;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tbl = request.getParameter("table");
        String sql = "INSERT INTO " + tbl + " FORMAT RowBinary";
        stmt.sendRowBinaryStream(sql, new ClickHouseStreamCallback() {
            public void writeTo(ru.yandex.clickhouse.util.ClickHouseRowBinaryStream out) {}
        });
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !findSinkID(flows, "java.clickhouse.statement.sendrowbinarystream") {
		t.Error("expected java.clickhouse.statement.sendrowbinarystream finding for getParameter -> ClickHouseStatement.sendRowBinaryStream")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// =========================================================================
// Safe pattern: parameterized v2 query overload — no flow expected.
// Client#query(String sql, Map<String,Object> params, QuerySettings settings)
// uses server-side `{name:Type}` placeholders; user data flows into the
// params map, never the SQL string template.
// =========================================================================

func TestJava_ClickHouse_Client_ParameterizedQuery_Safe(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.clickhouse.client.api.Client;
import com.clickhouse.client.api.query.QuerySettings;
import java.util.Collections;
import java.util.Map;

public class Handler extends HttpServlet {
    private Client client;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("id");
        Map<String, Object> params = Collections.singletonMap("uid", userId);
        client.query("SELECT id, name FROM users WHERE id = {uid:String}", params, new QuerySettings());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		// None of the new ClickHouse-specific sinks should fire on this safe path.
		switch f.Sink.ID {
		case "java.clickhouse.client.queryall",
			"java.clickhouse.client.queryrecords",
			"java.clickhouse.client.gettableschemafromquery",
			"java.clickhouse.statement.executequeryclickhouseresponse",
			"java.clickhouse.statement.executequeryclickhouserowbinarystream",
			"java.clickhouse.statement.sendrowbinarystream":
			t.Errorf("expected NO ClickHouse SQL injection flow for parameterized query; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.ID, f.Confidence)
		}
	}
}
