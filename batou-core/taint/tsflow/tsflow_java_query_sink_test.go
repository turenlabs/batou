package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// hasCWE89Flow reports whether any flow lands on a SnkSQLQuery sink tagged
// CWE-89 (SQL injection).
func hasCWE89Flow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.CWEID == "CWE-89" {
			return true
		}
	}
	return false
}

// TestJava_QuerySink_NoFalsePositiveOnBareQuery pins the GAP-java PART A fix.
//
// The tsflow matcher indexes sinks by MethodName, so a SQL sink that names the
// bare method "query" with an empty ObjectType becomes a catch-all `.query()`
// sink. On macrozheng/mall that fired CWE-89 on alipayService.query() — an
// Alipay API call, not SQL. The Vert.x SQL Client sink is now pinned to its
// concrete receiver shapes (pool/client/sqlClient/pgPool/mysqlPool/connection),
// so a bare `.query(` method name no longer fires CWE-89 without a DB/JDBC-like
// receiver, while genuine JDBC and Vert.x SQL sinks still fire.
func TestJava_QuerySink_NoFalsePositiveOnBareQuery(t *testing.T) {
	t.Run("alipayService.query is NOT CWE-89", func(t *testing.T) {
		code := `
public class PayController {
    private AlipayService alipayService;

    public String pay(javax.servlet.http.HttpServletRequest request) {
        String tradeNo = request.getParameter("tradeNo");
        return alipayService.query(tradeNo);
    }
}
`
		flows := Analyze(code, "/app/PayController.java", rules.LangJava)
		if hasCWE89Flow(flows) {
			t.Error("expected NO CWE-89 flow for alipayService.query() — it is an Alipay API call, not SQL")
			for _, f := range flows {
				t.Logf("  unexpected flow: src=%s sink=%s id=%s cwe=%s", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
			}
		}
	})

	t.Run("statement.executeQuery(sql) still fires CWE-89", func(t *testing.T) {
		code := `
import java.sql.*;

public class UserDao {
    private Connection conn;

    public ResultSet find(javax.servlet.http.HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return stmt.executeQuery(sql);
    }
}
`
		flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
		if !hasCWE89Flow(flows) {
			t.Error("expected CWE-89 flow for getParameter -> statement.executeQuery(sql)")
			for _, f := range flows {
				t.Logf("  flow: src=%s sink=%s id=%s cwe=%s", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
			}
		}
	})

	t.Run("jdbcTemplate.query(sql) still fires CWE-89", func(t *testing.T) {
		code := `
import org.springframework.jdbc.core.JdbcTemplate;

public class UserDao {
    private JdbcTemplate jdbcTemplate;

    public java.util.List<User> find(javax.servlet.http.HttpServletRequest request) {
        String name = request.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.query(sql, new UserRowMapper());
    }
}
`
		flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
		if !hasCWE89Flow(flows) {
			t.Error("expected CWE-89 flow for getParameter -> jdbcTemplate.query(sql)")
			for _, f := range flows {
				t.Logf("  flow: src=%s sink=%s id=%s cwe=%s", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
			}
		}
	})

	t.Run("Vert.x pool.query(sql) still fires CWE-89", func(t *testing.T) {
		code := `
import io.vertx.sqlclient.Pool;

public class OrderDao {
    private Pool pool;

    public void find(javax.servlet.http.HttpServletRequest request) {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM orders WHERE id = '" + id + "'";
        pool.query(sql).execute();
    }
}
`
		flows := Analyze(code, "/app/OrderDao.java", rules.LangJava)
		if !hasCWE89Flow(flows) {
			t.Error("expected CWE-89 flow for getParameter -> Vert.x pool.query(sql)")
			for _, f := range flows {
				t.Logf("  flow: src=%s sink=%s id=%s cwe=%s", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
			}
		}
	})
}
