package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// COVERAGE ADD (cov/java) — CWE-89 SQL injection across the Spring/ORM SQL
// execution paths real apps call that were previously absent:
//   - Spring NamedParameterJdbcTemplate
//   - jOOQ instance DSLContext plain-SQL overloads
//   - JDBI v3 Handle
//   - MyBatis-Plus QueryWrapper raw-fragment (apply/last)
//
// Each TP fixture seeds taint from request.getParameter and concatenates it
// into the SQL string passed to the new sink. Each safe fixture either binds
// the value via the framework's parameterization API (the paired sanitizer) or
// uses a constant string, and must stay clean.
// =========================================================================

func TestJava_NamedParamJdbc_SQLInjection(t *testing.T) {
	code := `
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import javax.servlet.http.HttpServletRequest;

public class UserRepo {
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    public Object find(HttpServletRequest request) {
        String name = request.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return namedParameterJdbcTemplate.queryForObject(sql, new java.util.HashMap<>(), Object.class);
    }
}
`
	flows := Analyze(code, "/app/UserRepo.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> NamedParameterJdbcTemplate.queryForObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_NamedParamJdbc_Constant_NoFlow(t *testing.T) {
	code := `
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

public class StaticRepo {
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    public Object find() {
        String sql = "SELECT * FROM users WHERE active = true";
        return namedParameterJdbcTemplate.queryForObject(sql, new java.util.HashMap<>(), Object.class);
    }
}
`
	flows := Analyze(code, "/app/StaticRepo.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a constant SQL string")
	}
}

func TestJava_JooqDSLContext_SQLInjection(t *testing.T) {
	code := `
import org.jooq.DSLContext;
import javax.servlet.http.HttpServletRequest;

public class ReportDao {
    private DSLContext create;

    public Object run(HttpServletRequest request) {
        String table = request.getParameter("table");
        String sql = "SELECT * FROM " + table;
        return create.fetch(sql);
    }
}
`
	flows := Analyze(code, "/app/ReportDao.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> DSLContext.fetch(String)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_JooqDSLContext_ResultQuery_SQLInjection(t *testing.T) {
	code := `
import org.jooq.DSLContext;
import javax.servlet.http.HttpServletRequest;

public class ReportDao {
    private DSLContext dsl;

    public Object run(HttpServletRequest request) {
        String col = request.getParameter("col");
        return dsl.resultQuery("SELECT " + col + " FROM t");
    }
}
`
	flows := Analyze(code, "/app/ReportDao.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> DSLContext.resultQuery(String)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_JdbiHandle_SQLInjection(t *testing.T) {
	code := `
import org.jdbi.v3.core.Handle;
import javax.servlet.http.HttpServletRequest;

public class AccountDao {
    public Object load(Handle handle, HttpServletRequest request) {
        String id = request.getParameter("id");
        return handle.createQuery("SELECT * FROM accounts WHERE id = " + id).mapToMap().list();
    }
}
`
	flows := Analyze(code, "/app/AccountDao.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> Handle.createQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_JdbiHandle_Bound_NoFlow(t *testing.T) {
	code := `
import org.jdbi.v3.core.Handle;
import javax.servlet.http.HttpServletRequest;

public class AccountDao {
    public Object load(Handle handle, HttpServletRequest request) {
        String id = request.getParameter("id");
        return handle.createQuery("SELECT * FROM accounts WHERE id = :id").bind("id", id).mapToMap().list();
    }
}
`
	flows := Analyze(code, "/app/AccountDao.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a JDBI .bind()-parameterized query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_MyBatisPlusWrapper_ApplyRawFragment_SQLInjection(t *testing.T) {
	code := `
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import javax.servlet.http.HttpServletRequest;

public class OrderService {
    public void search(HttpServletRequest request) {
        String orderBy = request.getParameter("sort");
        QueryWrapper qw = new QueryWrapper();
        qw.apply("order_no = " + orderBy);
    }
}
`
	flows := Analyze(code, "/app/OrderService.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> QueryWrapper.apply(raw)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_MyBatisPlusWrapper_TypedEq_NoFlow(t *testing.T) {
	code := `
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import javax.servlet.http.HttpServletRequest;

public class OrderService {
    public void search(HttpServletRequest request) {
        String orderNo = request.getParameter("no");
        QueryWrapper qw = new QueryWrapper();
        qw.eq("order_no", orderNo);
    }
}
`
	flows := Analyze(code, "/app/OrderService.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for QueryWrapper.eq() typed parameter binding")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// =========================================================================
// COVERAGE ADD (cov/java) — Zip Slip via ZipEntry.getName() SOURCE (CWE-22).
// The entry-name read flows into an existing FileOutputStream FileWrite sink.
// =========================================================================

func TestJava_ZipEntryGetName_ZipSlip(t *testing.T) {
	code := `
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.io.File;
import java.io.FileOutputStream;

public class Extractor {
    public void extract(ZipFile zipFile, File destDir) throws Exception {
        java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            File out = new File(destDir, name);
            FileOutputStream fos = new FileOutputStream(out);
        }
    }
}
`
	flows := Analyze(code, "/app/Extractor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow for ZipEntry.getName() -> new File / FileOutputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_SinksRegistered_Coverage(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	sinkIDs := map[string]bool{}
	for _, s := range cat.Sinks() {
		sinkIDs[s.ID] = true
	}
	for _, id := range []string{
		"java.spring.namedparamjdbc.queryforobject",
		"java.jooq.dslcontext.fetch",
		"java.jdbi.handle.createquery",
		"java.mybatisplus.wrapper.apply",
	} {
		if !sinkIDs[id] {
			t.Errorf("missing expected sink: %s", id)
		}
	}
	srcIDs := map[string]bool{}
	for _, s := range cat.Sources() {
		srcIDs[s.ID] = true
	}
	if !srcIDs["java.zip.zipentry.getname"] {
		t.Error("missing expected source: java.zip.zipentry.getname")
	}
	sanIDs := map[string]bool{}
	for _, s := range cat.Sanitizers() {
		sanIDs[s.ID] = true
	}
	for _, id := range []string{"java.jdbi.bind", "java.spring.mapsqlparametersource", "java.mybatisplus.wrapper.eq"} {
		if !sanIDs[id] {
			t.Errorf("missing expected sanitizer: %s", id)
		}
	}
}
