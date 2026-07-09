package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Recall test (SasanLabs/VulnerableApp, ErrorBasedSQLInjectionVulnerability):
// a Spring app autowires its JdbcTemplate bean under a QUALIFIER-PREFIXED field
// name (`applicationJdbcTemplate`, not the bare `jdbcTemplate`) — the idiomatic
// shape when more than one JdbcTemplate bean exists. The JdbcTemplate CWE-89
// sinks (ObjectType "JdbcTemplate", MethodName query/update/execute/…) were
// dead for any such field because the matcher's abbreviation heuristic only
// accepted a receiver that is a PREFIX of the type's last component
// ("jdbc" → "jdbctemplate"), never a receiver whose tail IS the type
// ("applicationJdbcTemplate" ends with "JdbcTemplate"). The receiver-suffix
// alias in matchesCatalogEntry closes that gap.
func TestJava_QualifiedJdbcTemplate_ConcatSQLi_Fires(t *testing.T) {
	code := `
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class ErrorBasedSQLInjectionVulnerability {
    private JdbcTemplate applicationJdbcTemplate;

    public String doesCarInformationExistsLevel1(@RequestParam String id) {
        return applicationJdbcTemplate.query(
            "select * from cars where id=" + id,
            (rs) -> "x");
    }
}
`
	flows := Analyze(code, "/app/ErrorBasedSQLInjectionVulnerability.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected applicationJdbcTemplate.query(\"...\" + id, mapper) to flag CWE-89 SQL injection (qualifier-prefixed JdbcTemplate field)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Coverage of other common qualifier prefixes (readOnly/primary/app) — all are
// the same `*JdbcTemplate` field-naming convention and must all fire.
func TestJava_QualifiedJdbcTemplate_Variants_Fire(t *testing.T) {
	for _, field := range []string{"readOnlyJdbcTemplate", "primaryJdbcTemplate", "appJdbcTemplate"} {
		code := `
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class Repo {
    private JdbcTemplate ` + field + `;

    public Object find(@RequestParam String id) {
        return ` + field + `.queryForObject("select * from cars where id=" + id, Long.class);
    }
}
`
		flows := Analyze(code, "/app/Repo.java", rules.LangJava)
		if !hasTaintFlow(flows, taint.SnkSQLQuery) {
			t.Errorf("expected %s.queryForObject(\"...\" + id, ...) to flag CWE-89 SQL injection", field)
		}
	}
}

// Negative 1: the PARAMETERIZED form — a constant SQL string with a `?`
// placeholder bound via a PreparedStatementSetter — carries no taint into arg 0
// and must NOT flag, even though the receiver is a qualifier-prefixed
// JdbcTemplate. Mirrors VulnerableApp's safe BlindSQLInjection level
// (`prepareStatement("... id=?")`).
func TestJava_QualifiedJdbcTemplate_Parameterized_Clean(t *testing.T) {
	code := `
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class Repo {
    private JdbcTemplate applicationJdbcTemplate;

    public Object find(@RequestParam String id) {
        return applicationJdbcTemplate.query(
            (conn) -> conn.prepareStatement("select * from cars where id=?"),
            (ps) -> ps.setString(1, id),
            (rs) -> "x");
    }
}
`
	flows := Analyze(code, "/app/Repo.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected parameterized prepareStatement(\"...?\") form to NOT flag SQL injection (constant first arg, value bound via setString)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative 2: a constant SQL string with no tainted concatenation must stay
// clean — proves the alias is only a sink MATCH and still requires a tainted
// arg 0.
func TestJava_QualifiedJdbcTemplate_ConstantSQL_Clean(t *testing.T) {
	code := `
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

public class Repo {
    private JdbcTemplate applicationJdbcTemplate;

    public Object findAll(@RequestParam String unused) {
        return applicationJdbcTemplate.query("select * from cars", (rs) -> "x");
    }
}
`
	flows := Analyze(code, "/app/Repo.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected constant-SQL query to NOT flag SQL injection")
	}
}
