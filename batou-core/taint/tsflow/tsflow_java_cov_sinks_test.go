package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// hasCovCWE reports whether any flow lands on a sink tagged with the given CWE.
func hasCovCWE(flows []taint.TaintFlow, cwe string) bool {
	for _, f := range flows {
		if f.Sink.CWEID == cwe {
			return true
		}
	}
	return false
}

// JDO PersistenceManager.newQuery(String) with a concatenated filter — JDO/SQL
// injection (CWE-89).
func TestJavaCov_JDO_NewQuery_Tainted(t *testing.T) {
	code := `
import javax.jdo.PersistenceManager;
public class Dao {
    private PersistenceManager pm;
    public Object find(javax.servlet.http.HttpServletRequest request) {
        String name = request.getParameter("name");
        return pm.newQuery("SELECT FROM Account WHERE owner == '" + name + "'");
    }
}
`
	flows := Analyze(code, "/app/Dao.java", rules.LangJava)
	if !hasCovCWE(flows, "CWE-89") {
		t.Errorf("expected CWE-89 flow for JDO pm.newQuery(concatenated filter)")
		for _, f := range flows {
			t.Logf("  flow: sink=%s id=%s cwe=%s", f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// JDO parameterized binding (declareParameters) must keep the query clean.
func TestJavaCov_JDO_Parameterized_Safe(t *testing.T) {
	code := `
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
public class Dao {
    private PersistenceManager pm;
    public Object find(javax.servlet.http.HttpServletRequest request) {
        String name = request.getParameter("name");
        Query q = pm.newQuery("SELECT FROM Account WHERE owner == :owner");
        q.declareParameters("String owner");
        return q.execute(name);
    }
}
`
	flows := Analyze(code, "/app/Dao.java", rules.LangJava)
	// The newQuery argument is a string literal (no concat), so no taint flow.
	if hasSinkID(flows, "java.jdo.pm.newquery") {
		t.Errorf("expected NO JDO injection flow for a literal parameterized query")
	}
}

// Apache Turbine BasePeer.executeQuery(String) with concatenated SQL (CWE-89).
func TestJavaCov_Turbine_BasePeer_Tainted(t *testing.T) {
	code := `
import org.apache.turbine.om.peer.BasePeer;
public class UserPeer {
    public java.util.List load(javax.servlet.http.HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        return BasePeer.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
`
	flows := Analyze(code, "/app/UserPeer.java", rules.LangJava)
	if !hasCovCWE(flows, "CWE-89") {
		t.Errorf("expected CWE-89 flow for Turbine BasePeer.executeQuery(concat)")
		for _, f := range flows {
			t.Logf("  flow: sink=%s id=%s cwe=%s", f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// JBoss Seam Log.error(String) with tainted CR/LF content (CWE-117).
func TestJavaCov_Seam_Log_Tainted(t *testing.T) {
	code := `
import org.jboss.seam.log.Log;
public class Audit {
    private Log log;
    public void record(javax.servlet.http.HttpServletRequest request) {
        String user = request.getParameter("user");
        log.error("login failed for " + user);
    }
}
`
	flows := Analyze(code, "/app/Audit.java", rules.LangJava)
	if !hasCovCWE(flows, "CWE-117") {
		t.Errorf("expected CWE-117 log-injection flow for Seam log.error(concat)")
		for _, f := range flows {
			t.Logf("  flow: sink=%s id=%s cwe=%s", f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// Note: SearchControls.setReturningObjFlag(true) is a config anti-pattern
// (the dangerous argument is the literal `true`, not a tainted value), so it
// is covered by the regex rule BATOU-JAVA-041, not by a taint sink. See
// batou-rules/rules/java/java_cov_test.go.
