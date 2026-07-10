package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// hasTaintFlowCWE reports whether any flow's sink has the given CWE id.
func hasTaintFlowCWE(flows []taint.TaintFlow, cwe string) bool {
	for _, f := range flows {
		if f.Sink.CWEID == cwe {
			return true
		}
	}
	return false
}

// TestCPP_Interproc_ArgvToSqliteExec covers the canonical two-function shape
// where the SOURCE (argv) lives in the caller (main) and the SINK
// (sqlite3_exec) lives in the callee (lookup_user). Before the interprocedural
// call-site emission + the pointer/reference parameter extraction fixes,
// neither per-function walk observed the full source→sink flow, so this
// real-world SQL injection produced zero findings.
func TestCPP_Interproc_ArgvToSqliteExec(t *testing.T) {
	code := `
#include <string>
struct sqlite3;
extern int sqlite3_exec(sqlite3 *db, const char *sql, void*, void*, char **errmsg);

void lookup_user(sqlite3 *db, const std::string &username) {
    std::string query = "SELECT id FROM users WHERE username = '" + username + "'";
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
}

int main(int argc, char *argv[]) {
    sqlite3 *db = nullptr;
    lookup_user(db, argv[1]);
    return 0;
}
`
	flows := Analyze(code, "/app/sqli.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatalf("expected interprocedural SQL injection flow argv -> sqlite3_exec; got %d flows", len(flows))
	}
	if !hasTaintFlowCWE(flows, "CWE-89") {
		t.Errorf("expected CWE-89 on the interprocedural SQL flow")
	}
}

// TestCPP_Interproc_Safe_ParameterizedQuery is the matching SAFE variant: the
// callee uses a prepared statement with a bound parameter, so the tainted argv
// never reaches a raw-SQL sink. The interprocedural emission must NOT fire.
func TestCPP_Interproc_Safe_ParameterizedQuery(t *testing.T) {
	code := `
#include <string>
struct sqlite3; struct sqlite3_stmt;
extern int sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void*);

void lookup_user(sqlite3 *db, const std::string &username) {
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT id FROM users WHERE username = ?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, nullptr);
}

int main(int argc, char *argv[]) {
    sqlite3 *db = nullptr;
    lookup_user(db, argv[1]);
    return 0;
}
`
	flows := Analyze(code, "/app/sqli_safe.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("parameterized query must NOT produce a SQL injection flow; got %d flows", len(flows))
	}
}

// TestCPP_Interproc_Safe_ConstantArg confirms the interprocedural emission is
// taint-gated: a callee whose parameter reaches a SQL sink does not produce a
// finding when the caller passes a constant (non-tainted) argument.
func TestCPP_Interproc_Safe_ConstantArg(t *testing.T) {
	code := `
#include <string>
struct sqlite3;
extern int sqlite3_exec(sqlite3 *db, const char *sql, void*, void*, char **errmsg);

void run_query(sqlite3 *db, const std::string &q) {
    std::string full = "SELECT * FROM t WHERE x = '" + q + "'";
    sqlite3_exec(db, full.c_str(), nullptr, nullptr, nullptr);
}

int main() {
    sqlite3 *db = nullptr;
    run_query(db, "constant");
    return 0;
}
`
	flows := Analyze(code, "/app/const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("constant argument must NOT produce a SQL injection flow; got %d flows", len(flows))
	}
}

// TestCPP_StdStringWrap_DoesNotSanitizeCommand verifies that wrapping a tainted
// value in std::string(...) no longer falsely sanitizes a command-injection
// flow. std::string is a memory-safety advisory, not an injection sanitizer.
func TestCPP_StdStringWrap_DoesNotSanitizeCommand(t *testing.T) {
	code := `
#include <cstdlib>
#include <string>
namespace bp = boost::process;

void execute_command() {
    char *cmd = getenv("CMD");
    bp::system(std::string(cmd));
}
`
	flows := Analyze(code, "/app/cmd.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Fatalf("std::string(cmd) must NOT sanitize command injection; expected a SnkCommand flow, got %d", len(flows))
	}
}

// TestCPP_StdStringDecl_StillAdvisory confirms the std::string memory-safety
// gate stays inert (no false sanitization) without firing on a safe constant
// command — i.e. we did not introduce a new false positive.
func TestCPP_StdStringDecl_StillSafeOnConstant(t *testing.T) {
	code := `
#include <cstdlib>
#include <string>

void run() {
    std::string s = "ls -la";
    system(s.c_str());
}
`
	flows := Analyze(code, "/app/safe_cmd.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("constant command must NOT produce a command injection flow; got %d flows", len(flows))
	}
}

// TestCPP_HandlerAnnotation_NoFalsePositive_ExecuteQuery is a regression guard:
// a C++ function whose body merely calls a method named ExecuteQuery(...) must
// NOT be treated as a web handler (which would seed its connection-handle
// parameter as user input and fire a spurious SQL finding on a hardcoded query).
func TestCPP_HandlerAnnotation_NoFalsePositive_ExecuteQuery(t *testing.T) {
	code := `
namespace spanner = google::cloud::spanner;
void run(spanner::Client& client) {
    auto stmt = spanner::SqlStatement("SELECT 1");
    auto rows = client.ExecuteQuery(stmt);
}
`
	flows := Analyze(code, "/app/spanner.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("ExecuteQuery( must not be treated as a web-handler annotation; got %d flows", len(flows))
	}
}
