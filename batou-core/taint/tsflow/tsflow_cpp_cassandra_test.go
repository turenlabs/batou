package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ DataStax Cassandra driver CQL injection tests (CWE-943)
// The cpp-driver uses C-style free functions. The safe pattern is a literal
// CQL string with `?` placeholders plus cass_statement_bind_* calls. Passing
// a concatenated/tainted query string into cass_statement_new or
// cass_session_prepare is CQL injection.
// =========================================================================

func TestCPP_Cassandra_StatementNew_Injection(t *testing.T) {
	code := `
#include <cassandra.h>
#include <string>

void lookup(const char* argv[]) {
    CassCluster* cluster = cass_cluster_new();
    CassSession* session = cass_session_new();
    std::string user_id = argv[1];
    std::string q = "SELECT * FROM users WHERE id = " + user_id;
    CassStatement* stmt = cass_statement_new(q.c_str(), 0);
    cass_session_execute(session, stmt);
}
`
	flows := Analyze(code, "/app/cass_statement_new.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for argv -> cass_statement_new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Cassandra_StatementNewN_Injection(t *testing.T) {
	code := `
#include <cassandra.h>
#include <string>

void lookup(const char* argv[]) {
    CassSession* session = cass_session_new();
    std::string name = argv[1];
    std::string q = "SELECT * FROM users WHERE name = '" + name + "'";
    CassStatement* stmt = cass_statement_new_n(q.c_str(), q.size(), 0);
    cass_session_execute(session, stmt);
}
`
	flows := Analyze(code, "/app/cass_statement_new_n.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for argv -> cass_statement_new_n")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Cassandra_SessionPrepare_Injection(t *testing.T) {
	code := `
#include <cassandra.h>
#include <string>

void prep(const char* argv[]) {
    CassSession* session = cass_session_new();
    std::string table = argv[1];
    std::string q = "SELECT * FROM " + table + " WHERE active = true";
    CassFuture* fut = cass_session_prepare(session, q.c_str());
    cass_future_wait(fut);
}
`
	flows := Analyze(code, "/app/cass_session_prepare.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for argv -> cass_session_prepare")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Cassandra_SessionPrepareN_Injection(t *testing.T) {
	code := `
#include <cassandra.h>
#include <string>

void prep(const char* argv[]) {
    CassSession* session = cass_session_new();
    std::string col = argv[1];
    std::string q = "SELECT " + col + " FROM users";
    CassFuture* fut = cass_session_prepare_n(session, q.c_str(), q.size());
    cass_future_wait(fut);
}
`
	flows := Analyze(code, "/app/cass_session_prepare_n.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for argv -> cass_session_prepare_n")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe pattern: literal CQL string with ? placeholders + bind calls.
// No tainted data reaches the query string, so no CQL injection finding.
// =========================================================================

func TestCPP_Cassandra_LiteralQueryWithBind_Safe(t *testing.T) {
	code := `
#include <cassandra.h>
#include <string>

void lookup(const char* argv[]) {
    CassSession* session = cass_session_new();
    std::string user_id = argv[1];
    CassStatement* stmt = cass_statement_new("SELECT * FROM users WHERE id = ?", 1);
    cass_statement_bind_string(stmt, 0, user_id.c_str());
    cass_session_execute(session, stmt);
}
`
	flows := Analyze(code, "/app/cass_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO CQL injection flow when using literal query + cass_statement_bind_*; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
