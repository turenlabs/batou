package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// These tests cover C/C++ parameter-as-source seeding (seedCParams): a
// handler-shaped function taking a user-shaped string/buffer parameter has
// that parameter seeded as a taint source, so an intraprocedural flow into a
// dangerous sink is detected even with no explicit framework source call.
//
// Before this seeding the C++ taint catalog was effectively INERT on plain
// handler signatures (`void handle(const std::string& user)`) — a real scan of
// such code produced zero taint findings.

// Primary lever probe: std::string handler param -> system() (CWE-78).
func TestCPP_ParamSource_StdStringToSystem(t *testing.T) {
	code := `
#include <string>
#include <cstdlib>
void handle(const std::string& user) {
    std::system(user.c_str());
}
`
	flows := Analyze(code, "/app/cmd_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for handler std::string param -> system()")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s", i, f.Source.ID, f.Sink.ID)
		}
	}
}

// Nested/chained-receiver SQL sink: req->db().query(user) (CWE-89).
func TestCPP_ParamSource_NestedReceiverQuery(t *testing.T) {
	code := `
#include <string>
struct DB { void query(const std::string& sql); };
struct Req { DB& db(); };
void handle_sql(Req* req, const std::string& user) {
    req->db().query(user);
}
`
	flows := Analyze(code, "/app/sql_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for handler param -> req->db().query(user)")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s", i, f.Source.ID, f.Sink.ID)
		}
	}
}

// Deeply nested two-level receiver: ctx->session().db()->query(user).
func TestCPP_ParamSource_DeepNestedReceiverQuery(t *testing.T) {
	code := `
#include <string>
void on_request(const std::string& user) {
    ctx->session().db()->query(user);
}
`
	flows := Analyze(code, "/app/deep.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow through a deeply nested receiver chain")
	}
}

// char* buffer handler param -> popen() (CWE-78), C language.
func TestC_ParamSource_CharBufToPopen(t *testing.T) {
	code := `
#include <stdio.h>
void handle_request(char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (fp) pclose(fp);
}
`
	flows := Analyze(code, "/app/c_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for handler char* param -> popen()")
	}
}

// Negative: a NON-handler helper with a std::string param must NOT be seeded.
// This is the safe-fixture shape (constant / parameterized argument arrives
// interprocedurally); seeding it would resurrect interproc-safe FPs.
func TestCPP_ParamSource_NonHandlerNotSeeded(t *testing.T) {
	code := `
#include <string>
#include <cstdlib>
void run_query(const std::string& q) {
    std::string full = "SELECT * FROM t WHERE x = '" + q + "'";
    std::system(full.c_str());
}
`
	flows := Analyze(code, "/app/helper.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("non-handler helper param must NOT be auto-seeded (would be an interproc FP)")
	}
}

// Negative: a handler whose param is a NON-string handle (struct/class
// pointer) must NOT be seeded — those are server handles, not payloads.
// Regression guard for the `ap_log_error(.., server_rec *s, ..)` and
// `process_user(struct User *user)` false positives.
func TestC_ParamSource_NonStringHandleNotSeeded(t *testing.T) {
	code := `
struct server_rec;
void handle(struct server_rec* s) {
    ap_log_error("MARK", 0, s, "static startup message");
}
`
	flows := Analyze(code, "/app/mod_x.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("handler with a non-string struct-pointer param must NOT be seeded")
	}
}

// Negative: a constant passed into the sink in a handler must NOT fire — the
// finding has to be taint-driven, not pattern-driven.
func TestCPP_ParamSource_ConstantNotFlagged(t *testing.T) {
	code := `
#include <string>
#include <cstdlib>
void handle(const std::string& user) {
    (void)user;
    std::system("echo hello");
}
`
	flows := Analyze(code, "/app/const_handler.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("constant system() argument must NOT produce a command-injection flow")
	}
}

// Negative: main()'s CLI argv must NOT be auto-seeded as a handler param.
// CLI argument injection is a distinct, locally-mitigated threat model and the
// safe fixtures validate argv then use the no-shell execve form.
func TestC_ParamSource_MainArgvNotSeeded(t *testing.T) {
	code := `
#include <unistd.h>
int main(int argc, char* argv[]) {
    char* args[] = {"/usr/bin/ping", "-c", "3", argv[1], 0};
    char* envp[] = {0};
    execve("/usr/bin/ping", args, envp);
    return 0;
}
`
	flows := Analyze(code, "/app/cli.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("main()'s argv must NOT be auto-seeded as a handler parameter")
	}
}
