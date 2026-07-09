package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// hasTaintFlowCWE reports whether any flow reached a sink carrying the given CWE.
func hasTaintFlowCWE(flows []taint.TaintFlow, cwe string) bool {
	for _, f := range flows {
		if f.Sink.CWEID == cwe {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// go-pg / go-pg ORM SQL injection (CWE-89)
// ---------------------------------------------------------------------------

// TestAnalyzeGo_GoPg_DB_Exec_SQLi: tainted query string into *pg.DB.Exec.
func TestAnalyzeGo_GoPg_DB_Exec_SQLi(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-pg/pg/v10"
)

func handler(w http.ResponseWriter, r *http.Request, db *pg.DB) {
	name := r.FormValue("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	_, _ = db.Exec(query)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for r.FormValue -> pg.DB.Exec, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_GoPg_ORM_Where_SQLi: tainted SQL fragment into *orm.Query.Where.
func TestAnalyzeGo_GoPg_ORM_Where_SQLi(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-pg/pg/v10/orm"
)

func handler(w http.ResponseWriter, r *http.Request, q *orm.Query) {
	role := r.URL.Query().Get("role")
	cond := "role = '" + role + "'"
	_ = q.Where(cond)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for r.URL.Query().Get -> orm.Query.Where, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_GoPg_DB_Param_Safe: user input passed as a ? placeholder arg
// (not into the query string) must NOT flag — DangerousArg is the query only.
func TestAnalyzeGo_GoPg_DB_Param_Safe(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-pg/pg/v10"
)

func handler(w http.ResponseWriter, r *http.Request, db *pg.DB) {
	name := r.FormValue("name")
	_, _ = db.Exec("SELECT * FROM users WHERE name = ?", name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("parameterized go-pg query (? placeholder) must not flag SQLi, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_GoPg_Ident_Sanitizer: wrapping a dynamic identifier in
// pg.Ident neutralizes the go-pg SQLi sink.
func TestAnalyzeGo_GoPg_Ident_Sanitizer(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-pg/pg/v10"
)

func handler(w http.ResponseWriter, r *http.Request, db *pg.DB) {
	col := r.FormValue("col")
	safe := pg.Ident(col)
	_, _ = db.Exec("SELECT ? FROM users", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("pg.Ident-wrapped identifier passed as placeholder arg must not flag SQLi, got %d flows", len(flows))
	}
}

// ---------------------------------------------------------------------------
// otto JavaScript VM code injection (CWE-94)
// ---------------------------------------------------------------------------

// TestAnalyzeGo_Otto_Run_CodeInjection: tainted script string into otto VM.
func TestAnalyzeGo_Otto_Run_CodeInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/robertkrimen/otto"
)

func handler(w http.ResponseWriter, r *http.Request, vm *otto.Otto) {
	script := r.FormValue("code")
	_, _ = vm.Run(script)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlowCWE(flows, "CWE-94") {
		t.Errorf("expected code-injection flow for r.FormValue -> otto.Otto.Run, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Otto_Run_Constant_Safe: a hardcoded script string is not tainted.
func TestAnalyzeGo_Otto_Run_Constant_Safe(t *testing.T) {
	code := `package main

import (
	"github.com/robertkrimen/otto"
)

func run(vm *otto.Otto) {
	_, _ = vm.Run("1 + 1")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlowCWE(flows, "CWE-94") {
		t.Errorf("constant script into otto.Run must not flag, got %d flows", len(flows))
	}
}

// ---------------------------------------------------------------------------
// Starlark embedded-script execution (CWE-94)
// ---------------------------------------------------------------------------

// TestAnalyzeGo_Starlark_ExecFile_Injection: tainted program string into
// starlark.ExecFile (arg index 2 = src).
func TestAnalyzeGo_Starlark_ExecFile_Injection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"go.starlark.net/starlark"
)

func handler(w http.ResponseWriter, r *http.Request, thread *starlark.Thread) {
	program := r.FormValue("program")
	_, _ = starlark.ExecFile(thread, "user.star", program, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlowCWE(flows, "CWE-94") {
		t.Errorf("expected script-injection flow for r.FormValue -> starlark.ExecFile, got %d flows", len(flows))
	}
}

// ---------------------------------------------------------------------------
// MongoDB Database.RunCommand NoSQL injection (CWE-943)
// ---------------------------------------------------------------------------

// TestAnalyzeGo_Mongo_RunCommand_NoSQLi: tainted command document.
func TestAnalyzeGo_Mongo_RunCommand_NoSQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func handler(w http.ResponseWriter, r *http.Request, db *mongo.Database) {
	js := r.FormValue("where")
	cmd := bson.D{{"$eval", js}}
	_ = db.RunCommand(context.TODO(), cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Errorf("expected NoSQL flow for r.FormValue -> mongo.Database.RunCommand, got %d flows", len(flows))
	}
}

// ---------------------------------------------------------------------------
// CloudWeGo Hertz request sources
// ---------------------------------------------------------------------------

// TestAnalyzeGo_Hertz_Query_Source_To_SQLi: Hertz query param flows to a SQL sink.
func TestAnalyzeGo_Hertz_Query_Source_To_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/cloudwego/hertz/pkg/app"
)

func handler(ctx context.Context, c *app.RequestContext, db *sql.DB) {
	id := c.Query("id")
	_, _ = db.Query("SELECT * FROM t WHERE id = '" + id + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for hertz c.Query -> db.Query, got %d flows", len(flows))
	}
	if !hasSourceCategory(flows, taint.SrcUserInput) {
		t.Errorf("expected Hertz c.Query to be a user-input source")
	}
}

// TestAnalyzeGo_Hertz_Body_Source_To_Command: Hertz raw body flows to exec.
func TestAnalyzeGo_Hertz_Body_Source_To_Command(t *testing.T) {
	code := `package main

import (
	"context"
	"os/exec"

	"github.com/cloudwego/hertz/pkg/app"
)

func handler(ctx context.Context, c *app.RequestContext) {
	raw := c.Body()
	cmd := string(raw)
	_ = exec.Command("sh", "-c", cmd).Run()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected command-injection flow for hertz c.Body -> exec.Command, got %d flows", len(flows))
	}
}

// ---------------------------------------------------------------------------
// connect-go RPC request sources
// ---------------------------------------------------------------------------

// TestAnalyzeGo_Connect_Header_Source_To_SSRF: connect request header into SSRF.
func TestAnalyzeGo_Connect_Header_Source_To_SSRF(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
)

func (s *server) Fetch(ctx context.Context, req *connect.Request[FetchRequest]) error {
	target := req.Header().Get("X-Target")
	_, _ = http.Get(target)
	return nil
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for connect req.Header().Get -> http.Get, got %d flows", len(flows))
	}
}
