package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// This file exercises the Go TypeExtractor against realistic code
// patterns. It doubles as the reference test suite each per-language PR
// (E1-T3 through E1-T6 in todo.json) should mirror: real code, real
// expected Params/Returns, covering framework sources, database types,
// return-type flags, method receivers, and parameter-shape edge cases.
//
// Per-language PRs: copy this file, s/golang/{lang}/, update Content to
// the equivalent source in your language, and adjust expected canonical
// types.

// -----------------------------------------------------------------------
// Web framework handlers — the primary source surface in most scans.
// -----------------------------------------------------------------------

func TestGoExtractor_Framework_Gin(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "gin_context_pointer_param",
			FilePath: "/app/routes/gin_handler.go",
			Content: `package routes

import "github.com/gin-gonic/gin"

func ListUsers(c *gin.Context) {
	id := c.Query("id")
	_ = id
}
`,
			Func: "ListUsers",
			WantParams: []ParamTaint{
				{
					Name:           "c",
					CanonicalType:  "*gin.Context",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_Framework_EchoV4(t *testing.T) {
	// Versioned import path /v4 must canonicalize to plain echo.Context,
	// matching the existing TestTypedSummary_VersionedImportAlias.
	cases := []HarnessCase{
		{
			Name:     "echo_v4_context_value_param",
			FilePath: "/app/echo_handler.go",
			Content: `package app

import "github.com/labstack/echo/v4"

func GetUser(c echo.Context) error {
	return c.String(200, "ok")
}
`,
			Func: "GetUser",
			WantParams: []ParamTaint{
				{
					Name:           "c",
					CanonicalType:  "echo.Context",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
			WantReturns: []ReturnTaint{
				{Type: "error", CanonicalType: "error"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_Framework_Fiber(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "fiber_ctx_pointer_param",
			FilePath: "/app/fiber_handler.go",
			Content: `package app

import "github.com/gofiber/fiber/v2"

func Search(c *fiber.Ctx) error {
	return c.SendString(c.Query("q"))
}
`,
			Func: "Search",
			WantParams: []ParamTaint{
				{
					Name:           "c",
					CanonicalType:  "*fiber.Ctx",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// Database types — SQL driver + ORM sink params and source rows.
// -----------------------------------------------------------------------

func TestGoExtractor_Database_SQLDB(t *testing.T) {
	// *sql.DB is recognized as a SINK-type param (IsSinkType=true) —
	// dangerous because unsanitized input passed into its Query methods
	// reaches the database.
	cases := []HarnessCase{
		{
			Name:     "sql_db_sink_param_mixed_with_user_input",
			FilePath: "/app/db/lookup.go",
			Content: `package db

import "database/sql"

func LookupUser(db *sql.DB, id string) (string, error) {
	row := db.QueryRow("SELECT name FROM users WHERE id=" + id)
	var name string
	err := row.Scan(&name)
	return name, err
}
`,
			Func: "LookupUser",
			WantParams: []ParamTaint{
				{Name: "db", CanonicalType: "*sql.DB", IsSinkType: true},
				{Name: "id", CanonicalType: "string"},
			},
			WantReturns: []ReturnTaint{
				{Type: "string", CanonicalType: "string"},
				{Type: "error", CanonicalType: "error"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_Database_SQLRow_Source(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "sql_row_param_is_source_database",
			FilePath: "/app/db/scan.go",
			Content: `package db

import "database/sql"

func Scan(row *sql.Row) string {
	var v string
	_ = row.Scan(&v)
	return v
}
`,
			Func: "Scan",
			WantParams: []ParamTaint{
				{
					Name:           "row",
					CanonicalType:  "*sql.Row",
					IsSourceType:   true,
					SourceCategory: taint.SrcDatabase,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// I/O and network — lower-level source surfaces.
// -----------------------------------------------------------------------

func TestGoExtractor_IO_Reader(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "io_reader_param_is_network_source",
			FilePath: "/app/io/copy.go",
			Content: `package io

import "io"

func ReadAll(r io.Reader) []byte {
	buf := make([]byte, 1024)
	_, _ = r.Read(buf)
	return buf
}
`,
			Func: "ReadAll",
			WantParams: []ParamTaint{
				{
					Name:           "r",
					CanonicalType:  "io.Reader",
					IsSourceType:   true,
					SourceCategory: taint.SrcNetwork,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_IO_NetConn(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "net_conn_value_param_is_network_source",
			FilePath: "/app/net/handle.go",
			Content: `package net

import "net"

func HandleConn(c net.Conn) {
	buf := make([]byte, 512)
	_, _ = c.Read(buf)
}
`,
			Func: "HandleConn",
			WantParams: []ParamTaint{
				{
					Name:           "c",
					CanonicalType:  "net.Conn",
					IsSourceType:   true,
					SourceCategory: taint.SrcNetwork,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// Return types — source-typed returns propagate taint; multi-return and
// named returns must index correctly.
// -----------------------------------------------------------------------

func TestGoExtractor_Returns_SourceTyped(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "function_returning_http_request_is_source",
			FilePath: "/app/builder.go",
			Content: `package app

import "net/http"

func Build(url string) *http.Request {
	req, _ := http.NewRequest("GET", url, nil)
	return req
}
`,
			Func: "Build",
			WantParams: []ParamTaint{
				{Name: "url", CanonicalType: "string"},
			},
			WantReturns: []ReturnTaint{
				{
					CanonicalType:  "*http.Request",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_Returns_MultiValue(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "multi_return_string_error",
			FilePath: "/app/lookup.go",
			Content: `package app

func Get(id int) (string, error) {
	return "", nil
}
`,
			Func: "Get",
			WantParams: []ParamTaint{
				{Name: "id", CanonicalType: "int"},
			},
			WantReturns: []ReturnTaint{
				{Type: "string", CanonicalType: "string"},
				{Type: "error", CanonicalType: "error"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_Returns_Named(t *testing.T) {
	// Named returns preserve the name alongside the type. The IsSourceType
	// flag still fires because CanonicalType is what drives the lookup.
	cases := []HarnessCase{
		{
			Name:     "named_returns_with_source_type",
			FilePath: "/app/named.go",
			Content: `package app

import "net/http"

func Build() (req *http.Request, err error) {
	req, err = http.NewRequest("GET", "/", nil)
	return
}
`,
			Func: "Build",
			WantReturns: []ReturnTaint{
				{
					Name:           "req",
					CanonicalType:  "*http.Request",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
				{Name: "err", CanonicalType: "error"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// Method receivers — FuncNode.Name is "Receiver.Method", not "Method".
// -----------------------------------------------------------------------

func TestGoExtractor_Methods_PointerReceiver(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "pointer_receiver_method_naming",
			FilePath: "/app/handler.go",
			Content: `package app

import "net/http"

type Server struct{}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
`,
			Func: "Server.ServeHTTP", // canonical FuncNode name
			WantParams: []ParamTaint{
				{Name: "w", CanonicalType: "http.ResponseWriter"},
				{Name: "r", CanonicalType: "*http.Request", IsSourceType: true},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_Methods_ValueReceiver(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "value_receiver_method_naming",
			FilePath: "/app/user.go",
			Content: `package app

type User struct{ Name string }

func (u User) Greeting() string { return "hi " + u.Name }
`,
			Func: "User.Greeting",
			WantReturns: []ReturnTaint{
				{Type: "string", CanonicalType: "string"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// Parameter shapes — grouped, anonymous, variadic.
// -----------------------------------------------------------------------

func TestGoExtractor_ParamShape_Grouped(t *testing.T) {
	// `func(a, b, c int, name string)` should yield 4 positional Params
	// with the first three sharing the `int` type and index 0/1/2.
	cases := []HarnessCase{
		{
			Name:     "grouped_names_same_type",
			FilePath: "/app/arith.go",
			Content: `package app

func Sum(a, b, c int, name string) int { return a + b + c }
`,
			Func: "Sum",
			WantParams: []ParamTaint{
				{Index: 0, Name: "a", CanonicalType: "int"},
				{Index: 1, Name: "b", CanonicalType: "int"},
				{Index: 2, Name: "c", CanonicalType: "int"},
				{Index: 3, Name: "name", CanonicalType: "string"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

func TestGoExtractor_ParamShape_Variadic(t *testing.T) {
	// Variadic params serialize with a `...` prefix in the Type string.
	// Per-language extractors should preserve the raw form; canonical
	// matching happens against the concrete element type if the catalog
	// has an entry.
	cases := []HarnessCase{
		{
			Name:     "variadic_string_args",
			FilePath: "/app/log.go",
			Content: `package app

func Join(sep string, parts ...string) string { return "" }
`,
			Func: "Join",
			WantParams: []ParamTaint{
				{Index: 0, Name: "sep", CanonicalType: "string"},
				// The second param is variadic; extractor should emit it
				// with a canonical form that starts with the element type.
				// Intentionally not asserting an exact CanonicalType here
				// — per-language catalogs decide variadic representation.
				{Index: 1, Name: "parts"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// Realistic full handler — the pattern a Go web handler actually takes.
// This is the canonical "what should a per-language PR cover" test.
// -----------------------------------------------------------------------

func TestGoExtractor_RealisticHandler_EndToEnd(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "http_handler_with_db_field_access",
			FilePath: "/app/users.go",
			Content: `package app

import (
	"database/sql"
	"net/http"
)

type Server struct {
	db *sql.DB
}

func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	_, _ = s.db.Exec("INSERT INTO users (name) VALUES ('" + name + "')")
	w.WriteHeader(201)
}
`,
			Func: "Server.CreateUser",
			WantParams: []ParamTaint{
				{
					Index:         0,
					Name:          "w",
					CanonicalType: "http.ResponseWriter",
				},
				{
					Index:          1,
					Name:           "r",
					CanonicalType:  "*http.Request",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// Negative cases — plain types correctly unflagged, private helpers
// still extracted, nothing over-reports.
// -----------------------------------------------------------------------

func TestGoExtractor_NegativeCases(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "plain_types_not_flagged_as_sources",
			FilePath: "/app/util.go",
			Content: `package app

import "time"

func Format(d time.Duration, tz string) string {
	return ""
}
`,
			Func: "Format",
			WantParams: []ParamTaint{
				{Name: "d", CanonicalType: "time.Duration"},
				{Name: "tz", CanonicalType: "string"},
			},
			WantReturns: []ReturnTaint{
				{Type: "string", CanonicalType: "string"},
			},
		},
		{
			Name:     "interface_type_not_matched_as_source",
			FilePath: "/app/log.go",
			Content: `package app

type Logger interface {
	Log(msg string)
}

func UseLogger(l Logger) {}
`,
			Func: "UseLogger",
			WantParams: []ParamTaint{
				{Name: "l", CanonicalType: "Logger"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// -----------------------------------------------------------------------
// TypesVersion consistency — every extracted Params/Returns must arrive
// with the current schema version when populated via the wire-up path.
// Loop-produced extractors should produce the same version so consumers
// can gate on it.
// -----------------------------------------------------------------------

func TestGoExtractor_ProducesCurrentTypesSchemaVersion(t *testing.T) {
	// Use ComputeTaintSigTyped (the scanner's entry point) to confirm
	// the extracted data sets TypesVersion correctly end-to-end.
	withMockExtractor(t, rules.LangPython, []FuncSignature{
		{
			Name: "handler",
			Params: []ParamTaint{
				{Index: 0, Name: "req", CanonicalType: "flask.Request",
					IsSourceType: true, SourceCategory: taint.SrcUserInput},
			},
		},
	})
	node := &FuncNode{
		Name:     "handler",
		FilePath: "/app/v.py",
		Language: rules.LangPython,
	}
	sig := ComputeTaintSigTyped(node, "def handler(req): pass\n", rules.LangPython, nil, nil, nil)
	if sig.TypesVersion != TypesSchemaVersion {
		t.Errorf("TypesVersion = %d, want %d", sig.TypesVersion, TypesSchemaVersion)
	}
	if len(sig.Params) != 1 {
		t.Fatalf("Params length = %d, want 1", len(sig.Params))
	}
}
