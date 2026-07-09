package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestAnalyzeGo_GraphQL_GqlgenFieldContextToSQL verifies that client-supplied
// GraphQL arguments read via gqlgen's FieldContext.Args flow into a SQL sink.
func TestAnalyzeGo_GraphQL_GqlgenFieldContextToSQL(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/99designs/gqlgen/graphql"
)

var db *sql.DB

func userResolver(ctx context.Context) (string, error) {
	fc := graphql.GetFieldContext(ctx)
	id := fc.Args["id"].(string)
	row := db.QueryRow("SELECT name FROM users WHERE id = " + id)
	var name string
	_ = row.Scan(&name)
	return name, nil
}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL taint flow for gqlgen GetFieldContext.Args -> db.QueryRow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// TestAnalyzeGo_GraphQL_GqlgenOperationContextToCommand verifies that the
// raw query string read via gqlgen's OperationContext flows into a command
// execution sink.
func TestAnalyzeGo_GraphQL_GqlgenOperationContextToCommand(t *testing.T) {
	code := `package main

import (
	"context"
	"os/exec"

	"github.com/99designs/gqlgen/graphql"
)

func debugResolver(ctx context.Context) (string, error) {
	op := graphql.GetOperationContext(ctx)
	raw := op.RawQuery
	out, err := exec.Command("sh", "-c", "echo "+raw).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command taint flow for gqlgen GetOperationContext.RawQuery -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// TestAnalyzeGo_GraphQL_GqlgenOperationContextVariablesToSQL verifies that
// the GraphQL Variables map from OperationContext is treated as tainted.
func TestAnalyzeGo_GraphQL_GqlgenOperationContextVariablesToSQL(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/99designs/gqlgen/graphql"
)

var db *sql.DB

func filterResolver(ctx context.Context) error {
	op := graphql.GetOperationContext(ctx)
	filter := op.Variables["filter"].(string)
	_, err := db.Exec("DELETE FROM posts WHERE body LIKE '%" + filter + "%'")
	return err
}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL taint flow for gqlgen OperationContext.Variables -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// TestAnalyzeGo_GraphQL_GqlgenRootFieldContextToFileSink verifies that the
// root resolver's Args map is tracked as tainted when it reaches a file path
// sink (go.os.readfile is catalogued as SnkFileWrite for path-traversal
// detection).
func TestAnalyzeGo_GraphQL_GqlgenRootFieldContextToFileSink(t *testing.T) {
	code := `package main

import (
	"context"
	"os"

	"github.com/99designs/gqlgen/graphql"
)

func downloadResolver(ctx context.Context) ([]byte, error) {
	rc := graphql.GetRootFieldContext(ctx)
	path := rc.Args["path"].(string)
	return os.ReadFile(path)
}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-sink taint flow for gqlgen GetRootFieldContext.Args -> os.ReadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// TestAnalyzeGo_GraphQL_GqlgenResolverContextLegacy verifies the pre-v0.11
// GetResolverContext helper is still recognised as a source.
func TestAnalyzeGo_GraphQL_GqlgenResolverContextLegacy(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/99designs/gqlgen/graphql"
)

var db *sql.DB

func legacyResolver(ctx context.Context) error {
	rc := graphql.GetResolverContext(ctx)
	name := rc.Args["name"].(string)
	_, err := db.Exec("INSERT INTO audit(name) VALUES ('" + name + "')")
	return err
}
`
	flows := AnalyzeGo(code, "/app/resolver.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL taint flow for gqlgen GetResolverContext.Args -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
