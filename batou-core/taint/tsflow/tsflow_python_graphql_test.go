// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Python strings for taint-flow unit tests
package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python GraphQL resolver sources — Strawberry, Graphene, Ariadne
// =========================================================================

func TestPython_GraphQLSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	ids := map[string]bool{}
	for _, s := range cat.Sources() {
		ids[s.ID] = true
	}
	want := []string{
		"py.graphql.info.context",
		"py.graphql.info.variable_values",
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// Strawberry resolver pulling a value out of info.context (the request) and
// concatenating it into a SQL query — classic SQLi via GraphQL.
func TestPython_GraphQL_Strawberry_InfoContext_SQLi(t *testing.T) {
	code := `
import strawberry
import sqlite3

@strawberry.type
class Query:
    @strawberry.field
    def user(self, info: strawberry.Info) -> str:
        user_id = info.context["user_id"]
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
        return cursor.fetchone()[0]
`
	flows := Analyze(code, "/app/schema.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from info.context -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Graphene resolver pulling a value from info.variable_values and shelling out.
func TestPython_GraphQL_Graphene_VariableValues_CommandInj(t *testing.T) {
	code := `
import graphene
import os

class Query(graphene.ObjectType):
    run = graphene.String()

    def resolve_run(self, info):
        target = info.variable_values["target"]
        os.system("deploy " + target)
        return "ok"
`
	flows := Analyze(code, "/app/schema.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from info.variable_values -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Ariadne resolver: payload reaches an HTML response (XSS).
func TestPython_GraphQL_Ariadne_InfoContext_XSS(t *testing.T) {
	code := `
from ariadne import QueryType
from starlette.responses import HTMLResponse

query = QueryType()

@query.field("greet")
def resolve_greet(_, info):
    name = info.context["request"].query_params.get("name")
    return HTMLResponse("<h1>Hello " + name + "</h1>")
`
	flows := Analyze(code, "/app/resolvers.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from info.context -> HTMLResponse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
