// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Ruby strings for taint-flow unit tests
package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby graphql-ruby resolver sources — context.query.variables / query_string
// =========================================================================

func TestRuby_GraphQLSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangRuby)
	if cat == nil {
		t.Fatal("Ruby catalog not loaded")
	}
	ids := map[string]bool{}
	for _, s := range cat.Sources() {
		ids[s.ID] = true
	}
	want := []string{
		"ruby.graphql.query.variables",
		"ruby.graphql.query.query_string",
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// graphql-ruby resolver pulls a client-supplied variable out of
// `context.query.variables` and shells out — classic command injection.
func TestRuby_GraphQL_QueryVariables_CommandInj(t *testing.T) {
	code := `
class Resolvers::RunDeploy < GraphQL::Schema::Resolver
  def resolve
    target = context.query.variables["target"]
    system("deploy " + target)
  end
end
`
	flows := Analyze(code, "/app/resolvers/run_deploy.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from context.query.variables -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// graphql-ruby resolver pulls raw operation text from `context.query.query_string`
// and pipes it into shell-argument construction — command injection.
func TestRuby_GraphQL_QueryString_CommandInj(t *testing.T) {
	code := `
class Resolvers::Explain < GraphQL::Schema::Resolver
  def resolve
    raw = context.query.query_string
    system("explain " + raw)
  end
end
`
	flows := Analyze(code, "/app/resolvers/explain.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from context.query.query_string -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// graphql-ruby resolver echoes the raw GraphQL query text into a logged
// string without sanitizing newlines — log injection.
func TestRuby_GraphQL_QueryString_LogInjection(t *testing.T) {
	code := `
class Resolvers::Debug < GraphQL::Schema::Resolver
  def resolve
    raw = context.query.query_string
    Rails.logger.info("graphql query: " + raw)
  end
end
`
	flows := Analyze(code, "/app/resolvers/debug.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow from context.query.query_string -> Rails.logger.info()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
