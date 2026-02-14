package graphql

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-GQL-001: GraphQL Introspection Enabled ---

func TestGQL001_IntrospectionEnabled_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/graphql_introspection.ts")
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustFindRule(t, result, "GTSS-GQL-001")
}

func TestGQL001_IntrospectionEnabled_Inline(t *testing.T) {
	content := `const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});`
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustFindRule(t, result, "GTSS-GQL-001")
}

func TestGQL001_IntrospectionEnabled_Python(t *testing.T) {
	content := `from ariadne import make_executable_schema
schema = make_executable_schema(type_defs, query)
app = GraphQL(schema, introspection=True)`
	result := testutil.ScanContent(t, "/app/server.py", content)
	testutil.MustFindRule(t, result, "GTSS-GQL-001")
}

func TestGQL001_Safe_IntrospectionDisabled(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/graphql_introspection_safe.ts")
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-GQL-001")
}

func TestGQL001_Safe_NoIntrospectionConfig(t *testing.T) {
	content := `const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
});`
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-GQL-001")
}

// --- GTSS-GQL-002: No Depth Limiting ---

func TestGQL002_NoDepthLimit_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/graphql_no_depth_limit.ts")
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustFindRule(t, result, "GTSS-GQL-002")
}

func TestGQL002_NoDepthLimit_Inline(t *testing.T) {
	content := `const server = new ApolloServer({
  typeDefs,
  resolvers,
});`
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustFindRule(t, result, "GTSS-GQL-002")
}

func TestGQL002_Safe_WithDepthLimit(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/graphql_depth_limit_safe.ts")
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-GQL-002")
}

func TestGQL002_Safe_WithMaxDepthConfig(t *testing.T) {
	content := `const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(10)],
});`
	result := testutil.ScanContent(t, "/app/server.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-GQL-002")
}
