package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// C# GraphQL resolver source tests — validates that user-controlled
// arguments read from HotChocolate IResolverContext and GraphQL.NET
// IResolveFieldContext are tracked into dangerous sinks.
// ===========================================================================

func TestCSharp_GraphQL_HotChocolate_ArgumentValue_SQL(t *testing.T) {
	code := `
using HotChocolate;
using HotChocolate.Resolvers;
using System.Data.SqlClient;

public class UserResolver {
    public string GetUser(IResolverContext context) {
        var id = context.ArgumentValue<string>("id");
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = '" + id + "'");
        cmd.ExecuteNonQuery();
        return id;
    }
}
`
	flows := Analyze(code, "/app/UserResolver.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for HotChocolate ArgumentValue -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_GraphQL_HotChocolate_ArgumentLiteral_Command(t *testing.T) {
	code := `
using HotChocolate.Resolvers;
using System.Diagnostics;

public class AdminResolver {
    public string RunCommand(IResolverContext ctx) {
        var cmd = ctx.ArgumentLiteral<string>("cmd");
        Process.Start(cmd);
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/AdminResolver.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for HotChocolate ArgumentLiteral -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_GraphQL_HotChocolate_ArgumentOptional_SQL(t *testing.T) {
	code := `
using HotChocolate.Resolvers;
using System.Data.SqlClient;

public class ProductResolver {
    public string GetProduct(IResolverContext context) {
        var filter = context.ArgumentOptional<string>("filter");
        var cmd = new SqlCommand("SELECT * FROM products WHERE name LIKE '%" + filter + "%'");
        cmd.ExecuteNonQuery();
        return filter;
    }
}
`
	flows := Analyze(code, "/app/ProductResolver.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for HotChocolate ArgumentOptional -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_GraphQL_HotChocolate_Parent_SQL(t *testing.T) {
	code := `
using HotChocolate.Resolvers;
using System.Data.SqlClient;

public class OrderResolver {
    public string GetOrders(IResolverContext context) {
        var user = context.Parent<string>();
        var cmd = new SqlCommand("SELECT * FROM orders WHERE customer = '" + user + "'");
        cmd.ExecuteNonQuery();
        return user;
    }
}
`
	flows := Analyze(code, "/app/OrderResolver.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for HotChocolate Parent -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_GraphQL_GraphQLNet_GetArgument_SQL(t *testing.T) {
	code := `
using GraphQL;
using System.Data.SqlClient;

public class UserType {
    public string ResolveUser(IResolveFieldContext context) {
        var name = context.GetArgument<string>("name");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'");
        cmd.ExecuteNonQuery();
        return name;
    }
}
`
	flows := Analyze(code, "/app/UserType.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for GraphQL.NET GetArgument -> SqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
