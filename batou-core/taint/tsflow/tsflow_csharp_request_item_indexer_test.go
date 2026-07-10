package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// C# umbrella request user-input idioms that were previously DEAD (zero
// dataflow) because the catalog only had the named sub-collections
// (Request.Query/Form/Cookies/Headers/...):
//
//	SLICE A (pure catalog): Request.Params["x"] / Request.ServerVariables["x"]
//	        and the prefixed context.Request.Params["x"].
//	SLICE B (engine extension): the HttpRequest.Item indexer — bare Request["x"]
//	        (Page/Controller property), and the member-access holder forms
//	        context.Request["x"] / this.Request["x"].
//
// These are the #1 pre-Core WebForms/MVC5 input shapes (WebGoat.NET
// ProductDetails/Orders/ReflectedXSS all use bare Request["x"]; Autocomplete
// uses context.Request["x"]). Each test pins a source->SQL-sink flow; the
// negatives pin the FP gate (a local/parameter named Request shadows the page
// property, and the capital-Request convention excludes a lowercase local).

// sqlSinkAfter wraps a request-source expression in a concat->SqlDataAdapter
// SQL sink so each case differs only in the SOURCE token.
func sqlSinkAfter(sourceExpr string) string {
	return `
using System.Data.SqlClient;
public class H {
    private SqlConnection conn;
    public void M(System.Web.HttpContext context) {
        string q = ` + sourceExpr + `;
        string sql = "SELECT * FROM t WHERE x = '" + q + "'";
        SqlDataAdapter da = new SqlDataAdapter(sql, conn);
    }
}
`
}

// --- SLICE B: HttpRequest.Item indexer (bare + member-access holders) ---

func TestCSharp_RequestItem_Bare_FiresSQL(t *testing.T) {
	flows := Analyze(sqlSinkAfter(`Request["q"]`), "/app/H.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected CWE-89 sql_query flow for bare Request["q"] -> SqlDataAdapter`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_RequestItem_ContextHolder_FiresSQL(t *testing.T) {
	flows := Analyze(sqlSinkAfter(`context.Request["q"]`), "/app/H.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected CWE-89 sql_query flow for context.Request["q"] -> SqlDataAdapter`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_RequestItem_ThisHolder_FiresSQL(t *testing.T) {
	flows := Analyze(sqlSinkAfter(`this.Request["q"]`), "/app/H.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected CWE-89 sql_query flow for this.Request["q"] -> SqlDataAdapter`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SLICE A: Request.Params / Request.ServerVariables (pure catalog) ---

func TestCSharp_RequestParams_Bare_FiresSQL(t *testing.T) {
	flows := Analyze(sqlSinkAfter(`Request.Params["q"]`), "/app/H.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected CWE-89 sql_query flow for Request.Params["q"] -> SqlDataAdapter`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_RequestParams_ContextPrefixed_FiresSQL(t *testing.T) {
	flows := Analyze(sqlSinkAfter(`context.Request.Params["q"]`), "/app/H.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected CWE-89 sql_query flow for context.Request.Params["q"] -> SqlDataAdapter`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_RequestServerVariables_FiresSQL(t *testing.T) {
	flows := Analyze(sqlSinkAfter(`Request.ServerVariables["q"]`), "/app/H.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected CWE-89 sql_query flow for Request.ServerVariables["q"] -> SqlDataAdapter`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- FP gate: a local/parameter named Request shadows the page property ---

// The canonical FP shape from the task spec: a non-HttpRequest local named
// Request must NOT seed taint via the bare-indexer route.
func TestCSharp_RequestItem_LocalShadow_DoesNotFire(t *testing.T) {
	code := `
using System.Data.SqlClient;
using System.Collections.Generic;
public class H {
    private SqlConnection conn;
    Dictionary<string,string> GetSafe() { return new Dictionary<string,string>(); }
    public void M() {
        var Request = GetSafe();
        string q = Request["x"];
        string sql = "SELECT * FROM t WHERE x = '" + q + "'";
        SqlDataAdapter da = new SqlDataAdapter(sql, conn);
    }
}
`
	flows := Analyze(code, "/app/H.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected NO sql_query flow: local "var Request = GetSafe()" shadows the page property`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// A parameter named Request likewise shadows the page property.
func TestCSharp_RequestItem_ParamShadow_DoesNotFire(t *testing.T) {
	code := `
using System.Data.SqlClient;
using System.Collections.Generic;
public class H {
    private SqlConnection conn;
    public void M(Dictionary<string,string> Request) {
        string q = Request["x"];
        string sql = "SELECT * FROM t WHERE x = '" + q + "'";
        SqlDataAdapter da = new SqlDataAdapter(sql, conn);
    }
}
`
	flows := Analyze(code, "/app/H.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected NO sql_query flow: parameter named Request shadows the page property`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Lowercase `request[...]` is a plain local, not the inherited Request property:
// the capital-Request convention excludes it.
func TestCSharp_RequestItem_Lowercase_DoesNotFire(t *testing.T) {
	code := `
using System.Data.SqlClient;
using System.Collections.Generic;
public class H {
    private SqlConnection conn;
    Dictionary<string,string> GetSafe() { return new Dictionary<string,string>(); }
    public void M() {
        var request = GetSafe();
        string q = request["x"];
        string sql = "SELECT * FROM t WHERE x = '" + q + "'";
        SqlDataAdapter da = new SqlDataAdapter(sql, conn);
    }
}
`
	flows := Analyze(code, "/app/H.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error(`expected NO sql_query flow: lowercase request[...] is not the page property`)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
