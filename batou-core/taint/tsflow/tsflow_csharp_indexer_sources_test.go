package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// C# ASP.NET indexer-expression taint sources: Request.Query["x"],
// Request.Form["x"], Request.Headers["x"], etc. are the dominant input shape in
// ASP.NET. They are registered C# sources but were previously dead because the
// tsflow walker never routed C#'s indexer node type (element_access_expression)
// the way it routes subscript/element_reference for Python/JS/Ruby/PHP. These
// tests pin the routing so the regression is caught.

// Assignment-RHS form: var f = Request.Query["f"]; File.ReadAllText(f).
func TestCSharp_Indexer_Query_AssignedToFileRead(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle() {
        var f = Request.Query["f"];
        var contents = File.ReadAllText(f);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for Request.Query[\"f\"] -> File.ReadAllText (assignment RHS)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Inline-at-sink form: File.ReadAllText(Request.Query["f"]).
func TestCSharp_Indexer_Query_InlineAtFileRead(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle() {
        var contents = File.ReadAllText(Request.Query["f"]);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for inline File.ReadAllText(Request.Query[\"f\"])")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Request.Form["x"] indexer reaching a sink.
func TestCSharp_Indexer_Form_AssignedToFileRead(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle() {
        var name = Request.Form["name"];
        var contents = File.ReadAllText(name);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for Request.Form[\"name\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PRECISION: a non-source indexer (an arbitrary dictionary lookup) must NOT seed
// taint. Only registered Request.* sources are seeded; widening to any
// dict[key] would FP.
func TestCSharp_Indexer_NonSourceDict_DoesNotFire(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Collections.Generic;

public class Handler {
    public void Handle(Dictionary<string, string> someDict) {
        var d = someDict["k"];
        var contents = File.ReadAllText(d);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected NO file_read flow for non-source dictionary indexer someDict[\"k\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// 5-CWE coverage via the Request.Query[...] indexer source: path-traversal,
// SSRF, XSS, XXE, LDAP. Each asserts the dominant ASP.NET indexer source now
// reaches a representative sink category for that CWE class.
func TestCSharp_Indexer_FiveCWEProbe(t *testing.T) {
	cases := []struct {
		name string
		code string
		sink taint.SinkCategory
	}{
		{
			name: "path-traversal",
			code: `
using System.IO;
public class H { public void M() {
    var p = Request.Query["path"];
    File.ReadAllText(p);
}}`,
			sink: taint.SnkFileRead,
		},
		{
			name: "ssrf",
			code: `
using System.Net;
public class H { public void M() {
    var url = Request.Query["url"];
    var req = WebRequest.Create(url);
}}`,
			sink: taint.SnkURLFetch,
		},
		{
			name: "xss",
			code: `
public class H { public void M() {
    var msg = Request.Query["msg"];
    Response.Write(msg);
}}`,
			sink: taint.SnkHTMLOutput,
		},
		{
			name: "xxe",
			code: `
using System.Xml;
public class H { public void M() {
    var xml = Request.Query["xml"];
    var reader = XmlReader.Create(xml);
}}`,
			sink: taint.SnkDeserialize,
		},
		{
			name: "ldap",
			code: `
using System.DirectoryServices;
public class H { public void M() {
    var u = Request.Query["user"];
    var ds = new DirectorySearcher(u);
}}`,
			sink: taint.SnkLDAP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/Handler.cs", rules.LangCSharp)
			if !hasTaintFlow(flows, tc.sink) {
				t.Errorf("expected %s flow via Request.Query[...] indexer for %s", tc.sink, tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
				}
			}
		})
	}
}
