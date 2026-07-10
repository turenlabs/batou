package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// C# ASP.NET request sources are registered with a dotted MethodName
// ("Request.Query") and an implicit `this.Request` receiver. #1285 routed the
// indexer node so the BARE Request.Query["x"] seeds taint, but anything that
// PREFIXES the chain — context.Request.Query["x"] (the dominant modern
// minimal-API / middleware / HttpContext-handler form) and
// _httpContextAccessor.HttpContext.Request.Query["x"] (the DI-injected accessor
// form) — stayed dead because the receiver heuristic only accepts a bare
// "request". These tests pin the C#-scoped dotted-suffix access-path match that
// revives the prefixed forms.

// PREFIXED middleware/handler form: var f = context.Request.Query["file"]; File.ReadAllText(f).
func TestCSharp_PrefixedRequest_HttpContext_Query_FileRead(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle(HttpContext context) {
        var f = context.Request.Query["file"];
        var contents = File.ReadAllText(f);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for context.Request.Query[\"file\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PREFIXED DI-accessor form:
// var f = _httpContextAccessor.HttpContext.Request.Query["file"]; File.ReadAllText(f).
func TestCSharp_PrefixedRequest_HttpContextAccessor_Query_FileRead(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    private readonly IHttpContextAccessor _httpContextAccessor;
    public void Handle() {
        var f = _httpContextAccessor.HttpContext.Request.Query["file"];
        var contents = File.ReadAllText(f);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for _httpContextAccessor.HttpContext.Request.Query[\"file\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PREFIXED Request.Form chain reaching a sink.
func TestCSharp_PrefixedRequest_HttpContext_Form_FileRead(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle(HttpContext context) {
        var name = context.Request.Form["name"];
        var contents = File.ReadAllText(name);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for context.Request.Form[\"name\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// REGRESSION GUARD: the BARE Request.Query["file"] form must STILL fire after
// the suffix-match is added (no loss of the implicit-this case #1285 enabled).
func TestCSharp_PrefixedRequest_BareQuery_StillFires(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle() {
        var f = Request.Query["file"];
        var contents = File.ReadAllText(f);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected CWE-22 file_read flow for bare Request.Query[\"file\"] -> File.ReadAllText (regression)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PRECISION: a non-Request indexer whose chain merely ENDS in ".Query" but is
// NOT an ASP.NET request (someObj.Other.Query["k"]) must NOT seed taint — the
// suffix "Request.Query" is not a dot-boundary suffix of "someObj.Other.Query".
func TestCSharp_PrefixedRequest_NonRequestOtherQuery_DoesNotFire(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle(SomeType someObj) {
        var d = someObj.Other.Query["k"];
        var contents = File.ReadAllText(d);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected NO file_read flow for non-request someObj.Other.Query[\"k\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PRECISION: a NON-dot-boundary prefix (MyRequest.Query["k"]) must NOT fire —
// the char before "Request.Query" is "y" (from "My"), not ".", so the dotted
// suffix requirement rejects it.
func TestCSharp_PrefixedRequest_MyRequestQuery_DoesNotFire(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle(MyRequest MyRequest) {
        var d = MyRequest.Query["k"];
        var contents = File.ReadAllText(d);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected NO file_read flow for non-dot-boundary MyRequest.Query[\"k\"] -> File.ReadAllText")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
