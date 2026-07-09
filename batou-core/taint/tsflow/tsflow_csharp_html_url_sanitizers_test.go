package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# HTML / URL / JS gap-fill sanitizer tests
//
// Each "Sanitized" test wires Console.ReadLine -> sanitizer -> sink and
// asserts the flow is suppressed. Each is paired with a "Control" test
// that runs the same source -> sink without the sanitizer to confirm the
// pipeline emits a flow when no sanitizer is in place — proving the
// sanitized variant suppresses the flow rather than silently mismatching.
// =========================================================================

// --- HtmlAgilityPack.HtmlEntity.Entitize: HTML body / header escaping ---

func TestCSharp_HtmlEntityEntitize_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using HtmlAgilityPack;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = HtmlEntity.Entitize(userInput);
        Response.Write(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is HtmlEntity.Entitize'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_HtmlEntityEntitize_Control_ResponseWrite(t *testing.T) {
	code := `
using System;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        Response.Write(userInput);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("control test broken: expected SnkHTMLOutput flow when Console.ReadLine flows directly to Response.Write")
	}
}

// --- HttpUtility.HtmlAttributeEncode: HTML attribute-context escaping ---

func TestCSharp_HtmlAttributeEncode_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using System.Web;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = HttpUtility.HtmlAttributeEncode(userInput);
        Response.Write(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is HttpUtility.HtmlAttributeEncode'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- HttpUtility.JavaScriptStringEncode: JS string-literal escaping ---

func TestCSharp_JavaScriptStringEncode_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using System.Web;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = HttpUtility.JavaScriptStringEncode(userInput);
        Response.Write("<script>var x = '" + safe + "';</script>");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is HttpUtility.JavaScriptStringEncode'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- HttpUtility.UrlEncode: URL-safe percent encoding ---
// We use WebRequest.Create as the SSRF sink because its catalog entry has
// ObjectType "WebRequest/WebClient", and a static-call receiver "WebRequest"
// matches lastPart prefix-abbreviation deterministically. Using HttpClient
// would require receiver text "httpClient" or "HttpClient" — naming-fragile.

func TestCSharp_HttpUtilityUrlEncode_Sanitized_WebRequest(t *testing.T) {
	code := `
using System;
using System.Net;
using System.Web;

public class Handler {
    public void Handle() {
        string userInput = Console.ReadLine();
        string safe = HttpUtility.UrlEncode(userInput);
        WebRequest.Create(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SnkURLFetch flow when payload is HttpUtility.UrlEncode'd before WebRequest.Create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_HttpUtilityUrlEncode_Control_WebRequest(t *testing.T) {
	code := `
using System;
using System.Net;

public class Handler {
    public void Handle() {
        string userInput = Console.ReadLine();
        WebRequest.Create(userInput);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("control test broken: expected SnkURLFetch flow when Console.ReadLine flows directly to WebRequest.Create")
	}
}

// --- IdnMapping.GetAscii: IDN host canonicalization (Punycode) ---

func TestCSharp_IdnMappingGetAscii_Sanitized_WebRequest(t *testing.T) {
	code := `
using System;
using System.Globalization;
using System.Net;

public class Handler {
    public void Handle() {
        string userInput = Console.ReadLine();
        var idn = new IdnMapping();
        string safe = idn.GetAscii(userInput);
        WebRequest.Create(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SnkURLFetch flow when host is IdnMapping.GetAscii'd before WebRequest.Create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative pattern test: ensure unrelated GetAscii calls don't match ---
// IdnMapping.GetAscii is a real instance method, but the method name "GetAscii"
// could also appear as an extension/method on a string-like receiver. The
// sanitizer is scoped to ObjectType "System.Globalization.IdnMapping", so a
// receiver named "userInput" (a tainted string) must not be matched. We rely
// on the tainted-receiver propagation path to keep the flow live.

func TestCSharp_IdnMappingGetAscii_Negative_DoesNotMatchTaintedReceiver(t *testing.T) {
	code := `
using System;
using System.Net;

public class Handler {
    public void Handle() {
        string userInput = Console.ReadLine();
        string fake = userInput.GetAscii();
        WebRequest.Create(fake);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("over-broad: tainted string's .GetAscii() must NOT be treated as IdnMapping sanitizer (receiver 'userInput' is not an IdnMapping abbreviation)")
	}
}
