package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# AntiXSS context-specific output encoder sanitizer tests
//
// Covers the CSS / XML output-context encoders exposed by both the AntiXSS
// library (Microsoft.Security.Application.Encoder) and the System.Web
// built-in (System.Web.Security.AntiXss.AntiXssEncoder): CssEncode,
// XmlEncode, XmlAttributeEncode. Each "Sanitized" test wires
// Console.ReadLine -> encoder -> Response.Write and asserts the SnkHTMLOutput
// flow is suppressed, paired with a "Control" (no encoder) proving the
// pipeline emits a flow when nothing sanitizes — so a passing "Sanitized"
// test means the sanitizer matched, not that the flow silently failed.
// =========================================================================

// --- Encoder.CssEncode (AntiXSS library) ---

func TestCSharp_EncoderCssEncode_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using Microsoft.Security.Application;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = Encoder.CssEncode(userInput);
        Response.Write("<style>body { color: " + safe + "; }</style>");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is Encoder.CssEncode'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_EncoderCssEncode_Control_ResponseWrite(t *testing.T) {
	code := `
using System;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        Response.Write("<style>body { color: " + userInput + "; }</style>");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("control test broken: expected SnkHTMLOutput flow when Console.ReadLine flows directly to Response.Write")
	}
}

// --- AntiXssEncoder.CssEncode (System.Web built-in) ---

func TestCSharp_AntiXssEncoderCssEncode_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using System.Web.Security.AntiXss;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = AntiXssEncoder.CssEncode(userInput);
        Response.Write("<style>body { color: " + safe + "; }</style>");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is AntiXssEncoder.CssEncode'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Encoder.XmlEncode (XML element-content context) ---

func TestCSharp_EncoderXmlEncode_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using Microsoft.Security.Application;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = Encoder.XmlEncode(userInput);
        Response.Write("<item>" + safe + "</item>");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is Encoder.XmlEncode'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- AntiXssEncoder.XmlAttributeEncode (XML attribute context) ---

func TestCSharp_AntiXssEncoderXmlAttributeEncode_Sanitized_ResponseWrite(t *testing.T) {
	code := `
using System;
using System.Web.Security.AntiXss;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string safe = AntiXssEncoder.XmlAttributeEncode(userInput);
        Response.Write("<item name=\"" + safe + "\"/>");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO SnkHTMLOutput flow when payload is AntiXssEncoder.XmlAttributeEncode'd before Response.Write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: a tainted string's same-named method must NOT be treated as a
// sanitizer. The encoders are scoped to ObjectType "Encoder"/"AntiXssEncoder";
// a receiver named "userInput" is neither, so the flow must stay live. ---

func TestCSharp_AntiXssContextEncoder_Negative_DoesNotMatchTaintedReceiver(t *testing.T) {
	code := `
using System;

public class Handler {
    public void Handle(System.Web.HttpResponse Response) {
        string userInput = Console.ReadLine();
        string fake = userInput.CssEncode();
        Response.Write(fake);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("over-broad: tainted string's .CssEncode() must NOT be treated as an AntiXSS encoder (receiver 'userInput' is not an Encoder abbreviation)")
	}
}
