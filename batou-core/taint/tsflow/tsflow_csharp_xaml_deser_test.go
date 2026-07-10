package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# XAML deserialization RCE (CWE-502)
//
// System.Windows.Markup.XamlReader.Parse/Load and System.Xaml.XamlServices
// .Parse/.Load instantiate arbitrary CLR types from XAML markup. When the
// markup is attacker-controlled it can embed an ObjectDataProvider gadget that
// invokes an arbitrary method (e.g. Process.Start) — the canonical
// ysoserial.net "ObjectDataProvider + XamlReader" RCE chain. The markup/stream
// is positional arg 0; a literal there carries no taint and never fires.
// ===========================================================================

func TestCSharp_Sink_XamlReader_Parse(t *testing.T) {
	code := `
using System;
using System.Windows.Markup;
using Microsoft.AspNetCore.Mvc;

public class ViewController : Controller {
    public IActionResult Render() {
        string markup = Request.QueryString.Value;
        object view = XamlReader.Parse(markup);
        return Ok(view.ToString());
    }
}
`
	flows := Analyze(code, "/app/ViewController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for Request.QueryString -> XamlReader.Parse (XAML RCE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_XamlReader_Load(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Xml;
using System.Windows.Markup;
using Microsoft.AspNetCore.Mvc;

public class ViewController : Controller {
    public IActionResult Render() {
        string markup = Request.QueryString.Value;
        var reader = XmlReader.Create(new StringReader(markup));
        object view = XamlReader.Load(reader);
        return Ok(view.ToString());
    }
}
`
	flows := Analyze(code, "/app/ViewController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for Request.QueryString -> XamlReader.Load (XAML RCE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_XamlServices_Parse(t *testing.T) {
	code := `
using System;
using System.Xaml;
using Microsoft.AspNetCore.Mvc;

public class WorkflowController : Controller {
    public IActionResult Run() {
        string markup = Request.QueryString.Value;
        object obj = XamlServices.Parse(markup);
        return Ok(obj.ToString());
    }
}
`
	flows := Analyze(code, "/app/WorkflowController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for Request.QueryString -> XamlServices.Parse (XAML RCE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_XamlServices_Load(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Xml;
using System.Xaml;
using Microsoft.AspNetCore.Mvc;

public class WorkflowController : Controller {
    public IActionResult Run() {
        string markup = Request.QueryString.Value;
        var reader = XmlReader.Create(new StringReader(markup));
        object obj = XamlServices.Load(reader);
        return Ok(obj.ToString());
    }
}
`
	flows := Analyze(code, "/app/WorkflowController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for Request.QueryString -> XamlServices.Load (XAML RCE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: the XAML markup is a hardcoded literal — no untrusted data reaches the
// loader, so no deserialization flow should be reported.
func TestCSharp_Sink_XamlReader_Parse_Safe_Literal(t *testing.T) {
	code := `
using System;
using System.Windows.Markup;
using Microsoft.AspNetCore.Mvc;

public class ViewController : Controller {
    public IActionResult Render() {
        string unused = Request.Form["xaml"];
        object view = XamlReader.Parse("<Button xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'/>");
        return Ok(view.ToString());
    }
}
`
	flows := Analyze(code, "/app/ViewController.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("did not expect SnkDeserialize flow when the XAML markup is a literal; got flow: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
