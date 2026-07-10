package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# XPath Injection (CWE-643) tests
// =========================================================================

func TestCSharp_XPath_NavigatorSelect(t *testing.T) {
	code := `
using System;
using System.Xml;
using System.Xml.XPath;

public class Handler {
    public XmlNodeList Handle(XmlDocument doc) {
        string userInput = Console.ReadLine();
        XPathNavigator navigator = doc.CreateNavigator();
        var result = navigator.Select("//users[@name='" + userInput + "']");
        return null;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for Console.ReadLine -> XPathNavigator.Select")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_XPath_NavigatorEvaluate(t *testing.T) {
	code := `
using System;
using System.Xml;
using System.Xml.XPath;

public class Handler {
    public object Handle(XmlDocument doc) {
        string userInput = Console.ReadLine();
        XPathNavigator navigator = doc.CreateNavigator();
        var result = navigator.Evaluate("count(//items[@type='" + userInput + "'])");
        return result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for Console.ReadLine -> XPathNavigator.Evaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_XPath_NavigatorMatches(t *testing.T) {
	code := `
using System;
using System.Xml;
using System.Xml.XPath;

public class Handler {
    public bool Handle(XmlDocument doc) {
        string userInput = Console.ReadLine();
        XPathNavigator navigator = doc.CreateNavigator();
        bool matched = navigator.Matches("//admin[@role='" + userInput + "']");
        return matched;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for Console.ReadLine -> XPathNavigator.Matches")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_XPath_LinqSelectElements(t *testing.T) {
	code := `
using System;
using System.Xml.Linq;
using System.Xml.XPath;

public class Handler {
    public void Handle(XDocument doc) {
        string userInput = Console.ReadLine();
        var elements = doc.XPathSelectElements("//users[@name='" + userInput + "']");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for Console.ReadLine -> XPathSelectElements")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_XPath_LinqSelectElement(t *testing.T) {
	code := `
using System;
using System.Xml.Linq;
using System.Xml.XPath;

public class Handler {
    public void Handle(XDocument doc) {
        string userInput = Console.ReadLine();
        var element = doc.XPathSelectElement("//user[@id='" + userInput + "']");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for Console.ReadLine -> XPathSelectElement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_XPath_LinqEvaluate(t *testing.T) {
	code := `
using System;
using System.Xml.Linq;
using System.Xml.XPath;

public class Handler {
    public object Handle(XDocument doc) {
        string userInput = Console.ReadLine();
        var result = doc.XPathEvaluate("count(//items[@category='" + userInput + "'])");
        return result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for Console.ReadLine -> XPathEvaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Sanitizer tests — verify XPath sanitizers prevent false positives
// =========================================================================

func TestCSharp_XPath_Sanitized_XmlConvertEncode(t *testing.T) {
	code := `
using System;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

public class Handler {
    public void Handle(XDocument doc) {
        string userInput = Console.ReadLine();
        string safe = XmlConvert.EncodeLocalName(userInput);
        var elements = doc.XPathSelectElements("//users[@name='" + safe + "']");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected NO XPath injection flow when input is sanitized via XmlConvert.EncodeLocalName")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_XPath_Sanitized_SecurityElementEscape(t *testing.T) {
	code := `
using System;
using System.Security;
using System.Xml;
using System.Xml.XPath;

public class Handler {
    public void Handle(XmlDocument doc) {
        string userInput = Console.ReadLine();
        string safe = SecurityElement.Escape(userInput);
        XPathNavigator navigator = doc.CreateNavigator();
        var result = navigator.Select("//users[@name='" + safe + "']");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected NO XPath injection flow when input is sanitized via SecurityElement.Escape")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
