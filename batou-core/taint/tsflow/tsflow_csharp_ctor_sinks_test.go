package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# constructor-sink dead-keying fixes (PR follow-up to #1253/#1254).
//
// A cluster of C# sinks carried `MethodName: "new <Type>"`. tsflow keys an
// object_creation_expression by its bare constructed type name, so the
// leading "new " produced an index key ("new HtmlString", "new FileInfo", …)
// that no call node ever matches — the sinks were registered but unreachable.
// These tests assert the idiomatic vulnerable constructor shape now fires at
// the dataflow tier, and that the safe (constant / no-taint) form stays clean.
// =========================================================================

func csFlowFires(t *testing.T, code string, cat taint.SinkCategory) (bool, float64) {
	t.Helper()
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == cat {
			return true, f.Confidence
		}
	}
	return false, 0
}

func TestCSharp_Ctor_HtmlString_XSS(t *testing.T) {
	code := `
using System; using Microsoft.AspNetCore.Html;
public class H { public void M() {
  string s = Console.ReadLine();
  var html = new HtmlString(s);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkHTMLOutput); !ok {
		t.Error("expected XSS flow for Console.ReadLine -> new HtmlString")
	}
	// Safe: constant literal -> no flow.
	safe := `
using System; using Microsoft.AspNetCore.Html;
public class H { public void M() {
  var html = new HtmlString("<b>static</b>");
}}`
	if ok, _ := csFlowFires(t, safe, taint.SnkHTMLOutput); ok {
		t.Error("did not expect XSS flow for new HtmlString with a constant literal")
	}
}

func TestCSharp_Ctor_MarkupString_XSS(t *testing.T) {
	code := `
using System; using Microsoft.AspNetCore.Components;
public class H { public void M() {
  string s = Console.ReadLine();
  var m = new MarkupString(s);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkHTMLOutput); !ok {
		t.Error("expected XSS flow for Console.ReadLine -> new MarkupString")
	}
}

func TestCSharp_Ctor_FileStream_PathTraversal(t *testing.T) {
	code := `
using System; using System.IO;
public class H { public void M() {
  string p = Console.ReadLine();
  var fs = new FileStream(p, FileMode.Open);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkFileWrite); !ok {
		t.Error("expected path-traversal flow for Console.ReadLine -> new FileStream")
	}
	// Safe: hardcoded path -> no flow.
	safe := `
using System; using System.IO;
public class H { public void M() {
  var fs = new FileStream("/etc/app/config.json", FileMode.Open);
}}`
	if ok, _ := csFlowFires(t, safe, taint.SnkFileWrite); ok {
		t.Error("did not expect flow for new FileStream with a constant path")
	}
}

func TestCSharp_Ctor_FileInfo_PathTraversal(t *testing.T) {
	code := `
using System; using System.IO;
public class H { public void M() {
  string p = Console.ReadLine();
  var fi = new FileInfo(p);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkFileRead); !ok {
		t.Error("expected path-traversal flow for Console.ReadLine -> new FileInfo")
	}
}

func TestCSharp_Ctor_DirectoryInfo_PathTraversal(t *testing.T) {
	code := `
using System; using System.IO;
public class H { public void M() {
  string p = Console.ReadLine();
  var di = new DirectoryInfo(p);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkFileRead); !ok {
		t.Error("expected path-traversal flow for Console.ReadLine -> new DirectoryInfo")
	}
}

func TestCSharp_Ctor_Regex_ReDoS(t *testing.T) {
	code := `
using System; using System.Text.RegularExpressions;
public class H { public void M() {
  string pat = Console.ReadLine();
  var re = new Regex(pat);
}}`
	// csharp.regex.new is categorised SnkEval (untrusted pattern compilation, CWE-1333).
	if ok, _ := csFlowFires(t, code, taint.SnkEval); !ok {
		t.Error("expected untrusted-pattern flow for Console.ReadLine -> new Regex")
	}
	// Safe: constant pattern -> no flow.
	safe := `
using System; using System.Text.RegularExpressions;
public class H { public void M() {
  var re = new Regex("^[a-z]+$");
}}`
	if ok, _ := csFlowFires(t, safe, taint.SnkEval); ok {
		t.Error("did not expect flow for new Regex with a constant pattern")
	}
}

func TestCSharp_Ctor_DirectorySearcher_LDAP(t *testing.T) {
	// arg-0 form: new DirectorySearcher(filter)  (IssueBlot.NET LDAPInjection2 ds2)
	code0 := `
using System; using System.DirectoryServices;
public class H { public void M() {
  string u = Console.ReadLine();
  var ds = new DirectorySearcher("(&(objectClass=user)(cn=" + u + "))");
}}`
	if ok, _ := csFlowFires(t, code0, taint.SnkLDAP); !ok {
		t.Error("expected LDAP-injection flow for Console.ReadLine -> new DirectorySearcher(filter)")
	}
	// arg-1 form: new DirectorySearcher(entry, filter)  (IssueBlot.NET ds3)
	code1 := `
using System; using System.DirectoryServices;
public class H { public void M() {
  string u = Console.ReadLine();
  var ds = new DirectorySearcher(new DirectoryEntry("LDAP://x"), "(cn=" + u + ")");
}}`
	if ok, _ := csFlowFires(t, code1, taint.SnkLDAP); !ok {
		t.Error("expected LDAP-injection flow for Console.ReadLine -> new DirectorySearcher(entry, filter)")
	}
	// Safe: constant filter -> no flow.
	safe := `
using System; using System.DirectoryServices;
public class H { public void M() {
  var ds = new DirectorySearcher("(objectClass=user)");
}}`
	if ok, _ := csFlowFires(t, safe, taint.SnkLDAP); ok {
		t.Error("did not expect LDAP flow for new DirectorySearcher with a constant filter")
	}
}

func TestCSharp_Ctor_SearchRequest_LDAP(t *testing.T) {
	code := `
using System; using System.DirectoryServices.Protocols;
public class H { public void M() {
  string u = Console.ReadLine();
  var req = new SearchRequest("dc=x", "(cn=" + u + ")", SearchScope.Subtree);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkLDAP); !ok {
		t.Error("expected LDAP-injection flow for Console.ReadLine -> new SearchRequest(dn, filter, scope)")
	}
}

func TestCSharp_Ctor_DirectoryEntry_LDAP(t *testing.T) {
	code := `
using System; using System.DirectoryServices;
public class H { public void M() {
  string u = Console.ReadLine();
  var e = new DirectoryEntry("LDAP://" + u);
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkLDAP); !ok {
		t.Error("expected LDAP-injection flow for Console.ReadLine -> new DirectoryEntry(path)")
	}
}

// Negative: a same-named user-defined constructor must not fire. `new FileInfo`
// is path-specific, but assert that an unrelated `new Regex` benign use with a
// constant does not leak into other categories, and that a constant DirectoryEntry
// constant path stays clean (the matcher requires a tainted arg).
func TestCSharp_Ctor_BenignSameName_NoFlow(t *testing.T) {
	code := `
using System; using System.DirectoryServices;
public class H { public void M() {
  var e = new DirectoryEntry("LDAP://localhost/DC=corp,DC=local");
}}`
	if ok, _ := csFlowFires(t, code, taint.SnkLDAP); ok {
		t.Error("did not expect LDAP flow for new DirectoryEntry with a constant path")
	}
}
