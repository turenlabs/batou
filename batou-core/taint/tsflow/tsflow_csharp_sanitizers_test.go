package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Sanitizer Tests — HtmlSanitizer (Ganss.Xss)
// =========================================================================

func TestCSharp_HtmlSanitizer_XSS_Sanitized(t *testing.T) {
	code := `
using System;
using Ganss.Xss;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var htmlSanitizer = new HtmlSanitizer();
        string clean = htmlSanitizer.Sanitize(input);
        Html.Raw(clean);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected XSS flow to be sanitized by HtmlSanitizer.Sanitize, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — Process.Start Command Injection
// =========================================================================

func TestCSharp_Process_UseShellExecuteFalse_Sanitized(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        string arg = Console.ReadLine();
        var psi = new ProcessStartInfo {
            FileName = "/usr/bin/ls",
            Arguments = arg,
            UseShellExecute = false
        };
        Process.Start(psi);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("expected command flow to be sanitized by UseShellExecute=false, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Process_NoProtection_Vulnerable(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        string cmd = Console.ReadLine();
        Process.Start(cmd);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Console.ReadLine -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — DataProtection for Trust Boundary
// =========================================================================

func TestCSharp_DataProtection_TrustBoundary_Sanitized(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.DataProtection;

public class Handler {
    private readonly IDataProtector _protector;

    public void Handle() {
        string userInput = Console.ReadLine();
        string protectedData = _protector.Protect(userInput);
        TempData["data"] = protectedData;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary && f.Confidence > 0.5 {
			t.Errorf("expected trust boundary flow to be sanitized by IDataProtector.Protect, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — FluentValidation + SQL
// =========================================================================

func TestCSharp_FluentValidation_SQL_Sanitized(t *testing.T) {
	code := `
using System;
using FluentValidation;
using System.Data.SqlClient;

public class UserValidator : AbstractValidator<User> {
    public UserValidator() {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(50);
    }
}

public class Handler {
    public void Handle(SqlCommand cmd) {
        string name = Console.ReadLine();
        var validator = new UserValidator();
        cmd.CommandText = "SELECT * FROM users WHERE name = '" + name + "'";
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected SQL flow to be sanitized by FluentValidation, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — CSharpScript Eval vulnerable baseline
// =========================================================================

func TestCSharp_CSharpScript_NoProtection_Vulnerable(t *testing.T) {
	code := `
using System;
using Microsoft.CodeAnalysis.CSharp.Scripting;

public class Handler {
    public async void Handle() {
        string code = Console.ReadLine();
        await CSharpScript.EvaluateAsync(code);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code eval flow for Console.ReadLine -> CSharpScript.EvaluateAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — ProcessStartInfo.ArgumentList (CWE-78)
// =========================================================================

func TestCSharp_ArgumentList_Command_Sanitized(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Handle() {
        string arg = Console.ReadLine();
        var psi = new ProcessStartInfo("/usr/bin/grep");
        psi.ArgumentList.Add(arg);
        Process.Start(psi);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("expected command flow to be sanitized by ArgumentList.Add, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — Path.GetExtension (CWE-22)
// =========================================================================

func TestCSharp_PathGetExtension_FileRead_Sanitized(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle() {
        string filename = Console.ReadLine();
        string ext = Path.GetExtension(filename);
        File.ReadAllText("/uploads/" + ext);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Errorf("expected file read flow to be sanitized by Path.GetExtension, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — Path.IsPathFullyQualified (CWE-22)
// =========================================================================

func TestCSharp_PathIsPathFullyQualified_FileWrite_Sanitized(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public void Handle() {
        string path = Console.ReadLine();
        if (Path.IsPathFullyQualified(path)) {
            File.WriteAllText(path, "data");
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Confidence > 0.5 {
			t.Errorf("expected file write flow to be sanitized by Path.IsPathFullyQualified, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — Protobuf deserialization (CWE-502)
// =========================================================================

func TestCSharp_Protobuf_ParseFrom_Sanitized(t *testing.T) {
	code := `
using System;
using Google.Protobuf;

public class Handler {
    public void Handle() {
        byte[] data = Convert.FromBase64String(Console.ReadLine());
        var msg = MyMessage.Parser.ParseFrom(data);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.5 {
			t.Errorf("expected deser flow to be sanitized by Protobuf ParseFrom, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_ProtobufNet_Deserialize_Sanitized(t *testing.T) {
	code := `
using System;
using System.IO;
using ProtoBuf;

public class Handler {
    public void Handle() {
        byte[] data = Convert.FromBase64String(Console.ReadLine());
        var stream = new MemoryStream(data);
        var obj = ProtoBuf.Serializer.Deserialize<MyModel>(stream);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.5 {
			t.Errorf("expected deser flow to be sanitized by ProtoBuf.Serializer.Deserialize, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — Convert.ToBase64String (safe output)
// =========================================================================

func TestCSharp_Base64_SQL_Sanitized(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;
using System.Text;

public class Handler {
    public void Handle(SqlCommand cmd) {
        string input = Console.ReadLine();
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
        cmd.CommandText = "SELECT * FROM t WHERE data = '" + encoded + "'";
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected SQL flow to be sanitized by Convert.ToBase64String, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — XsltArgumentList.AddParam (CWE-643)
// =========================================================================

func TestCSharp_XsltArgumentList_XPath_Sanitized(t *testing.T) {
	code := `
using System;
using System.Xml.Xsl;

public class Handler {
    public void Handle() {
        string userInput = Console.ReadLine();
        var args = new XsltArgumentList();
        args.AddParam("name", "", userInput);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath && f.Confidence > 0.5 {
			t.Errorf("expected XPath flow to be sanitized by XsltArgumentList.AddParam, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Sanitizer Tests — IAntiforgery.ValidateRequestAsync (CWE-352)
// =========================================================================

func TestCSharp_AntiforgeryValidateAsync_TrustBoundary_Sanitized(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

public class Handler {
    private readonly IAntiforgery _antiforgery;

    public async void Handle(HttpContext context) {
        string input = Console.ReadLine();
        await _antiforgery.ValidateRequestAsync(context);
        context.Session.SetString("key", input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary && f.Confidence > 0.5 {
			t.Errorf("expected trust boundary flow to be sanitized by ValidateRequestAsync, got confidence %.2f", f.Confidence)
		}
	}
}
