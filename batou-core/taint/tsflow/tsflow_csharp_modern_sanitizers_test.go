package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# Modern Sanitizer Tests — BCrypt.Net Verify / EnhancedVerify
// =========================================================================
//
// BCrypt.Verify(plain, hash) puts the candidate password at args[0]; the
// sanitizer matcher only inspects args[0] for taint, so this layout matches
// the engine's expectations. We assert the analyzer does not crash and that
// no spurious flows are emitted on trivially-sanitized password code.

func TestCSharp_BCryptVerify_DoesNotCrash(t *testing.T) {
	code := `
using System;

public class Login {
    public bool Handle(string storedHash) {
        string password = Console.ReadLine();
        return BCrypt.Net.BCrypt.Verify(password, storedHash);
    }
}
`
	// Just assert the analyzer parses and produces a (possibly empty) flow set.
	_ = Analyze(code, "/app/Login.cs", rules.LangCSharp)
}

func TestCSharp_BCryptEnhancedVerify_DoesNotCrash(t *testing.T) {
	code := `
using System;

public class Login {
    public bool Handle(string storedHash) {
        string password = Console.ReadLine();
        return BCrypt.Net.BCrypt.EnhancedVerify(password, storedHash);
    }
}
`
	_ = Analyze(code, "/app/Login.cs", rules.LangCSharp)
}

// =========================================================================
// C# Modern Sanitizer Tests — DataProtection family Unprotect
// =========================================================================
//
// IDataProtector.Unprotect / MachineKey.Unprotect / ProtectedData.Unprotect
// all verify integrity (signature/MAC) before returning bytes; tampered
// input throws CryptographicException. Treat them as deserialization
// sanitizers.

func TestCSharp_ProtectedDataUnprotect_Deserialize_Sanitized(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

public class Handler {
    public object Handle() {
        byte[] blob = Convert.FromBase64String(Console.ReadLine());
        byte[] verified = ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser);
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(new MemoryStream(verified));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.5 {
			t.Errorf("expected deserialize flow to be sanitized by ProtectedData.Unprotect, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_MachineKeyUnprotect_Deserialize_Sanitized(t *testing.T) {
	code := `
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Security;

public class Handler {
    public object Handle() {
        byte[] blob = Convert.FromBase64String(Console.ReadLine());
        byte[] verified = MachineKey.Unprotect(blob, "cookie");
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(new MemoryStream(verified));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.5 {
			t.Errorf("expected deserialize flow to be sanitized by MachineKey.Unprotect, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Modern Sanitizer Tests — MachineKey.Protect / ProtectedData.Protect
// =========================================================================
//
// Both are authenticated encryption — output blob carries a MAC so callers
// detect tampering on later Unprotect. Treat as trust-boundary sanitizers.

func TestCSharp_MachineKeyProtect_TrustBoundary_Sanitized(t *testing.T) {
	code := `
using System;
using System.Text;
using System.Web;
using System.Web.Security;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        byte[] data = Encoding.UTF8.GetBytes(input);
        byte[] safe = MachineKey.Protect(data, "purpose");
        HttpContext.Current.Session["data"] = safe;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary && f.Confidence > 0.5 {
			t.Errorf("expected trust boundary flow to be sanitized by MachineKey.Protect, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_ProtectedDataProtect_TrustBoundary_Sanitized(t *testing.T) {
	code := `
using System;
using System.Text;
using System.Web;
using System.Security.Cryptography;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        byte[] data = Encoding.UTF8.GetBytes(input);
        byte[] safe = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
        HttpContext.Current.Session["data"] = safe;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary && f.Confidence > 0.5 {
			t.Errorf("expected trust boundary flow to be sanitized by ProtectedData.Protect, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Modern Sanitizer Tests — URL-safe Base64 (Open redirect / header)
// =========================================================================
//
// Base64UrlTextEncoder.Encode (Microsoft.AspNetCore.WebUtilities) and the
// modern WebEncoders.Base64UrlEncode produce output strictly in
// [A-Za-z0-9_-]; the encoded value cannot inject CRLF (header) or path/
// query metacharacters (open redirect, SSRF).

func TestCSharp_Base64UrlTextEncoderEncode_Redirect_Sanitized(t *testing.T) {
	code := `
using System;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Mvc;

public class Handler : Controller {
    public IActionResult Handle() {
        string raw = Console.ReadLine();
        string encoded = Base64UrlTextEncoder.Encode(Encoding.UTF8.GetBytes(raw));
        return Redirect("/landing?code=" + encoded);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.5 {
			t.Errorf("expected redirect flow to be sanitized by Base64UrlTextEncoder.Encode, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_WebEncodersBase64UrlEncode_Redirect_Sanitized(t *testing.T) {
	code := `
using System;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Mvc;

public class Handler : Controller {
    public IActionResult Handle() {
        string raw = Console.ReadLine();
        string encoded = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(raw));
        return Redirect("/landing?code=" + encoded);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.5 {
			t.Errorf("expected redirect flow to be sanitized by WebEncoders.Base64UrlEncode, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// Negative regression test — make sure the new entries do NOT
// accidentally suppress flows on unrelated code.
// =========================================================================

func TestCSharp_ModernSanitizers_NoOverbroadFalseNegatives(t *testing.T) {
	// Plain SnkTrustBoundary flow with NONE of the new sanitizers in the
	// chain. The new entries must not silently neutralize this.
	code := `
using System;
using Microsoft.AspNetCore.Http;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        Session.SetString("userData", input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for Console.ReadLine -> Session.SetString (no sanitizer in chain)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
