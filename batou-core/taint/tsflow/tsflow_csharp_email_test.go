package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Email Header Injection (CWE-93)
// System.Net.Mail (MailAddress / MailMessage.Headers) and MimeKit
// (MailboxAddress) accept raw strings as recipient/display-name/header
// values. CRLF characters injected by an attacker produce extra SMTP
// headers. CVE-2026-30227 documents the MimeKit quoted-local-part
// variant that enables full SMTP command injection.
// =========================================================================

func TestCSharp_EmailInjection_MailAddressCtor_DisplayName(t *testing.T) {
	code := `
using System;
using System.Net.Mail;

public class Handler {
    public void Handle() {
        string displayName = Console.ReadLine();
        var addr = new MailAddress("noreply@example.com", displayName);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for Console.ReadLine -> new MailAddress(..., displayName)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_EmailInjection_MimeKit_MailboxAddressCtor(t *testing.T) {
	code := `
using System;
using MimeKit;

public class Handler {
    public void Handle() {
        string userName = Console.ReadLine();
        var from = new MailboxAddress(userName, "noreply@example.com");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for Console.ReadLine -> new MailboxAddress(userName, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_EmailInjection_MimeKit_MailboxAddress_Address_CRLF(t *testing.T) {
	// CVE-2026-30227 — tainted address string with quoted local-part
	// enabled SMTP command injection via MailboxAddress ctor.
	code := `
using System;
using MimeKit;

public class Handler {
    public void Handle() {
        string recipient = Console.ReadLine();
        var to = new MailboxAddress("Friend", recipient);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for Console.ReadLine -> new MailboxAddress(name, recipient) [CVE-2026-30227]")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_EmailInjection_MailMessage_HeadersAdd(t *testing.T) {
	code := `
using System;
using System.Net.Mail;

public class Handler {
    public void Handle() {
        string headerValue = Console.ReadLine();
        var msg = new MailMessage();
        msg.Headers.Add("X-Custom", headerValue);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for Console.ReadLine -> msg.Headers.Add(name, value)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_EmailInjection_SendGrid_AddHeader(t *testing.T) {
	code := `
using System;
using SendGrid.Helpers.Mail;

public class Handler {
    public void Handle() {
        string traceId = Console.ReadLine();
        var msg = new SendGridMessage();
        msg.AddHeader("X-Trace-Id", traceId);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected email header injection flow for Console.ReadLine -> SendGridMessage.AddHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_EmailInjection_LegacyAspNet_AddHeader(t *testing.T) {
	// System.Web.HttpResponse.AddHeader — legacy ASP.NET.
	// Classic CRLF header-injection vector.
	code := `
using System;
using System.Web;

public class Handler {
    public void Handle(HttpResponse response) {
        string lang = Console.ReadLine();
        response.AddHeader("Content-Language", lang);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for Console.ReadLine -> HttpResponse.AddHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: tainted display name is CRLF-stripped before being passed to the
// MailAddress constructor. No SnkHeader flow should be reported.
func TestCSharp_EmailInjection_MailAddress_Sanitized_NoFlow(t *testing.T) {
	code := `
using System;
using System.Net.Mail;

public class Handler {
    public void Handle() {
        string raw = Console.ReadLine();
        string safe = raw.Replace("\r", "").Replace("\n", "");
        var addr = new MailAddress("noreply@example.com", safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("unexpected header flow after CRLF sanitization: source=%s sink=%s", f.Source.Category, f.Sink.Category)
		}
	}
}
