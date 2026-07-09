package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# LDAP Injection — System.DirectoryServices.AccountManagement (CWE-90)
// =========================================================================

func TestCSharp_LDAP_UserPrincipalFindByIdentity(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.AccountManagement;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com");
        var user = UserPrincipal.FindByIdentity(ctx, input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> UserPrincipal.FindByIdentity")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_GroupPrincipalFindByIdentity(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.AccountManagement;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com");
        var group = GroupPrincipal.FindByIdentity(ctx, IdentityType.Name, input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> GroupPrincipal.FindByIdentity")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_ComputerPrincipalFindByIdentity(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.AccountManagement;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com");
        var comp = ComputerPrincipal.FindByIdentity(ctx, input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> ComputerPrincipal.FindByIdentity")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_PrincipalContextNew(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.AccountManagement;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com", input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> new PrincipalContext(container)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_PrincipalContextValidateCredentials(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.AccountManagement;

public class Handler {
    public bool Handle() {
        string input = Console.ReadLine();
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com");
        return ctx.ValidateCredentials(input, "fixed-password");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> PrincipalContext.ValidateCredentials")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_PrincipalSearcherNew(t *testing.T) {
	// UserPrincipal(PrincipalContext, samAccountName, password, enabled) seeds the
	// principal's SamAccountName from the constructor — a tainted samAccountName
	// makes the resulting Principal a tainted query template for PrincipalSearcher.
	code := `
using System;
using System.DirectoryServices.AccountManagement;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com");
        var query = new UserPrincipal(ctx, input, "fixed-pwd", true);
        var searcher = new PrincipalSearcher(query);
        searcher.FindAll();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> new PrincipalSearcher")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_LdapDirectoryIdentifierNew(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.Protocols;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        var identifier = new LdapDirectoryIdentifier(input, 389);
        var conn = new LdapConnection(identifier);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> new LdapDirectoryIdentifier")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_UserPrincipalFindByIdentity_Sanitized(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.AccountManagement;
using Microsoft.Security.Application;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        string safe = Encoder.LdapFilterEncode(input);
        var ctx = new PrincipalContext(ContextType.Domain, "corp.example.com");
        var user = UserPrincipal.FindByIdentity(ctx, safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP && f.Confidence > 0.5 {
			t.Errorf("expected LDAP flow to be sanitized by Encoder.LdapFilterEncode, got confidence %.2f", f.Confidence)
		}
	}
}
