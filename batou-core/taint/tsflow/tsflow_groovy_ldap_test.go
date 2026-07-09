package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy LDAP injection tests (CWE-90)
//
// Covers JNDI DirContext (bind/rebind/createSubcontext/modifyAttributes/
// rename), Spring LdapTemplate (bind/authenticate), and UnboundID
// LDAPConnection (search/bind). All flows pass tainted DN or filter values
// without LDAP-specific escaping.
// =========================================================================

func TestGroovy_LDAP_DirContextBind(t *testing.T) {
	code := `
def handler(input) {
    def ctx = new InitialDirContext(env)
    ctx.bind(input, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ctx.bind")
		t.Error("expected LDAP DN injection flow for parameter input -> ctx.bind")
	}
}
// Groovy LDAP injection tests (CWE-90)
// Covers JNDI DirContext DN operations, Spring LdapTemplate operations,
// UnboundID LDAP SDK, and LdapContext search.
// =========================================================================

func TestGroovy_DirContextBindLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    dirContext.bind(userInput, obj)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> DirContext.bind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_DirContext_Rebind_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ctx = new InitialDirContext(env)
    ctx.rebind(userInput, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ctx.rebind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_DirContext_CreateSubcontext_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def dirContext = new InitialDirContext(env)
    dirContext.createSubcontext(userInput, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> dirContext.createSubcontext")
	}
}
func TestGroovy_LDAP_DirContextRebind(t *testing.T) {
	code := `
def handler(input) {
    def dirContext = new InitialDirContext(env)
    dirContext.rebind(input, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> dirContext.rebind")
	}
}

func TestGroovy_LDAP_DirContextCreateSubcontext(t *testing.T) {
	code := `
def handler(input) {
    def ctx = new InitialDirContext(env)
    ctx.createSubcontext(input, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> ctx.createSubcontext")
	}
}

func TestGroovy_LDAP_DirContextDestroySubcontext(t *testing.T) {
	code := `
def handler(input) {
    def ctx = new InitialDirContext(env)
    ctx.destroySubcontext(input)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> ctx.destroySubcontext")
	}
}

func TestGroovy_LDAP_DirContextModifyAttributes(t *testing.T) {
	code := `
def handler(input) {
    def ctx = new InitialDirContext(env)
    ctx.modifyAttributes(input, mods)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> ctx.modifyAttributes")
	}
}

func TestGroovy_LDAP_DirContextRename(t *testing.T) {
	code := `
def handler(input, data) {
    def ctx = new InitialDirContext(env)
    ctx.rename(input, data)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> ctx.rename")
	}
}

// =========================================================================
// Groovy Spring LdapTemplate tests (CWE-90)
// =========================================================================

func TestGroovy_LDAP_SpringLdapTemplateBind(t *testing.T) {
	code := `
def handler(input) {
    ldapTemplate.bind(input, obj, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> ldapTemplate.bind")
	}
}

func TestGroovy_LDAP_SpringLdapTemplateAuthenticate(t *testing.T) {
	code := `
def handler(input) {
    def filterStr = "(uid=" + input + ")"
    ldapTemplate.authenticate("ou=users", filterStr, password)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP filter injection flow for parameter input -> ldapTemplate.authenticate")
	}
}
func TestGroovy_DirContextRebindLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    dirContext.rebind(userInput, attrs)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> DirContext.rebind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_LDAP_SpringLdapTemplateFindOne(t *testing.T) {
	code := `
def handler(input) {
    def filterStr = "(uid=" + input + ")"
    ldapTemplate.findOne(filterStr, User.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP filter injection flow for parameter input -> ldapTemplate.findOne")
	}
}

func TestGroovy_LDAP_SpringLdapTemplateFind(t *testing.T) {
	code := `
def handler(input) {
    ldapTemplate.find(input, User.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP filter injection flow for parameter input -> ldapTemplate.find")
	}
}
func TestGroovy_DirContextModifyAttributesLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    dirContext.modifyAttributes(userInput, modItems)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> DirContext.modifyAttributes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_DirContextCreateSubcontextLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    dirContext.createSubcontext(userInput, attrs)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> DirContext.createSubcontext")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_DirContext_ModifyAttributes_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ctx = new InitialDirContext(env)
    ctx.modifyAttributes(userInput, mods)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ctx.modifyAttributes")
	}
}
func TestGroovy_DirContextDestroySubcontextLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    dirContext.destroySubcontext(userInput)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> DirContext.destroySubcontext")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_DirContext_Rename_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ctx = new InitialDirContext(env)
    ctx.rename(userInput, "cn=new,dc=example,dc=com")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ctx.rename")
	}
}
func TestGroovy_DirContextRenameLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    dirContext.rename(userInput, "cn=new,ou=users")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> DirContext.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_LdapTemplate_Bind_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ldapTemplate = new LdapTemplate(contextSource)
    ldapTemplate.bind(userInput, ctx, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ldapTemplate.bind")
	}
}
func TestGroovy_LdapContextSearchLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapContext.search("ou=users,dc=example,dc=com", userInput, searchControls)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LdapContext.search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_LdapTemplate_Authenticate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ldapTemplate = new LdapTemplate(contextSource)
    def ok = ldapTemplate.authenticate("ou=people", userInput, password)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ldapTemplate.authenticate")
	}
}
func TestGroovy_SpringLdapTemplateBindLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapTemplate.bind(userInput, entry, null)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LdapTemplate.bind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_UnboundID_Search_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ldapConnection = new LDAPConnection(host, port)
    def result = ldapConnection.search("dc=example,dc=com", SearchScope.SUB, userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ldapConnection.search")
	}
}
func TestGroovy_SpringLdapTemplateUnbindLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapTemplate.unbind(userInput)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LdapTemplate.unbind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_UnboundID_Bind_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ldapConnection = new LDAPConnection(host, port)
    ldapConnection.bind(userInput, password)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for userInput -> ldapConnection.bind")
	}
}
func TestGroovy_SpringLdapTemplateFindOneLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapTemplate.findOne(userInput, mapper)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LdapTemplate.findOne")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringLdapTemplateAuthenticateLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapTemplate.authenticate("ou=users", userInput, password)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LdapTemplate.authenticate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_UnboundIDLDAPConnectionBindLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapConnection.bind(userInput, password)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LDAPConnection.bind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_UnboundIDLDAPConnectionSearchLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapConnection.search("dc=example,dc=com", SearchScope.SUB, userInput)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LDAPConnection.search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_UnboundIDLDAPConnectionModifyLDAPInjection(t *testing.T) {
	code := `
def handler(userInput) {
    ldapConnection.modify(userInput, modifications)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter userInput -> LDAPConnection.modify")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Groovy UnboundID LDAP SDK tests (CWE-90)
// =========================================================================

func TestGroovy_LDAP_UnboundIDSearch(t *testing.T) {
	code := `
def handler(input) {
    def ldapConnection = new LDAPConnection("ldap.example.com", 389)
    ldapConnection.search("dc=example,dc=com", SearchScope.SUB, input)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter input -> ldapConnection.search (UnboundID)")
	}
}

func TestGroovy_LDAP_UnboundIDBind(t *testing.T) {
	code := `
def handler(input) {
    def ldapConnection = new LDAPConnection("ldap.example.com", 389)
    ldapConnection.bind(input, password)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for parameter input -> ldapConnection.bind (UnboundID)")
	}
}

// =========================================================================
// Safe / sanitized cases — ensure existing sanitizers still neutralize the new sinks
// =========================================================================

func TestGroovy_LDAP_BindSafe_NameEncode(t *testing.T) {
	code := `
def handler(input) {
    def safeDn = LdapEncoder.nameEncode(input)
    def ctx = new InitialDirContext(env)
    ctx.bind(safeDn, attrs)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("did not expect LDAP flow when DN is sanitized via LdapEncoder.nameEncode")
		t.Error("LdapEncoder.nameEncode() should neutralize DN taint before ctx.bind")
	}
}

func TestGroovy_LDAP_AuthenticateSafe_FilterEncode(t *testing.T) {
	code := `
def handler(username) {
    def safeUid = LdapEncoder.filterEncode(username)
    def filter = "(uid=" + safeUid + ")"
    ldapTemplate.authenticate("ou=users", filter, password)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapEncoder.filterEncode() should neutralize filter taint before ldapTemplate.authenticate")
	}
}
// Negative tests — sanitizers should suppress the LDAP flow
// =========================================================================

func TestGroovy_RdnEscapeValueSanitizes(t *testing.T) {
	code := `
def handler(userInput) {
    def escaped = Rdn.escapeValue(userInput)
    ldapTemplate.bind(escaped, entry, null)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("did not expect LDAP flow when input is escaped via Rdn.escapeValue()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ApacheFilterEncoderSanitizes(t *testing.T) {
	code := `
def handler(userInput) {
    def safe = FilterEncoder.encodeFilterValue(userInput)
    ldapConnection.search("dc=example,dc=com", SearchScope.SUB, safe)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("did not expect LDAP flow when input is encoded via FilterEncoder.encodeFilterValue()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
