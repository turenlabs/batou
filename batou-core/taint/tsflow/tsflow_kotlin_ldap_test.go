package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func TestKotlin_LDAP_DirContext_Bind(t *testing.T) {
	code := `
import javax.naming.directory.InitialDirContext

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    val dirCtx = InitialDirContext()
    dirCtx.bind(dn, entry)
}
`
	flows := Analyze(code, "/app/LdapHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> DirContext.bind()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_DirContext_Rebind(t *testing.T) {
	code := `
import javax.naming.directory.DirContext

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    dirContext.rebind(dn, entry)
}
`
	flows := Analyze(code, "/app/LdapHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> DirContext.rebind()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_DirContext_CreateSubcontext(t *testing.T) {
	code := `
import javax.naming.directory.DirContext

fun handler(request: HttpServletRequest) {
    val org = request.getParameter("org")
    val dn = "ou=" + org + ",dc=example,dc=com"
    dirContext.createSubcontext(dn, attrs)
}
`
	flows := Analyze(code, "/app/LdapHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> DirContext.createSubcontext()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_DirContext_ModifyAttributes(t *testing.T) {
	code := `
import javax.naming.directory.DirContext

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val dn = "uid=" + user + ",ou=people"
    dirContext.modifyAttributes(dn, mods)
}
`
	flows := Analyze(code, "/app/LdapHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> DirContext.modifyAttributes()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_DirContext_Rename(t *testing.T) {
	code := `
import javax.naming.directory.DirContext

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val oldDn = "uid=" + user + ",ou=people"
    val newDn = "uid=" + user + ",ou=archive"
    dirContext.rename(oldDn, newDn)
}
`
	flows := Analyze(code, "/app/LdapHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> DirContext.rename()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_Spring_Search(t *testing.T) {
	code := `
import org.springframework.ldap.core.LdapTemplate

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val filter = "(uid=" + user + ")"
    ldapTemplate.search(filter, null)
}
`
	flows := Analyze(code, "/app/SpringLdap.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> LdapTemplate.search()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_Spring_Bind(t *testing.T) {
	code := `
import org.springframework.ldap.core.LdapTemplate

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val dn = "uid=" + user + ",ou=people"
    ldapTemplate.bind(dn, entry, null)
}
`
	flows := Analyze(code, "/app/SpringLdap.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> LdapTemplate.bind()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_Spring_Authenticate(t *testing.T) {
	code := `
import org.springframework.ldap.core.LdapTemplate

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val filter = "(uid=" + user + ")"
    ldapTemplate.authenticate("ou=people", filter, "password")
}
`
	flows := Analyze(code, "/app/SpringLdap.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> LdapTemplate.authenticate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_UnboundID_Search(t *testing.T) {
	code := `
import com.unboundid.ldap.sdk.LDAPConnection
import com.unboundid.ldap.sdk.SearchRequest

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val filter = "(uid=" + user + ")"
    val ldapConn = LDAPConnection("ldap.example.com", 389)
    ldapConn.search("dc=example", filter)
}
`
	flows := Analyze(code, "/app/UnboundIdLdap.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> LDAPConnection.search()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_LDAP_UnboundID_Bind(t *testing.T) {
	code := `
import com.unboundid.ldap.sdk.LDAPConnection

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val dn = "uid=" + user + ",ou=people"
    val ldapConn = LDAPConnection("ldap.example.com", 389)
    ldapConn.bind(dn, "password")
}
`
	flows := Analyze(code, "/app/UnboundIdLdap.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> LDAPConnection.bind()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sanitizer negative tests (should NOT produce high-confidence LDAP flow) ---

func TestKotlin_LDAP_Safe_LdapName(t *testing.T) {
	code := `
import javax.naming.ldap.LdapName

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val safeDn = LdapName(user)
    dirContext.bind(safeDn, entry)
}
`
	flows := Analyze(code, "/app/SafeLdap.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP && f.Confidence > 0.5 {
			t.Error("expected no high-confidence LDAP flow when LdapName() validates DN")
		}
	}
}

func TestKotlin_LDAP_Safe_RdnEscapeValue(t *testing.T) {
	code := `
import javax.naming.ldap.Rdn

fun handler(request: HttpServletRequest) {
    val user = request.getParameter("user")
    val escaped = Rdn.escapeValue(user)
    val dn = "uid=" + escaped + ",ou=people"
    dirContext.bind(dn, entry)
}
`
	flows := Analyze(code, "/app/SafeLdap.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP && f.Confidence > 0.5 {
			t.Error("expected no high-confidence LDAP flow when Rdn.escapeValue() sanitizes input")
		}
	}
}
