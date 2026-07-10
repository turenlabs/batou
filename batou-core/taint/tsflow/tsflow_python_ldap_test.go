package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Python LDAP injection — python-ldap synchronous _s methods (CWE-90).
// These methods take a tainted DN or filter that, without escape_filter_chars or
// escape_dn_chars, permits CWE-90 LDAP injection attacks.

func TestPython_LDAP_SearchExtS(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.args.get("user")
    conn = ldap.initialize("ldap://example.com")
    conn.search_ext_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> search_ext_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_SearchSt(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user_cn = request.args.get("cn")
    conn = ldap.initialize("ldap://example.com")
    dn = "cn=" + user_cn + ",ou=users,dc=example,dc=com"
    modlist = [("objectClass", [b"inetOrgPerson"])]
    conn.add_s(dn, modlist)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow when user input reaches add_s DN")
	}
}

func TestPython_LDAP_SearchStFilter(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    filt = request.args.get("filter")
    conn = ldap.initialize("ldap://example.com")
    conn.search_st("dc=example,dc=com", ldap.SCOPE_SUBTREE, filt)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> search_st()")
	}
}

func TestPython_LDAP_SimpleBindS(t *testing.T) {
	code := `
import ldap
from flask import request

def login():
    user = request.form.get("username")
    l = ldap.initialize("ldap://dir.example.com")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    l.simple_bind_s(dn, "password")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.form -> ldap.simple_bind_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_AddS(t *testing.T) {
	code := `
def handler():
    uid = request.args.get("uid")
    conn = ldap.initialize("ldap://example.com")
    dn = "uid=" + uid + ",ou=users,dc=example,dc=com"
    modlist = [(ldap.MOD_REPLACE, "mail", [b"new@example.com"])]
    conn.modify_s(dn, modlist)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow when user input reaches modify_s DN")
	}
}

func TestPython_LDAP_DeleteS_TaintedDN(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.form.get("username")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    conn.simple_bind_s(dn, "password")
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.form -> simple_bind_s()")
	}
}

func TestPython_LDAP_BindS(t *testing.T) {
	code := `
import ldap
from flask import request

def create_user():
    username = request.args.get("user")
    l = ldap.initialize("ldap://dir.example.com")
    dn = "uid=" + username + ",ou=people,dc=example,dc=com"
    modlist = [("objectClass", [b"inetOrgPerson"])]
    l.add_s(dn, modlist)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.args -> ldap.add_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_DeleteS(t *testing.T) {
	code := `
import ldap
from flask import request

def delete_user():
    username = request.args.get("user")
    l = ldap.initialize("ldap://dir.example.com")
    dn = "uid=" + username + ",ou=people,dc=example,dc=com"
    l.delete_s(dn)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.args -> ldap.delete_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_CompareS_TaintedValue(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    who = request.args.get("who")
    conn = ldap.initialize("ldap://example.com")
    conn.bind_s(who, "cred", ldap.AUTH_SIMPLE)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> bind_s()")
	}
}

func TestPython_LDAP_SaslInteractiveBindS(t *testing.T) {
	code := `
import ldap
import ldap.sasl
from flask import request

def handler():
    who = request.args.get("who")
    auth = ldap.sasl.sasl({}, "GSSAPI")
    conn = ldap.initialize("ldap://example.com")
    conn.sasl_interactive_bind_s(who, auth)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> sasl_interactive_bind_s()")
	}
}

func TestPython_LDAP_ModifyS(t *testing.T) {
	code := `
import ldap
from flask import request

def update_attr():
    username = request.args.get("user")
    l = ldap.initialize("ldap://dir.example.com")
    dn = "uid=" + username + ",ou=people,dc=example,dc=com"
    modlist = [(ldap.MOD_REPLACE, "mail", b"new@example.com")]
    l.modify_s(dn, modlist)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.args -> ldap.modify_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_ModifyExtS(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.args.get("user")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    mods = [(ldap.MOD_REPLACE, "mail", b"new@example.com")]
    conn.modify_ext_s(dn, mods)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> modify_ext_s()")
	}
}

func TestPython_LDAP_AddS_Tainted(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.args.get("user")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    attrs = [("objectClass", [b"inetOrgPerson"])]
    conn.add_s(dn, attrs)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> add_s()")
	}
}

func TestPython_LDAP_DeleteS_Tainted(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.args.get("user")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    conn.delete_s(dn)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> delete_s()")
	}
}

func TestPython_LDAP_CompareS(t *testing.T) {
	code := `
import ldap
from flask import request

def compare_attr():
    username = request.args.get("user")
    l = ldap.initialize("ldap://dir.example.com")
    dn = "uid=" + username + ",ou=people,dc=example,dc=com"
    l.compare_s(dn, "mail", b"user@example.com")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.args -> ldap.compare_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_ModrdnS_TaintedRDN(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.args.get("user")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    conn.compare_s(dn, "mail", b"user@example.com")
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> compare_s()")
	}
}

func TestPython_LDAP_RenameS(t *testing.T) {
	code := `
import ldap
from flask import request

def rename_user():
    old_uid = request.args.get("old")
    new_uid = request.args.get("new")
    l = ldap.initialize("ldap://dir.example.com")
    dn = "uid=" + old_uid + ",ou=people,dc=example,dc=com"
    newrdn = "uid=" + new_uid
    l.rename_s(dn, newrdn)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.args -> ldap.rename_s()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP3_ModifyDN(t *testing.T) {
	code := `
from ldap3 import Server, Connection
from flask import request

def move_user():
    user = request.args.get("user")
    server = Server("ldap.example.com")
    connection = Connection(server, user="cn=admin,dc=example,dc=com", password="s3cret")
    connection.bind()
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    connection.modify_dn(dn, "uid=relocated")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for request.args -> ldap3 Connection.modify_dn()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_LDAP_ModrdnS_TaintedNewRDN(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    new_cn = request.args.get("new_cn")
    conn = ldap.initialize("ldap://example.com")
    new_rdn = "cn=" + new_cn
    conn.modrdn_s("uid=alice,ou=users,dc=example,dc=com", new_rdn)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP flow when user input reaches modrdn_s new_rdn")
	}
}

// --- Sanitized variants ---

func TestPython_LDAP_AddS_Sanitized(t *testing.T) {
	code := `
import ldap
import ldap.dn
from flask import request

def handler():
    user_cn = request.args.get("cn")
    safe_cn = ldap.dn.escape_dn_chars(user_cn)
    conn = ldap.initialize("ldap://example.com")
    dn = "cn=" + safe_cn + ",ou=users,dc=example,dc=com"
    modlist = [("objectClass", [b"inetOrgPerson"])]
    conn.add_s(dn, modlist)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP flow when escape_dn_chars sanitizes the DN")
		}
	}
}

func TestPython_LDAP_RenameS_Tainted(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    old_user = request.args.get("old")
    dn = "uid=" + old_user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    conn.rename_s(dn, "uid=newname")
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> rename_s()")
	}
}

func TestPython_LDAP_PasswdS(t *testing.T) {
	code := `
import ldap
from flask import request

def handler():
    user = request.args.get("user")
    dn = "uid=" + user + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    conn.passwd_s(dn, "oldpw", "newpw")
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for request.args -> passwd_s()")
	}
}

// =========================================================================
// Safe cases — escape_filter_chars and escape_dn_chars should sanitize
// =========================================================================

func TestPython_LDAP_SearchExtS_Sanitized(t *testing.T) {
	code := `
import ldap
import ldap.filter
from flask import request

def handler():
    username = request.args.get("u")
    safe_user = ldap.filter.escape_filter_chars(username)
    conn = ldap.initialize("ldap://example.com")
    filter_str = "(uid=" + safe_user + ")"
    conn.search_ext_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP flow when escape_filter_chars sanitizes the filter")
		}
	}
}

func TestPython_LDAP_ModifyS_Sanitized(t *testing.T) {
	code := `
import ldap
import ldap.dn
from flask import request

def handler():
    user = request.args.get("user")
    safe = ldap.dn.escape_dn_chars(user)
    dn = "uid=" + safe + ",ou=people,dc=example,dc=com"
    conn = ldap.initialize("ldap://example.com")
    mods = [(ldap.MOD_REPLACE, "mail", b"new@example.com")]
    conn.modify_s(dn, mods)
`
	flows := Analyze(code, "/app/ldap_handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Errorf("unexpected LDAP flow after escape_dn_chars: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
