package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ OpenLDAP injection tests (CWE-90)
//
// OpenLDAP exposes a C API that is routinely called from C++. These tests
// exercise the write/auth-side operations — modify, add, delete, compare,
// rename, modrdn, simple_bind, sasl_bind, bind — on .cpp files to confirm
// the catalog's C++-scoped entries fire.
// =========================================================================

func TestCPP_LDAPModify_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void modify_entry(LDAP *ld) {
    const char *dn = std::getenv("LDAP_DN");
    LDAPMod mod;
    LDAPMod *mods[] = {&mod, nullptr};
    ldap_modify_ext_s(ld, dn, mods, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_modify_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPModify_Safe(t *testing.T) {
	code := `
#include <ldap.h>

void modify_entry(LDAP *ld) {
    const char *dn = "cn=admin,dc=example,dc=com";
    LDAPMod mod;
    LDAPMod *mods[] = {&mod, nullptr};
    ldap_modify_ext_s(ld, dn, mods, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected NO LDAP flow when DN is a literal")
	}
}

func TestCPP_LDAPAdd_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void add_entry(LDAP *ld) {
    const char *dn = std::getenv("NEW_DN");
    LDAPMod mod;
    LDAPMod *mods[] = {&mod, nullptr};
    ldap_add_ext_s(ld, dn, mods, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_add_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPDelete_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void remove_entry(LDAP *ld) {
    const char *dn = std::getenv("LDAP_DN");
    ldap_delete_ext_s(ld, dn, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_delete_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPCompare_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void compare_entry(LDAP *ld) {
    const char *dn = std::getenv("LDAP_DN");
    struct berval bvalue = {0, nullptr};
    ldap_compare_ext_s(ld, dn, "uid", &bvalue, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_compare_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPRename_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void move_entry(LDAP *ld) {
    const char *dn = std::getenv("LDAP_DN");
    ldap_rename_s(ld, dn, "cn=new", nullptr, 1, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_rename_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPModRDN_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void legacy_rename(LDAP *ld) {
    const char *dn = std::getenv("LDAP_DN");
    ldap_modrdn2_s(ld, dn, "cn=new", 1);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_modrdn2_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPSimpleBind_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void authenticate(LDAP *ld) {
    const char *who = std::getenv("LDAP_USER_DN");
    ldap_simple_bind_s(ld, who, "password");
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_simple_bind_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPSaslBind_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void authenticate(LDAP *ld) {
    const char *dn = std::getenv("LDAP_USER_DN");
    struct berval cred = {0, nullptr};
    ldap_sasl_bind_s(ld, dn, "PLAIN", &cred, nullptr, nullptr, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_sasl_bind_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAPBind_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void legacy_authenticate(LDAP *ld) {
    const char *who = std::getenv("LDAP_USER_DN");
    ldap_bind_s(ld, who, "password", LDAP_AUTH_SIMPLE);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_bind_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LDAP_SanitizedByBv2Escaped(t *testing.T) {
	code := `
#include <ldap.h>
#include <cstdlib>

void search_escaped(LDAP *ld) {
    const char *raw = std::getenv("LDAP_FILTER_VALUE");
    struct berval in = {0, (char *)raw};
    struct berval out;
    ldap_bv2escaped_filter_value_s(&in, &out);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, out.bv_val, nullptr, 0, nullptr, nullptr, nullptr, 0, nullptr);
}
`
	flows := Analyze(code, "/app/ldap_handler.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Errorf("expected NO LDAP flow when value is escaped with ldap_bv2escaped_filter_value_s (got flow from %s)", f.Source.Category)
		}
	}
}
