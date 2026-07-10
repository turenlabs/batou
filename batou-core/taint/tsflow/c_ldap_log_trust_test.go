package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ==========================================================================
// C LDAP injection tests (CWE-90)
// ==========================================================================

func TestC_LDAPModify_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void modify_entry(LDAP *ld) {
    char *dn = getenv("LDAP_DN");
    LDAPMod mod;
    LDAPMod *mods[] = {&mod, NULL};
    ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
}
`
	flows := Analyze(code, "/app/ldap_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_modify_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LDAPModify_Safe(t *testing.T) {
	code := `
#include <ldap.h>

void modify_entry(LDAP *ld) {
    const char *dn = "cn=admin,dc=example,dc=com";
    LDAPMod mod;
    LDAPMod *mods[] = {&mod, NULL};
    ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
}
`
	flows := Analyze(code, "/app/ldap_handler.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected NO LDAP flow when DN is a literal")
	}
}

func TestC_LDAPAdd_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void add_entry(LDAP *ld) {
    char *dn = getenv("NEW_DN");
    LDAPMod mod;
    LDAPMod *mods[] = {&mod, NULL};
    ldap_add_ext_s(ld, dn, mods, NULL, NULL);
}
`
	flows := Analyze(code, "/app/ldap_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for fgets -> ldap_add_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LDAPDelete_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void delete_entry(LDAP *ld) {
    char *dn = getenv("DELETE_DN");
    ldap_delete_ext_s(ld, dn, NULL, NULL);
}
`
	flows := Analyze(code, "/app/ldap_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_delete_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LDAPCompare_Tainted(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void compare_entry(LDAP *ld) {
    char *dn = getenv("COMPARE_DN");
    struct berval bv = {"value", 5};
    ldap_compare_ext_s(ld, dn, "attr", &bv, NULL, NULL);
}
`
	flows := Analyze(code, "/app/ldap_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getenv -> ldap_compare_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ==========================================================================
// C log injection tests (CWE-117)
// ==========================================================================

func TestC_LogOpenlog_Tainted(t *testing.T) {
	code := `
#include <syslog.h>
#include <stdlib.h>

void init_logging() {
    char *ident = getenv("APP_NAME");
    openlog(ident, LOG_PID, LOG_DAEMON);
}
`
	flows := Analyze(code, "/app/logger.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> openlog")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LogOpenlog_Safe(t *testing.T) {
	code := `
#include <syslog.h>

void init_logging() {
    openlog("myapp", LOG_PID, LOG_DAEMON);
}
`
	flows := Analyze(code, "/app/logger.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected NO log flow when ident is a literal")
	}
}

// ==========================================================================
// C trust boundary tests (CWE-501)
// ==========================================================================

func TestC_TrustSetenv_Tainted(t *testing.T) {
	code := `
#include <stdlib.h>

void configure() {
    char *val = getenv("USER_INPUT");
    setenv("CONFIG_PATH", val, 1);
}
`
	flows := Analyze(code, "/app/config.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for fgets -> setenv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_TrustPutenv_Tainted(t *testing.T) {
	code := `
#include <stdlib.h>

void set_path() {
    char *val = getenv("USER_PATH");
    putenv(val);
}
`
	flows := Analyze(code, "/app/config.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for scanf -> putenv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_TrustSetenv_Safe(t *testing.T) {
	code := `
#include <stdlib.h>

void configure() {
    setenv("CONFIG_PATH", "/usr/local/bin", 1);
}
`
	flows := Analyze(code, "/app/config.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected NO trust boundary flow when value is a literal")
	}
}
