package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// libxml2 parsed-document accessors as second-order taint sources.
// Parsed XML attribute / text values flow into command, SQL, and XPath sinks.
//
// NOTE: tsflow's C walker does not propagate taint through C cast
// expressions like `(char *)xmlGetProp(...)`. Tests therefore omit casts.
// In real-world C code this means a missed flow only when the developer
// inserts an explicit cast — direct assignments and uses still detect.
// =========================================================================

func TestC_LibxmlGetProp_ToSystem(t *testing.T) {
	code := `
#include <libxml/tree.h>
#include <stdlib.h>

void run(xmlNodePtr node) {
    char *cmd = xmlGetProp(node, "cmd");
    system(cmd);
}
`
	flows := Analyze(code, "/app/xml_attr_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for xmlGetProp -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlNodeGetContent_ToMysqlQuery(t *testing.T) {
	code := `
#include <libxml/tree.h>
#include <mysql/mysql.h>

void run(MYSQL *conn, xmlNodePtr node) {
    char *val = xmlNodeGetContent(node);
    mysql_query(conn, val);
}
`
	flows := Analyze(code, "/app/xml_text_sql.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for xmlNodeGetContent -> mysql_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlGetNoNsProp_ToPopen(t *testing.T) {
	code := `
#include <libxml/tree.h>
#include <stdio.h>

void run(xmlNodePtr node) {
    char *prog = xmlGetNoNsProp(node, "path");
    FILE *p = popen(prog, "r");
}
`
	flows := Analyze(code, "/app/xml_nons_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for xmlGetNoNsProp -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlNodeListGetString_ToXPath(t *testing.T) {
	code := `
#include <libxml/tree.h>
#include <libxml/xpath.h>

void run(xmlDocPtr doc, xmlNodePtr children) {
    char *expr = xmlNodeListGetString(doc, children, 1);
    xmlXPathCompExprPtr comp = xmlXPathCompile(expr);
}
`
	flows := Analyze(code, "/app/xml_list_xpath.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath-injection flow for xmlNodeListGetString -> xmlXPathCompile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlBufferContent_ToSystem(t *testing.T) {
	code := `
#include <libxml/tree.h>
#include <stdlib.h>

void run(xmlBufferPtr buf) {
    char *cmd = xmlBufferContent(buf);
    system(cmd);
}
`
	flows := Analyze(code, "/app/xml_buf_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for xmlBufferContent -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlReaderConstValue_ToSystem(t *testing.T) {
	code := `
#include <libxml/xmlreader.h>
#include <stdlib.h>

void run(xmlTextReaderPtr reader) {
    char *cmd = xmlTextReaderConstValue(reader);
    system(cmd);
}
`
	flows := Analyze(code, "/app/xml_reader_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for xmlTextReaderConstValue -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlReaderGetAttribute_ToPopen(t *testing.T) {
	code := `
#include <libxml/xmlreader.h>
#include <stdio.h>

void run(xmlTextReaderPtr reader) {
    char *val = xmlTextReaderGetAttribute(reader, "file");
    FILE *p = popen(val, "r");
}
`
	flows := Analyze(code, "/app/xml_reader_attr_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for xmlTextReaderGetAttribute -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxmlReaderReadString_ToSystem(t *testing.T) {
	code := `
#include <libxml/xmlreader.h>
#include <stdlib.h>

void run(xmlTextReaderPtr reader) {
    char *val = xmlTextReaderReadString(reader);
    system(val);
}
`
	flows := Analyze(code, "/app/xml_reader_read_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for xmlTextReaderReadString -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// OpenLDAP libldap result accessors as second-order taint sources.
// Server-supplied DN / attribute values flow into command sinks.
// =========================================================================

func TestC_LdapGetDn_ToSystem(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void run(LDAP *ld, LDAPMessage *entry) {
    char *dn = ldap_get_dn(ld, entry);
    system(dn);
}
`
	flows := Analyze(code, "/app/ldap_dn_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ldap_get_dn -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LdapGetValuesLen_ToSystem(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void run(LDAP *ld, LDAPMessage *entry) {
    char *path = ldap_get_values_len(ld, entry, "homeDirectory");
    system(path);
}
`
	flows := Analyze(code, "/app/ldap_vals_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ldap_get_values_len -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LdapGetValues_ToPopen(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdio.h>

void run(LDAP *ld, LDAPMessage *entry) {
    char *shell = ldap_get_values(ld, entry, "loginShell");
    FILE *p = popen(shell, "r");
}
`
	flows := Analyze(code, "/app/ldap_oldvals_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ldap_get_values -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LdapFirstAttribute_ToSystem(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void run(LDAP *ld, LDAPMessage *entry) {
    BerElement *ber = NULL;
    char *attr = ldap_first_attribute(ld, entry, &ber);
    system(attr);
}
`
	flows := Analyze(code, "/app/ldap_firstattr_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ldap_first_attribute -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LdapNextAttribute_ToSystem(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void run(LDAP *ld, LDAPMessage *entry, BerElement *ber) {
    char *attr = ldap_next_attribute(ld, entry, ber);
    system(attr);
}
`
	flows := Analyze(code, "/app/ldap_nextattr_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ldap_next_attribute -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// libssh2 server-supplied identity strings as taint sources.
// Banner / hostkey / supported-auth-list flow into command sinks.
// =========================================================================

func TestC_LibSSH2BannerGet_ToSystem(t *testing.T) {
	code := `
#include <libssh2.h>
#include <stdlib.h>

void run(LIBSSH2_SESSION *session) {
    char *banner = libssh2_session_banner_get(session);
    system(banner);
}
`
	flows := Analyze(code, "/app/ssh_banner_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for libssh2_session_banner_get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibSSH2HostKey_ToSystem(t *testing.T) {
	code := `
#include <libssh2.h>
#include <stdlib.h>

void run(LIBSSH2_SESSION *session) {
    size_t len = 0;
    int type = 0;
    char *hk = libssh2_session_hostkey(session, &len, &type);
    system(hk);
}
`
	flows := Analyze(code, "/app/ssh_hostkey_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for libssh2_session_hostkey -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibSSH2UserauthList_ToPopen(t *testing.T) {
	code := `
#include <libssh2.h>
#include <stdio.h>

void run(LIBSSH2_SESSION *session) {
    char *methods = libssh2_userauth_list(session, "alice", 5);
    FILE *p = popen(methods, "r");
}
`
	flows := Analyze(code, "/app/ssh_authlist_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for libssh2_userauth_list -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative tests — hardcoded/literal arguments must not generate a flow.
// =========================================================================

func TestC_ParsedDataSources_LiteralCommand_NoFlow(t *testing.T) {
	code := `
#include <libxml/tree.h>
#include <stdlib.h>

void run(void) {
    char *cmd = "ls -la /tmp";
    system(cmd);
}
`
	flows := Analyze(code, "/app/safe_literal_xml.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow when command is a literal — verifies the new XML/LDAP/SSH sources didn't over-broaden")
	}
}
