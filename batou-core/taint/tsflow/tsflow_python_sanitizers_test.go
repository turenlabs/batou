package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Header injection sanitizers ---

func TestPython_Header_Unsanitized(t *testing.T) {
	code := `
from flask import request

def handler():
    value = request.args.get("header_val")
    self.set_header("X-Custom", value)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow when user input goes directly to set_header")
	}
}

func TestPython_Header_Sanitized_EmailFormatAddr(t *testing.T) {
	code := `
import email.utils
from flask import request

def handler():
    name = request.args.get("name")
    safe = email.utils.formataddr((name, "user@example.com"))
    send_header("From", safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow when email.utils.formataddr is used")
		}
	}
}

// --- LDAP injection sanitizers ---

func TestPython_LDAP_Unsanitized(t *testing.T) {
	code := `
from flask import request
from ldap3 import Connection

def handler():
    username = request.args.get("user")
    filter_str = "(uid=" + username + ")"
    conn.search("dc=example,dc=com", filter_str)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow when user input goes directly to conn.search")
	}
}

func TestPython_LDAP_Sanitized_EscapeFilter(t *testing.T) {
	code := `
from flask import request
import ldap
import ldap.filter

def handler():
    username = request.args.get("user")
    safe = ldap.filter.escape_filter_chars(username)
    conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + safe + ")")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP flow when ldap.filter.escape_filter_chars is used")
		}
	}
}

func TestPython_LDAP_Sanitized_EscapeDN(t *testing.T) {
	code := `
from flask import request
import ldap.dn

def handler():
    username = request.args.get("user")
    safe = ldap.dn.escape_dn_chars(username)
    conn.search_s("ou=" + safe + ",dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP flow when ldap.dn.escape_dn_chars is used")
		}
	}
}

func TestPython_LDAP_Sanitized_Ldap3Escape(t *testing.T) {
	code := `
from flask import request
from ldap3.utils.conv import escape_filter_chars

def handler():
    username = request.args.get("user")
    safe = ldap3.utils.conv.escape_filter_chars(username)
    conn.search("dc=example,dc=com", "(uid=" + safe + ")")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP flow when ldap3 escape is used")
		}
	}
}

// --- Log injection sanitizers ---

func TestPython_Log_Unsanitized(t *testing.T) {
	code := `
import logging
from flask import request

def handler():
    username = request.args.get("user")
    logging.info("Login attempt: " + username)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow when user input goes directly to logging.info")
	}
}

func TestPython_Log_Sanitized_Structlog(t *testing.T) {
	code := `
import structlog
from flask import request

def handler():
    username = request.args.get("user")
    logger = structlog.get_logger()
    logger.info("login_attempt", user=username)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when structlog structured logging is used")
		}
	}
}

func TestPython_Log_Sanitized_JsonDumps(t *testing.T) {
	code := `
import json
import logging
from flask import request

def handler():
    username = request.args.get("user")
    safe = json.dumps(username)
    logging.info("Login attempt: " + safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when json.dumps sanitizes the input")
		}
	}
}

// --- Trust boundary sanitizers ---

func TestPython_TrustBoundary_Unsanitized(t *testing.T) {
	code := `
from flask import request, session

def handler():
    role = request.args.get("role")
    session.update({"user_role": role})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow when user input goes directly to session.update")
	}
}

func TestPython_TrustBoundary_Sanitized_CleanedData(t *testing.T) {
	code := `
from flask import request, session

def handler():
    role = request.args.get("role")
    safe = form.cleaned_data["role"]
    session["user_role"] = safe
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when cleaned_data is used")
		}
	}
}

func TestPython_TrustBoundary_Sanitized_Itsdangerous(t *testing.T) {
	code := `
from flask import request, session
import itsdangerous

def handler():
    token = request.args.get("token")
    s = itsdangerous.URLSafeSerializer("secret")
    data = s.loads(token)
    session["data"] = data
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when itsdangerous serializer validates input")
		}
	}
}

