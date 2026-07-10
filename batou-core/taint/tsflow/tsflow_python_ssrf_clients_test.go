package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python SSRF — non-HTTP network clients (cov/python coverage adds):
//   ftplib.FTP / FTP.connect, xmlrpc.client.ServerProxy, telnetlib.Telnet,
//   smtplib.SMTP / imaplib.IMAP4 / poplib.POP3 host, and jinja2
//   Environment.get_template template-name traversal.
//
// Each detection class has a TP case that must fire and a near-miss/safe
// case that must stay clean (constant host / dict.get collision / constant
// template name), proving the receiver-typed/module-anchored sinks do not
// collide with everyday code.
// =========================================================================

// --- ftplib.FTP constructor (CWE-918 / CWE-319) ---

func TestPython_SSRF_FtplibConstructor(t *testing.T) {
	code := `
from flask import request
import ftplib

def handler():
    host = request.args.get("server")
    ftp = ftplib.FTP(host)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.args -> ftplib.FTP()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s]", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestPython_SSRF_FtplibTLSConstructor(t *testing.T) {
	code := `
from flask import request
import ftplib

def handler():
    host = request.args.get("server")
    ftp = ftplib.FTP_TLS(host)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.args -> ftplib.FTP_TLS()")
	}
}

func TestPython_SSRF_FtplibConnect(t *testing.T) {
	code := `
from flask import request
import ftplib

def handler():
    host = request.args.get("server")
    ftp = ftplib.FTP()
    ftp.connect(host)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.args -> ftp.connect()")
	}
}

func TestPython_SSRF_FtplibConstantHost_Safe(t *testing.T) {
	// Constant host — no tainted argument, must NOT produce a flow.
	code := `
from flask import request
import ftplib

def handler():
    _ = request.args.get("ignored")
    ftp = ftplib.FTP("ftp.internal.example.com")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.ftplib.ftp.constructor" {
			t.Errorf("unexpected ftplib SSRF flow on a constant host: %s", f.Sink.ID)
		}
	}
}

// --- xmlrpc.client.ServerProxy (CWE-918) ---

func TestPython_SSRF_XmlrpcServerProxy(t *testing.T) {
	code := `
from flask import request
import xmlrpc.client

def handler():
    endpoint = request.args.get("endpoint")
    proxy = xmlrpc.client.ServerProxy(endpoint)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.args -> xmlrpc.client.ServerProxy()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s] %s", f.Source.Category, f.Sink.Category, f.Sink.CWEID, f.Sink.ID)
		}
	}
}

func TestPython_SSRF_XmlrpclibServerProxy(t *testing.T) {
	code := `
from flask import request
import xmlrpclib

def handler():
    endpoint = request.args.get("endpoint")
    proxy = xmlrpclib.ServerProxy(endpoint)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.args -> xmlrpclib.ServerProxy()")
	}
}

// --- telnetlib.Telnet (CWE-918 / CWE-319) ---

func TestPython_SSRF_TelnetlibTelnet(t *testing.T) {
	code := `
from flask import request
import telnetlib

def handler():
    host = request.form["host"]
    tn = telnetlib.Telnet(host)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.form -> telnetlib.Telnet()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s] %s", f.Source.Category, f.Sink.Category, f.Sink.CWEID, f.Sink.ID)
		}
	}
}

func TestPython_SSRF_TelnetConstantHost_Safe(t *testing.T) {
	code := `
from flask import request
import telnetlib

def handler():
    _ = request.args.get("ignored")
    tn = telnetlib.Telnet("10.0.0.5")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.telnetlib.telnet" {
			t.Errorf("unexpected telnet SSRF flow on a constant host: %s", f.Sink.ID)
		}
	}
}

// --- smtplib.SMTP / imaplib.IMAP4 / poplib.POP3 host (CWE-918) ---

func TestPython_SSRF_SmtplibHost(t *testing.T) {
	code := `
from flask import request
import smtplib

def handler():
    relay = request.values.get("relay")
    conn = smtplib.SMTP(relay)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.values -> smtplib.SMTP()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s] %s", f.Source.Category, f.Sink.Category, f.Sink.CWEID, f.Sink.ID)
		}
	}
}

func TestPython_SSRF_ImaplibHost(t *testing.T) {
	code := `
from flask import request
import imaplib

def handler():
    host = request.args.get("imap")
    conn = imaplib.IMAP4_SSL(host)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Error("expected SSRF flow for request.args -> imaplib.IMAP4_SSL()")
	}
}

// --- jinja2 Environment.get_template template-name traversal (CWE-22) ---

func TestPython_Traversal_JinjaGetTemplate(t *testing.T) {
	code := `
from flask import request
import jinja2

def handler(env):
    name = request.args.get("page")
    tmpl = env.get_template(name)
    return tmpl.render()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-22") {
		t.Error("expected template-path-traversal flow for request.args -> env.get_template()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s] %s", f.Source.Category, f.Sink.Category, f.Sink.CWEID, f.Sink.ID)
		}
	}
}

func TestPython_Traversal_JinjaSelectTemplate(t *testing.T) {
	code := `
from flask import request
import jinja2

def handler(env):
    name = request.args.get("page")
    tmpl = env.select_template([name, "default.html"])
    return tmpl.render()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-22") {
		t.Error("expected template-path-traversal flow for request.args -> env.select_template()")
	}
}

func TestPython_Traversal_JinjaConstantName_Safe(t *testing.T) {
	// Constant template name — must NOT fire (the common, safe shape).
	code := `
from flask import request
import jinja2

def handler(env):
    _ = request.args.get("ignored")
    tmpl = env.get_template("index.html")
    return tmpl.render()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.jinja2.environment.get_template" {
			t.Errorf("unexpected jinja get_template flow on a constant template name: %s", f.Sink.ID)
		}
	}
}

// --- Near-miss collision guard: dict.get must NOT be treated as a sink. ---

func TestPython_SSRF_DictGet_NoCollision(t *testing.T) {
	// A plain dict `.get(...)` lookup on a tainted value must not produce
	// any url_fetch flow — this is the exact bare-name collision the
	// receiver-typed sinks are designed to avoid.
	code := `
from flask import request

def handler():
    cache = {}
    key = request.args.get("k")
    value = cache.get(key)
    return value
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("dict.get() incorrectly flagged as an SSRF sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s [%s] %s", f.Source.Category, f.Sink.Category, f.Sink.CWEID, f.Sink.ID)
		}
	}
}
