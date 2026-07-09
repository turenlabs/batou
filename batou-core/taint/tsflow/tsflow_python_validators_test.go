package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// All tests use the fully-qualified-call form (e.g. django.core.validators.validate_slug)
// because the tsflow matcher requires a non-empty receiver to bind a sanitizer to its
// catalog ObjectType. The bare-call form (`from x import y; y(...)`) is a known engine
// limitation shared with the existing py.werkzeug.secure_filename entry.

// =========================================================================
// Django core validators — module-qualified form
// =========================================================================

func TestPython_Sanitizer_DjangoValidateSlug_FileRead(t *testing.T) {
	code := `
from flask import request
import django.core.validators
import os

def handler():
    name = request.args.get("name")
    clean = django.core.validators.validate_slug(name)
    info = os.stat(clean)
    return str(info)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("django.core.validators.validate_slug should neutralize FileRead taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPython_Sanitizer_DjangoValidateSlug_NegativeControl(t *testing.T) {
	code := `
from flask import request
import os

def handler():
    name = request.args.get("name")
    info = os.stat(name)
    return str(info)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow when no validator is called (negative control)")
	}
}

func TestPython_Sanitizer_DjangoValidateUnicodeSlug_URLFetch(t *testing.T) {
	code := `
from flask import request
import django.core.validators
import requests

def handler():
    slug = request.args.get("slug")
    clean = django.core.validators.validate_unicode_slug(slug)
    return requests.get(clean)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("django.core.validators.validate_unicode_slug should neutralize URLFetch taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPython_Sanitizer_DjangoValidateIPv6_URLFetch(t *testing.T) {
	code := `
from flask import request
import django.core.validators
import requests

def handler():
    host = request.args.get("host")
    clean = django.core.validators.validate_ipv6_address(host)
    return requests.get(clean)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("django.core.validators.validate_ipv6_address should neutralize URLFetch taint flow")
	}
}

func TestPython_Sanitizer_DjangoValidateEmail_Header(t *testing.T) {
	code := `
from flask import request, make_response
import django.core.validators

def handler():
    addr = request.args.get("addr")
    clean = django.core.validators.validate_email(addr)
    resp = make_response("hi")
    resp.set_cookie(clean, "v")
    return resp
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("django.core.validators.validate_email should neutralize Header taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// =========================================================================
// Werkzeug security
// =========================================================================

func TestPython_Sanitizer_WerkzeugSafeJoin_FileWrite_Inline(t *testing.T) {
	code := `
from flask import request
import werkzeug.security

def handler():
    name = request.args.get("name")
    f = open(werkzeug.security.safe_join("/var/uploads", name), "w")
    f.write("data")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("werkzeug.security.safe_join (inline) should neutralize FileWrite taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPython_Sanitizer_WerkzeugSafeJoin_FileRead_Inline(t *testing.T) {
	code := `
from flask import request
import werkzeug.security
import os

def handler():
    name = request.args.get("name")
    info = os.stat(werkzeug.security.safe_join("/data", name))
    return str(info)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("werkzeug.security.safe_join (inline) should neutralize FileRead taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPython_Sanitizer_WerkzeugSafeJoin_NegativeControl(t *testing.T) {
	code := `
from flask import request

def handler():
    name = request.args.get("name")
    f = open(name, "w")
    f.write("data")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow when safe_join is not used (negative control)")
	}
}

// =========================================================================
// email-validator (PyPI)
// =========================================================================

func TestPython_Sanitizer_EmailValidator_Header(t *testing.T) {
	code := `
from flask import request, make_response
import email_validator

def handler():
    addr = request.args.get("addr")
    info = email_validator.validate_email(addr)
    resp = make_response("hi")
    resp.set_cookie(info, "v")
    return resp
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("email_validator.validate_email should neutralize Header taint flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPython_Sanitizer_EmailValidator_NegativeControl(t *testing.T) {
	code := `
from flask import request, make_response

def handler():
    addr = request.args.get("addr")
    resp = make_response("hi")
    resp.set_cookie(addr, "v")
    return resp
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected Header flow when no validator is called (negative control)")
	}
}
