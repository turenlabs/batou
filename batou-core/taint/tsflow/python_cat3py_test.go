// PR-CAT3py: Python catalog P2 — same-file walker tests that pin the
// behaviour of the newly-registered SnkTrustBoundary sanitizers.
//
// Motivating cross-file FPs (Sentry production scan):
//
//   - sudo/utils.py:50  -> request.session[k] = get_random_string(12)
//   - auth.py:165       -> request.session["_next"] = next_url   # validated by is_valid_redirect
//   - auth.py:434       -> request.session["activeorg"] = org_slug
//
// The cross-file scanner has its own line-level FP filter (see
// scanPythonBodyForSinks in graph/crossfile_walk_python.go). The
// catalog entries tested here keep the same-file walker honest: when
// the assignment LHS is a *call sink* like `session.update(...)`,
// recognising the RHS sanitizer should clear the SnkTrustBoundary
// tag from the flow. The corresponding subscript-assignment shape
// (`session["k"] = sanitizer(...)`) is covered by the cross-file
// regression tests in graph/crossfile_walk_python_test.go.

package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs so the matcher loads sources,
	// sinks, and sanitizers for Python.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Unsanitised baseline — confirms the same-file walker still
// recognises a trust-boundary sink when the value is plainly tainted.
// All sanitised tests below pair against this baseline.
func TestPython_CAT3py_TrustBoundary_Unsanitized_Baseline(t *testing.T) {
	code := `
from flask import request, session

def handler():
    role = request.args.get("role")
    session.update({"user_role": role})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("baseline: tainted request value flowing into session.update should produce SnkTrustBoundary")
	}
}

// --- secrets.token_* ------------------------------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_SecretsTokenHex(t *testing.T) {
	code := `
from flask import session
import secrets

def handler():
    token = secrets.token_hex(32)
    session.update({"csrf_token": token})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("secrets.token_hex() should neutralize SnkTrustBoundary (server-generated)")
		}
	}
}

func TestPython_CAT3py_TrustBoundary_Sanitized_SecretsTokenBytes(t *testing.T) {
	code := `
from flask import session
import secrets

def handler():
    token = secrets.token_bytes(16)
    session.update({"raw": token})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("secrets.token_bytes() should neutralize SnkTrustBoundary")
		}
	}
}

func TestPython_CAT3py_TrustBoundary_Sanitized_SecretsTokenUrlsafe(t *testing.T) {
	code := `
from flask import session
import secrets

def handler():
    token = secrets.token_urlsafe(24)
    session.update({"link_token": token})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("secrets.token_urlsafe() should neutralize SnkTrustBoundary")
		}
	}
}

// --- uuid.uuid1/uuid4 -----------------------------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_UuidUuid4(t *testing.T) {
	code := `
from flask import session
import uuid

def handler():
    sid = uuid.uuid4()
    session.update({"sid": sid})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("uuid.uuid4() should neutralize SnkTrustBoundary")
		}
	}
}

func TestPython_CAT3py_TrustBoundary_Sanitized_UuidUuid1(t *testing.T) {
	code := `
from flask import session
import uuid

def handler():
    sid = uuid.uuid1()
    session.update({"sid": sid})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("uuid.uuid1() should neutralize SnkTrustBoundary")
		}
	}
}

// --- os.urandom -----------------------------------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_OsUrandom(t *testing.T) {
	code := `
from flask import session
import os

def handler():
    nonce = os.urandom(16)
    session.update({"nonce": nonce})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("os.urandom() should neutralize SnkTrustBoundary")
		}
	}
}

// --- hashlib.<algo>(...).hexdigest() --------------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_HashlibHexdigest(t *testing.T) {
	code := `
from flask import session
import hashlib

def handler():
    digest = hashlib.sha256(b"server-secret").hexdigest()
    session.update({"fingerprint": digest})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("hashlib.sha256(...).hexdigest() should neutralize SnkTrustBoundary")
		}
	}
}

// --- jwt.encode -----------------------------------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_JwtEncode(t *testing.T) {
	code := `
from flask import session
import jwt

def handler():
    token = jwt.encode({"sub": 123}, "secret", algorithm="HS256")
    session.update({"jwt": token})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("jwt.encode() should neutralize SnkTrustBoundary (server-signed)")
		}
	}
}

// --- django.core.signing --------------------------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_SigningDumps(t *testing.T) {
	code := `
from flask import session
from django.core import signing

def handler():
    signed = signing.dumps({"k": "v"})
    session.update({"signed": signed})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("signing.dumps() should neutralize SnkTrustBoundary (HMAC-signed)")
		}
	}
}

// --- django.utils.crypto.get_random_string --------------------------------

func TestPython_CAT3py_TrustBoundary_Sanitized_GetRandomString(t *testing.T) {
	code := `
from flask import session
from django.utils.crypto import get_random_string

def handler():
    token = get_random_string(12)
    session.update({"token": token})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("django.utils.crypto.get_random_string() should neutralize SnkTrustBoundary")
		}
	}
}

// --- is_valid_redirect / url_has_allowed_host_and_scheme ------------------
//
// These are the validated-next-URL sanitizers. When the request value is
// gated by an allowlist check, the resulting value is safe to store in
// the session.

func TestPython_CAT3py_TrustBoundary_Sanitized_IsValidRedirect(t *testing.T) {
	code := `
from flask import request, session
from sentry.utils.auth import is_valid_redirect

def handler():
    next_url = request.args.get("next")
    validated = is_valid_redirect(next_url, allowed_hosts={"example.com"})
    session.update({"_next": validated})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("is_valid_redirect() should neutralize SnkTrustBoundary on next_url")
		}
	}
}

func TestPython_CAT3py_TrustBoundary_Sanitized_UrlHasAllowedHostAndScheme(t *testing.T) {
	code := `
from flask import request, session
from django.utils.http import url_has_allowed_host_and_scheme

def handler():
    next_url = request.args.get("next")
    safe = url_has_allowed_host_and_scheme(next_url, allowed_hosts={"example.com"})
    session.update({"_next": safe})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("url_has_allowed_host_and_scheme() should neutralize SnkTrustBoundary")
		}
	}
}
