package tsflow

// Tests for PR-CAT2py: broader Python catalog tightening on top of the
// PR-CATpy receiver-scoping fixes. Each test pins a specific Sentry-found
// false-positive shape and a matching true-positive to make sure the
// catalog narrowing didn't accidentally remove real coverage.
//
// Context: a triage of 80 production cross-file findings on the Sentry
// codebase attributed 78 of them to method-name suffix collisions
// (Sentry-internal `.get()`, `.execute()`, `.loads()`, bare `Response()`
// flagged against `requests.get`, `cursor.execute`,
// `xmlrpc.client.loads`, `aiohttp.web.Response`). The fixes here
// (a) anchor receiver-required HTTP-client sinks to their module names,
// (b) narrow the bare `.execute(` regex to common DB-client receivers,
// (c) split xmlrpc.client.loads off from a bare-`.loads(` catalog entry,
// (d) gate aiohttp web.Response on a `web` receiver to stop matching
//     DRF `Response(data)`, and (e) sanitise Django auto-escaped
//     template rendering as a SnkHTMLOutput sanitiser.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// P0.1 — `.get(...)` SSRF false positives
// ---------------------------------------------------------------------------

// TestPython_DictGet_NotSSRF verifies that `params.get("k")` is NOT
// treated as `requests.get(url)`. This is the dominant Sentry FP shape
// (request.GET.get / session.get / params.get / response_json.get).
func TestPython_DictGet_NotSSRF(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"params.get",
			`
from flask import request

def handler():
    params = request.args
    return params.get("k")
`,
		},
		{"request.GET.get (Django)",
			`
def handler(request):
    return request.GET.get("section")
`,
		},
		{"request.session.get",
			`
def handler(request):
    return request.session.get("user_id")
`,
		},
		{"response_json.get",
			`
from flask import request

def handler():
    raw = request.args.get("payload")
    response_json = {"k": raw}
    return response_json.get("k")
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/handler.py", rules.LangPython)
			if hasTaintFlow(flows, taint.SnkURLFetch) {
				t.Errorf("dict-style .get(...) must NOT be classified as SnkURLFetch; got flows=%+v", flows)
			}
		})
	}
}

// TestPython_RequestsGet_StillSSRF preserves the genuine requests.get
// true positive — the catalog must only have *narrowed* the receiver,
// not removed the sink entirely.
func TestPython_RequestsGet_StillSSRF(t *testing.T) {
	code := `
import requests
from flask import request

def handler():
    url = request.args.get("url")
    return requests.get(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Fatalf("requests.get(tainted_url) must still fire SnkURLFetch; got %d flows: %+v", len(flows), flows)
	}
}

// TestPython_RequestsPost_StillSSRF preserves the requests.post true
// positive (also receiver-scoped to the `requests` module).
func TestPython_RequestsPost_StillSSRF(t *testing.T) {
	code := `
import requests
from flask import request

def handler():
    url = request.args.get("url")
    return requests.post(url, json={"k": "v"})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("requests.post(tainted_url) must still fire SnkURLFetch; got flows=%+v", flows)
	}
}

// TestPython_UrlopenStillSSRF preserves urlopen on the proper module
// receiver (`urllib.request.urlopen`).
func TestPython_UrlopenStillSSRF(t *testing.T) {
	code := `
import urllib.request
from flask import request

def handler():
    url = request.args.get("u")
    return urllib.request.urlopen(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("urllib.request.urlopen(tainted_url) must still fire SnkURLFetch; got flows=%+v", flows)
	}
}

// ---------------------------------------------------------------------------
// P0.2 — `.execute(...)` SQL false positive on non-DB receivers
// ---------------------------------------------------------------------------

// TestPython_RedisPipelineExecute_NotSQL reproduces the Sentry monitor
// manager FP — `pipeline.execute()` on a Redis pipeline must not fire
// SnkSQLQuery (its receiver isn't a DB cursor/connection/session).
//
// The cross-file walker is what's affected most here (its regex Pattern
// is what flagged the bare `\.execute\(` in interproc flows). The
// same-file tsflow matcher already rejected this via the cursor
// ObjectType heuristic, so a direct flow-based assertion is the best we
// can do at this layer — verify that a tainted value passed into
// `pipeline.execute()` doesn't surface as a SQL flow.
func TestPython_RedisPipelineExecute_NotSQL(t *testing.T) {
	code := `
from flask import request

def handler(redis):
    pipeline = redis.pipeline()
    entity = request.args.get("entity")
    pipeline.zadd("set:" + entity, {})
    pipeline.delete("err:" + entity)
    pipeline.execute()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("Redis pipeline.execute() must NOT be classified as SnkSQLQuery; got flows=%+v", flows)
	}
}

// TestPython_CursorExecute_StillSQL preserves the genuine cursor.execute
// true positive.
func TestPython_CursorExecute_StillSQL(t *testing.T) {
	code := `
from flask import request

def handler(conn):
    cursor = conn.cursor()
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("cursor.execute(tainted_sql) must still fire SnkSQLQuery; got flows=%+v", flows)
	}
}

// ---------------------------------------------------------------------------
// P0.3 — `.loads(...)` deserialize false positive (orjson/json vs xmlrpc)
// ---------------------------------------------------------------------------

// TestPython_OrjsonLoads_NotXMLRPCDeserialize is the Sentry FP shape —
// `orjson.loads(raw)` must not be classified as a SnkDeserialize via
// the previously module-unconstrained xmlrpc.client.loads entry.
// JSON parsing (orjson, json, ujson, etc.) is a safe operation.
func TestPython_OrjsonLoads_NotXMLRPCDeserialize(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"orjson.loads",
			`
import orjson
from flask import request

def handler():
    raw = request.get_data()
    return orjson.loads(raw)
`,
		},
		{"json.loads",
			`
import json
from flask import request

def handler():
    raw = request.get_data()
    return json.loads(raw)
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/handler.py", rules.LangPython)
			if hasTaintFlow(flows, taint.SnkDeserialize) {
				t.Errorf("safe-JSON .loads(...) must NOT be classified as SnkDeserialize; got flows=%+v", flows)
			}
		})
	}
}

// TestPython_XmlrpcClientLoads_StillDeserialize preserves the genuine
// xmlrpc.client.loads true positive — it's still a SnkDeserialize sink,
// just receiver-pinned to the xmlrpc module to stop the .loads bare-name
// collision.
func TestPython_XmlrpcClientLoads_StillDeserialize(t *testing.T) {
	code := `
import xmlrpc.client
from flask import request

def handler():
    raw = request.get_data()
    return xmlrpc.client.loads(raw)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Errorf("xmlrpc.client.loads(tainted) must still fire SnkDeserialize; got flows=%+v", flows)
	}
}

// ---------------------------------------------------------------------------
// P1.4 — DRF Response(...) ≠ aiohttp web.Response(...)
// ---------------------------------------------------------------------------

// TestPython_DRFResponse_NotHTMLOutput verifies that DRF's bare
// `Response(data)` is not classified as a SnkHTMLOutput sink. DRF
// returns JSON by default — the catalog now requires the aiohttp `web`
// receiver, not the bare class.
func TestPython_DRFResponse_NotHTMLOutput(t *testing.T) {
	code := `
from rest_framework.response import Response
from flask import request

def handler():
    data = {"value": request.args.get("v")}
    return Response(data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("DRF Response(data) must NOT fire SnkHTMLOutput; got flows=%+v", flows)
	}
}

// TestPython_AiohttpWebResponse_StillHTMLOutput preserves the aiohttp
// true positive — `web.Response(body=tainted)` is still a sink.
func TestPython_AiohttpWebResponse_StillHTMLOutput(t *testing.T) {
	code := `
from aiohttp import web
from flask import request

async def handler():
    body = request.args.get("body")
    return web.Response(text=body, content_type="text/html")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("aiohttp web.Response(tainted) must still fire SnkHTMLOutput; got flows=%+v", flows)
	}
}

// ---------------------------------------------------------------------------
// P1.5 — render_to_string / render_to_response: auto-escaped sanitizer
// ---------------------------------------------------------------------------

// TestPython_RenderToString_AutoEscaped verifies that
// `render_to_string(name, context)` neutralises a SnkHTMLOutput flow.
// Django templates auto-escape by default; the catalog removed the
// (over-aggressive) py.django.render_to_string sink and added the
// matching SnkHTMLOutput sanitizer here.
//
// We assert the *combined* shape: tainted context flowing through
// render_to_string then into an aiohttp web.Response must NOT fire a
// HTML-output flow. Without the sanitizer the chain previously fired
// because the rendered output was still considered taintful.
func TestPython_RenderToString_AutoEscaped(t *testing.T) {
	code := `
from aiohttp import web
from django.template.loader import render_to_string
from flask import request

def handler():
    user = request.args.get("user")
    body = render_to_string("page.html", {"user": user})
    return web.Response(text=body)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("render_to_string(..., ctx) auto-escapes — must NOT fire SnkHTMLOutput; got flows=%+v", flows)
	}
}

// TestPython_RenderToResponse_AutoEscaped is the wrapper-call shape —
// `render_to_response(name, context)` (Sentry-style web.helpers shim)
// must also neutralise a downstream HTML sink.
func TestPython_RenderToResponse_AutoEscaped(t *testing.T) {
	code := `
from aiohttp import web
from django.shortcuts import render_to_response
from flask import request

def handler():
    user = request.args.get("user")
    body = render_to_response("page.html", {"user": user})
    return web.Response(text=body)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("render_to_response(..., ctx) auto-escapes — must NOT fire SnkHTMLOutput; got flows=%+v", flows)
	}
}

// ---------------------------------------------------------------------------
// P1.6 — Open-redirect sanitizers (is_valid_redirect)
// ---------------------------------------------------------------------------

// TestPython_IsValidRedirect_Sanitizes verifies that
// `is_valid_redirect(next_url, ...)` is recognised as a SnkRedirect
// sanitizer. Tested in the standard sanitizer-wrap shape (the same one
// used for url_has_allowed_host_and_scheme / is_safe_url) — the
// existing per-file taint engine treats sanitization as
// "value-producing" rather than "guard-narrowing".
//
// Sentry's `get_login_redirect` uses an if-guard shape; we cover that
// at the cross-file regex walker level via the textual sanitizer
// catalog (pythonSanitizerRe.MatchString on arg expression).
func TestPython_IsValidRedirect_Sanitizes(t *testing.T) {
	code := `
from django.http import HttpResponseRedirect
from flask import request

def is_valid_redirect(url, allowed_hosts):
    return url

def handler():
    next_url = request.args.get("next")
    safe = is_valid_redirect(next_url, allowed_hosts=["example.com"])
    return HttpResponseRedirect(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Errorf("is_valid_redirect(...) wrap must neutralise SnkRedirect; got flows=%+v", flows)
	}
}

// ---------------------------------------------------------------------------
// P1.7 — re.* DangerousArgs = [0] (pattern only, NOT haystack)
// ---------------------------------------------------------------------------

// TestPython_ReMatch_HardcodedPattern_NotRegexDoS verifies that
// `re.match(HARDCODED, user_input)` does NOT fire SnkRegexDoS. The
// pattern (arg 0) is hardcoded — the haystack (arg 1) being tainted is
// the *normal* shape of regex matching against untrusted input.
func TestPython_ReMatch_HardcodedPattern_NotRegexDoS(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"re.match", `re.match(r"^\d+$", q)`},
		{"re.search", `re.search(r"foo", q)`},
		{"re.findall", `re.findall(r"\\w+", q)`},
		{"re.sub", `re.sub(r"x", "y", q)`},
		{"re.split", `re.split(r"\\s+", q)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
import re
from flask import request

def handler():
    q = request.args.get("q")
    return ` + tc.call + `
`
			flows := Analyze(code, "/app/handler.py", rules.LangPython)
			if hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("%s with hardcoded pattern and tainted haystack must NOT fire SnkRegexDoS; got flows=%+v", tc.call, flows)
			}
		})
	}
}

// TestPython_ReSub_TaintedPattern_StillRegexDoS preserves the
// re.sub/re.subn/re.split true positives — a tainted pattern (arg 0) is
// still classified as SnkRegexDoS.
func TestPython_ReSub_TaintedPattern_StillRegexDoS(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"re.sub", `re.sub(p, "y", "haystack")`},
		{"re.subn", `re.subn(p, "y", "haystack")`},
		{"re.split", `re.split(p, "haystack")`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
import re
from flask import request

def handler():
    p = request.args.get("pattern")
    return ` + tc.call + `
`
			flows := Analyze(code, "/app/handler.py", rules.LangPython)
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("%s with tainted pattern must fire SnkRegexDoS; got flows=%+v", tc.call, flows)
			}
		})
	}
}
