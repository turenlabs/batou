package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Python Litestar framework request sources. Litestar (formerly
// Starlite) is an ASGI framework with its own Request object exposing the
// standard ASGI surface. These tests confirm that taint flows from Litestar
// request attributes into common downstream sinks.
//
// Litestar is built on Starlette under the hood, so existing Starlette source
// entries already match `request: Request` parameter access via the
// receiver-name heuristic. The Litestar-specific entries provide framework
// attribution and add net-new attribute coverage (path_params, cookies, url)
// that was previously missing for any Python framework using a Request-style
// object.
//
// Method-call sources like `await request.json()` / `request.form()` /
// `request.body()` are intentionally NOT added here: the tsflow walker
// currently unwraps `await_expression` (C#/JS/TS) but not Python's `await`
// node type, so any catalog entry whose Pattern requires `await ...()` is
// dormant. Adding such entries without a working test violates the
// "every new source needs a passing test" rule.

func TestPython_Litestar_SourcesRegistered(t *testing.T) {
	sources := taint.SourcesForLanguage(rules.LangPython)
	want := []string{
		"py.litestar.request.query_params",
		"py.litestar.request.path_params",
		"py.litestar.request.headers",
		"py.litestar.request.cookies",
		"py.litestar.request.url",
	}
	for _, id := range want {
		found := false
		for _, s := range sources {
			if s.ID == id {
				found = true
				if s.Category != taint.SrcUserInput {
					t.Errorf("source %s: expected SrcUserInput, got %v", id, s.Category)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected source %s to be registered for Python", id)
		}
	}
}

// --- Litestar request.query_params -> SQL sink ---

func TestPython_Litestar_QueryParams_SQLi(t *testing.T) {
	code := `
from litestar import Request, get
import sqlite3

@get("/users")
async def list_users(request: Request) -> list:
    name = request.query_params.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    return []
`
	flows := Analyze(code, "/app/handlers.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Litestar request.query_params -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Litestar request.path_params -> command injection sink ---
// path_params is a NEW attribute coverage gap previously missing from the
// catalog for any Python framework.

func TestPython_Litestar_PathParams_CommandInjection(t *testing.T) {
	code := `
from litestar import Request, get
import subprocess

@get("/files/{name:str}")
async def fetch_file(request: Request) -> str:
    name = request.path_params["name"]
    subprocess.call("cat /var/data/" + name, shell=True)
    return "ok"
`
	flows := Analyze(code, "/app/handlers.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Litestar request.path_params -> subprocess.call")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Litestar request.headers -> SQL sink ---

func TestPython_Litestar_Headers_SQLi(t *testing.T) {
	code := `
from litestar import Request, get

@get("/me")
async def me(request: Request) -> dict:
    tenant = request.headers.get("x-tenant-id")
    q = f"SELECT * FROM accounts WHERE tenant = '{tenant}'"
    cursor.execute(q)
    return {}
`
	flows := Analyze(code, "/app/handlers.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Litestar request.headers -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Litestar request.cookies -> SQL sink ---

func TestPython_Litestar_Cookies_SQLi(t *testing.T) {
	code := `
from litestar import Request, get

@get("/dashboard")
async def dashboard(request: Request) -> dict:
    sid = request.cookies.get("sid")
    q = "SELECT * FROM sessions WHERE id = '" + sid + "'"
    cursor.execute(q)
    return {}
`
	flows := Analyze(code, "/app/handlers.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Litestar request.cookies -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Litestar request.url -> SQL sink ---

func TestPython_Litestar_Url_SQLi(t *testing.T) {
	code := `
from litestar import Request, get

@get("/audit")
async def audit(request: Request) -> dict:
    url = request.url
    q = "INSERT INTO audit (path) VALUES ('" + str(url) + "')"
    cursor.execute(q)
    return {}
`
	flows := Analyze(code, "/app/handlers.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Litestar request.url -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: hardcoded value (no Request) should NOT produce a flow ---

func TestPython_Litestar_HardcodedValue_NoFlow(t *testing.T) {
	code := `
from litestar import get

@get("/version")
async def version() -> dict:
    name = "static-name"
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(q)
    return {}
`
	flows := Analyze(code, "/app/handlers.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow for hardcoded string passed to cursor.execute")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
