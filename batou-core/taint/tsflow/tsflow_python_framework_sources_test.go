package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// PR-BBpy: framework-aware Python source coverage.
//
// Each test exercises one canonical request-input shape per framework and
// asserts a SQL-injection flow is detected through cursor.execute(). The
// goal is to prove that the new SourceDef entries in
// batou-core/taint/languages/python_sources.go are wired through the
// tsflow walker and produce taint flows. We intentionally use the
// simplest source-to-sink shape (one assignment, one concat or formatted
// string, one cursor.execute) so the test fails for catalog-wiring
// reasons rather than walker-precision reasons.

func TestPython_FrameworkSources_Flask_ArgsGet_SQLi(t *testing.T) {
	code := `
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/users")
def list_users():
    q = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
    return "ok"
`
	flows := Analyze(code, "/app/flask_app.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.args.get -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_FrameworkSources_Django_GetGet_SQLi(t *testing.T) {
	code := `
from django.db import connection

def list_users(request):
    q = request.GET.get("q")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
    return "ok"
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.GET.get -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

// FastAPI Pydantic body — exercises the existing seedPythonPydanticParams
// path. This is the canonical FastAPI source pattern that works today
// (PR-CCpy registered the request-type catalog; this test asserts the
// source still fires).
//
// KNOWN LIMITATION (deferred to a follow-up PR): the canonical "parameter
// default = Query(...)" shape
//
//	def handler(q: str = Query(...)):
//	    cursor.execute(q)
//
// is not propagated by tsflow today — the tree-sitter walker does not
// thread the Query()/Body()/Form()/etc. call result back through the
// parameter binding for `typed_default_parameter` nodes, and the
// `py.fastapi.param` source (with ObjectType "fastapi") does not match a
// bare `Query(...)` call when used as a parameter default. We mitigate
// this by adding the `py.fastapi.file` source (covers `File(...)`) and
// rely on the Pydantic body pattern below for the dominant FastAPI
// request-body shape. A future PR can teach
// seedPythonPydanticParams to also seed taint on typed_default_parameter
// whose value is a Query()/Path()/Body()/Form()/Header()/Cookie() call.
func TestPython_FrameworkSources_FastAPI_PydanticBody_SQLi(t *testing.T) {
	code := `
from pydantic import BaseModel
from fastapi import FastAPI
import sqlite3

app = FastAPI()

class UserQuery(BaseModel):
    name: str

@app.post("/users")
def list_users(q: UserQuery):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q.name + "'")
    return {"ok": True}
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from FastAPI Pydantic body field -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_FrameworkSources_Starlette_QueryParamsGet_SQLi(t *testing.T) {
	// Starlette: request.query_params is a sync property (returns an
	// ImmutableMultiDict-like object). request.query_params.get(...) does
	// NOT need `await`. Our new py.starlette.request.query_params.get
	// source matches it.
	code := `
from starlette.requests import Request
import sqlite3

async def list_users(request: Request):
    q = request.query_params.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
    return "ok"
`
	flows := Analyze(code, "/app/routes.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Starlette request.query_params.get -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_FrameworkSources_AIOHTTP_QueryGet_SQLi(t *testing.T) {
	code := `
from aiohttp import web
import sqlite3

async def list_users(request):
    q = request.query.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
    return web.Response(text="ok")
`
	flows := Analyze(code, "/app/server.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from aiohttp request.query.get -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_FrameworkSources_Pyramid_ParamsGet_SQLi(t *testing.T) {
	code := `
from pyramid.view import view_config
import sqlite3

@view_config(route_name="users", renderer="json")
def list_users(request):
    q = request.params.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
    return {"ok": True}
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Pyramid request.params.get -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_FrameworkSources_Bottle_Query_SQLi(t *testing.T) {
	// Bottle exposes request.query as a FormsDict; field access syntax
	// (`request.query.q`) is the idiomatic API. The new
	// py.bottle.request.query source matches the attribute read on
	// `request.query`.
	code := `
from bottle import request, route
import sqlite3

@route("/users")
def list_users():
    q = request.query.q
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
    return "ok"
`
	flows := Analyze(code, "/app/bottle_app.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Bottle request.query.q -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s (conf=%.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Catalog registration sanity check ---

func TestPython_FrameworkSources_PRBBpy_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	sources := cat.Sources()
	ids := map[string]bool{}
	for _, s := range sources {
		ids[s.ID] = true
	}
	want := []string{
		// Flask
		"py.flask.request.args.get",
		"py.flask.request.form.get",
		"py.flask.request.values.get",
		"py.flask.request.cookies.get",
		"py.flask.request.headers.get",
		"py.flask.request.get_data",
		// Django
		"py.django.request.get.get",
		"py.django.request.post.get",
		"py.django.request.cookies.get",
		"py.django.request.meta.get",
		"py.django.request.headers.get",
		"py.django.request.raw_post_data",
		// FastAPI
		"py.fastapi.file",
		// Starlette
		"py.starlette.request.query_params.get",
		"py.starlette.request.path_params",
		"py.starlette.request.cookies.get",
		"py.starlette.request.headers.get",
		"py.starlette.request.stream",
		"py.starlette.request.client",
		// AIOHTTP
		"py.aiohttp.request.query.get",
		"py.aiohttp.request.match_info.get",
		"py.aiohttp.request.cookies.get",
		"py.aiohttp.request.headers.get",
		"py.aiohttp.request.text",
		"py.aiohttp.request.read.await",
		"py.aiohttp.request.multipart",
		// Pyramid
		"py.pyramid.request.get.get",
		"py.pyramid.request.post.get",
		"py.pyramid.request.matchdict.get",
		"py.pyramid.request.cookies.get",
		// Bottle
		"py.bottle.request.query",
		"py.bottle.request.json",
		"py.bottle.request.cookies.get",
		"py.bottle.request.headers.get",
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("missing expected PR-BBpy source: %s", id)
		}
	}
}
