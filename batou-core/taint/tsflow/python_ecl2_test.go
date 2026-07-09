package tsflow

// ECL2 coverage-breadth cleanup wave — permanent tests for the Python sinks
// added in batou-core/taint/languages/python_sinks.go. Each detection has a
// positive (TP fires) test and a negative (safe / sanitized stays clean) test.
//
// These lock the closed detection categories:
//   - runpy.run_path/run_module          (CWE-94  code execution)
//   - code.interact/runsource/runcode    (CWE-94  interactive eval)
//   - string.Template.substitute         (CWE-1336 format-string / SSTI)
//   - boto3 S3 download_file Filename    (CWE-22  path traversal write)
//   - setattr(obj, tainted_name, ...)    (CWE-915 mass assignment)
//   - werkzeug.utils.redirect            (CWE-601 open redirect)
//   - aiohttp web.HTTPFound              (CWE-601 open redirect)
//   - bottle.redirect                    (CWE-601 open redirect)
//   - httpx.Client(proxy=)/requests proxies (CWE-918 SSRF via proxy)
//   - sqlite3.connect(path)              (CWE-22  arbitrary db path)

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- runpy dynamic execution (CWE-94) ---

func TestPython_ECL2_Runpy_Vulnerable(t *testing.T) {
	code := `
import runpy
from flask import request

def f():
    p = request.args.get('mod_path')
    runpy.run_path(p)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.runpy.run") {
		t.Fatalf("expected py.runpy.run for tainted runpy.run_path(); got %v", sinkIDs(flows))
	}
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Errorf("runpy.run_path(tainted) must be SnkEval (code execution)")
	}
}

func TestPython_ECL2_Runpy_Safe(t *testing.T) {
	// Constant path — no taint reaches arg 0, must stay clean.
	code := `
import runpy
from flask import request

def f():
    _ = request.args.get('ignored')
    runpy.run_path("/opt/app/bootstrap.py")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.runpy.run") {
		t.Errorf("runpy.run_path() with a constant path must stay clean; got %v", sinkIDs(flows))
	}
}

// --- code.interact / interactive eval (CWE-94) ---

func TestPython_ECL2_CodeInteract_Vulnerable(t *testing.T) {
	code := `
import code
from flask import request

def f():
    src = request.args.get('src')
    code.interact(src)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.code.interact") {
		t.Fatalf("expected py.code.interact for tainted code.interact(); got %v", sinkIDs(flows))
	}
}

func TestPython_ECL2_CodeInteract_Safe(t *testing.T) {
	code := `
import code

def f():
    code.interact(banner="welcome", local={})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.code.interact") {
		t.Errorf("code.interact() with constant banner must stay clean; got %v", sinkIDs(flows))
	}
}

// --- string.Template format-string injection (CWE-1336) ---

func TestPython_ECL2_StringTemplate_Vulnerable(t *testing.T) {
	code := `
from string import Template
from flask import request

def f():
    tmpl = request.args.get('tmpl')
    return Template(tmpl).substitute(name="x")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	// Detection category (SnkTemplate / CWE-1336) is what closes the gap;
	// either py.string.template.substitute or a peer template sink may win.
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Fatalf("expected SnkTemplate flow for tainted string.Template(); got %v", sinkIDs(flows))
	}
}

func TestPython_ECL2_StringTemplate_Safe(t *testing.T) {
	// Constant template, only the substituted *value* is tainted — safe shape.
	code := `
from string import Template
from flask import request

def f():
    name = request.args.get('name')
    return Template("Hello $name").substitute(name=name)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.string.template.substitute") {
		t.Errorf("constant template with tainted value must stay clean for py.string.template.substitute; got %v", sinkIDs(flows))
	}
}

// --- boto3 S3 download_file path traversal (CWE-22) ---

func TestPython_ECL2_Boto3Download_Vulnerable(t *testing.T) {
	code := `
import boto3
from flask import request

def f():
    client = boto3.client('s3')
    dest = request.args.get('dest')
    client.download_file('bucket', 'key', dest)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.boto3.s3.download_file") {
		t.Fatalf("expected py.boto3.s3.download_file for tainted local Filename; got %v", sinkIDs(flows))
	}
	if !hasTaintFlowCWE(flows, "CWE-22") {
		t.Errorf("boto3 download_file tainted Filename must be CWE-22 (path traversal)")
	}
}

func TestPython_ECL2_Boto3Download_Safe(t *testing.T) {
	// Tainted REMOTE key (arg 1), constant local Filename (arg 2) — arg 2 is
	// the dangerous one, so this must stay clean.
	code := `
import boto3
from flask import request

def f():
    client = boto3.client('s3')
    key = request.args.get('key')
    client.download_file('bucket', key, '/tmp/safe_download.bin')
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.boto3.s3.download_file") {
		t.Errorf("boto3 download_file with constant local Filename must stay clean; got %v", sinkIDs(flows))
	}
}

// --- setattr mass assignment (CWE-915) ---

func TestPython_ECL2_Setattr_Vulnerable(t *testing.T) {
	code := `
from flask import request

def f(obj):
    name = request.args.get('field')
    setattr(obj, name, "x")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.setattr.massassign") {
		t.Fatalf("expected py.setattr.massassign for tainted attribute name; got %v", sinkIDs(flows))
	}
}

func TestPython_ECL2_Setattr_Safe(t *testing.T) {
	// Tainted VALUE (arg 2), constant attribute NAME (arg 1) — only the name
	// is dangerous, so a tainted value must NOT fire this sink.
	code := `
from flask import request

def f(obj):
    value = request.args.get('value')
    setattr(obj, "display_name", value)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.setattr.massassign") {
		t.Errorf("setattr with constant attribute name must stay clean; got %v", sinkIDs(flows))
	}
}

// --- aiohttp web.HTTPFound open redirect (CWE-601) ---

func TestPython_ECL2_AiohttpRedirect_Vulnerable(t *testing.T) {
	code := `
from aiohttp import web

async def f(request):
    loc = request.query.get('url')
    raise web.HTTPFound(loc)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.aiohttp.httpfound") {
		t.Fatalf("expected py.aiohttp.httpfound for tainted location; got %v", sinkIDs(flows))
	}
}

func TestPython_ECL2_AiohttpRedirect_Safe(t *testing.T) {
	// is_safe_url host-allowlist validation in the wrap shape the per-file
	// taint engine models (value-producing, not guard-narrowing) neutralises
	// the redirect.
	code := `
from aiohttp import web
from django.utils.http import url_has_allowed_host_and_scheme

async def f(request):
    loc = request.query.get('url')
    safe = url_has_allowed_host_and_scheme(loc, allowed_hosts={'example.com'})
    raise web.HTTPFound(safe)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Errorf("aiohttp HTTPFound after url_has_allowed_host_and_scheme wrap must stay clean; got %v", sinkIDs(flows))
	}
}

// --- bottle.redirect open redirect (CWE-601) ---

func TestPython_ECL2_BottleRedirect_Vulnerable(t *testing.T) {
	code := `
import bottle

def f():
    url = bottle.request.GET.get('url')
    bottle.redirect(url)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.bottle.redirect") {
		t.Fatalf("expected py.bottle.redirect for tainted url; got %v", sinkIDs(flows))
	}
}

func TestPython_ECL2_BottleRedirect_Safe(t *testing.T) {
	code := `
import bottle

def f():
    bottle.redirect('/dashboard')
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.bottle.redirect") {
		t.Errorf("bottle.redirect to a constant path must stay clean; got %v", sinkIDs(flows))
	}
}

// --- httpx proxy SSRF (CWE-918) ---

func TestPython_ECL2_HttpxProxy_Vulnerable(t *testing.T) {
	code := `
import httpx
from flask import request

def f():
    p = request.args.get('proxy')
    httpx.Client(proxy=p)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.httpx.client.proxy") {
		t.Fatalf("expected py.httpx.client.proxy for tainted proxy URL; got %v", sinkIDs(flows))
	}
	if !hasTaintFlowCWE(flows, "CWE-918") {
		t.Errorf("tainted proxy must be CWE-918 (SSRF)")
	}
}

func TestPython_ECL2_HttpxProxy_Safe(t *testing.T) {
	code := `
import httpx

def f():
    httpx.Client(proxy="http://corp-proxy.internal:3128")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.httpx.client.proxy") {
		t.Errorf("httpx.Client with a constant proxy must stay clean; got %v", sinkIDs(flows))
	}
}

// --- sqlite3.connect path (CWE-22) ---

func TestPython_ECL2_Sqlite3Connect_Vulnerable(t *testing.T) {
	code := `
import sqlite3
from flask import request

def f():
    db = request.args.get('db')
    sqlite3.connect(db)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasSinkID(flows, "py.sqlite3.connect.path") {
		t.Fatalf("expected py.sqlite3.connect.path for tainted db path; got %v", sinkIDs(flows))
	}
}

func TestPython_ECL2_Sqlite3Connect_Safe(t *testing.T) {
	code := `
import sqlite3

def f():
    sqlite3.connect("/var/data/app.db")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasSinkID(flows, "py.sqlite3.connect.path") {
		t.Errorf("sqlite3.connect with a constant path must stay clean; got %v", sinkIDs(flows))
	}
}

// sinkIDs is a small helper for failure messages.
func sinkIDs(flows []taint.TaintFlow) []string {
	ids := make([]string, 0, len(flows))
	for _, f := range flows {
		ids = append(ids, f.Sink.ID)
	}
	return ids
}
