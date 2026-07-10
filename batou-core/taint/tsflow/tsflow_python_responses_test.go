package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python Starlette/FastAPI response sinks — HTMLResponse, FileResponse,
// StreamingResponse (CWE-79, CWE-22)
// =========================================================================

func TestPython_Starlette_HTMLResponse_XSS(t *testing.T) {
	code := `
from fastapi import FastAPI, Request
from starlette.responses import HTMLResponse

app = FastAPI()

@app.get("/greet")
async def greet(request: Request):
    name = request.query_params.get("name")
    return HTMLResponse(f"<h1>Hello {name}</h1>")
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for request.query_params -> HTMLResponse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Starlette_HTMLResponse_Safe(t *testing.T) {
	code := `
from starlette.responses import HTMLResponse
import html

def handler(request):
    name = request.query_params.get("name")
    safe_name = html.escape(name)
    return HTMLResponse(f"<h1>Hello {safe_name}</h1>")
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected no XSS flow after html.escape() sanitization")
	}
}

func TestPython_Starlette_PlainTextResponse_XSS(t *testing.T) {
	code := `
from fastapi import FastAPI, Request
from starlette.responses import PlainTextResponse

app = FastAPI()

@app.get("/echo")
async def echo(request: Request):
    msg = request.query_params.get("msg")
    return PlainTextResponse(msg)
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected reflected-content flow for request.query_params -> PlainTextResponse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Starlette_PlainTextResponse_Static_Safe(t *testing.T) {
	code := `
from starlette.responses import PlainTextResponse

def handler(request):
    return PlainTextResponse("ok")
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected no flow for a static PlainTextResponse body")
	}
}

func TestPython_Starlette_FileResponse_PathTraversal(t *testing.T) {
	code := `
from fastapi import FastAPI
from starlette.responses import FileResponse

app = FastAPI()

@app.get("/download")
async def download(request):
    filename = request.query_params.get("file")
    return FileResponse(filename)
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path traversal flow for request.query_params -> FileResponse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Starlette_StreamingResponse(t *testing.T) {
	code := `
from starlette.responses import StreamingResponse
from flask import request

def handler():
    data = request.args.get("content")
    return StreamingResponse(iter([data]), media_type="text/html")
`
	flows := Analyze(code, "/app/main.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for request.args -> StreamingResponse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Python aiohttp web response sinks — web.Response (CWE-79)
// =========================================================================

func TestPython_Aiohttp_WebResponse_XSS(t *testing.T) {
	code := `
from aiohttp import web

async def handler(request):
    name = request.query.get("name")
    return web.Response(text=f"<h1>{name}</h1>", content_type="text/html")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for request.query -> web.Response()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Aiohttp_WebResponse_Safe(t *testing.T) {
	code := `
from aiohttp import web
import html

async def handler(request):
    name = request.query.get("name")
    safe = html.escape(name)
    return web.Response(text=f"<p>{safe}</p>", content_type="text/html")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected no XSS flow after html.escape() sanitization")
	}
}

// =========================================================================
// Python archive extraction sinks — extractall, unpack_archive
// (CWE-22, CVE-2007-4559)
// =========================================================================

func TestPython_ZipFile_ExtractAll_ZipSlip(t *testing.T) {
	code := `
import zipfile

def extract_upload():
    archive_path = input()
    zf = zipfile.ZipFile(archive_path)
    zf.extractall('/tmp/output')
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for input() -> ZipFile() -> extractall() (zip-slip)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TarFile_ExtractAll_TarSlip(t *testing.T) {
	code := `
import tarfile

def extract_archive():
    path = input()
    tf = tarfile.open(path)
    tf.extractall('/tmp/output')
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for input() -> tf.extractall() (tar-slip)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Shutil_UnpackArchive(t *testing.T) {
	code := `
import shutil
from flask import request

def extract():
    archive_path = request.form.get('path')
    shutil.unpack_archive(archive_path, '/tmp/output')
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for request.form -> shutil.unpack_archive()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TarFile_ExtractAll_Basename_Safe(t *testing.T) {
	code := `
import tarfile
import os

def extract_archive():
    dest = input()
    safe_dest = os.path.basename(dest)
    tf = tarfile.open('/tmp/archive.tar.gz')
    tf.extractall(safe_dest)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected no file write flow when os.path.basename() sanitizer is present")
	}
}

// =========================================================================
// Python Sanic response sinks — response.html / response.raw (CWE-79)
// =========================================================================

func TestPython_Sanic_ResponseHTML_XSS(t *testing.T) {
	code := `
from sanic import Sanic, response

app = Sanic("app")

@app.route("/greet")
async def greet(request):
    name = request.args.get("name")
    return response.html(f"<h1>Hello {name}</h1>")
`
	flows := Analyze(code, "/app/server.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for request.args -> response.html()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Sanic_ResponseRaw_XSS(t *testing.T) {
	code := `
from sanic import Sanic, response

app = Sanic("app")

@app.route("/raw")
async def raw(request):
    body = request.json
    return response.raw(body, content_type="text/html")
`
	flows := Analyze(code, "/app/server.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected reflected-body flow for request.json -> response.raw()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_Sanic_ResponseHTML_Escaped_Safe(t *testing.T) {
	code := `
from sanic import Sanic, response
import html

app = Sanic("app")

@app.route("/greet")
async def greet(request):
    name = request.args.get("name")
    safe = html.escape(name)
    return response.html(f"<h1>Hello {safe}</h1>")
`
	flows := Analyze(code, "/app/server.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected no XSS flow after html.escape() sanitization")
	}
}

func TestPython_Sanic_ResponseJSON_Static_Safe(t *testing.T) {
	code := `
from sanic import Sanic, response

app = Sanic("app")

@app.route("/status")
async def status(request):
    return response.html("<p>ok</p>")
`
	flows := Analyze(code, "/app/server.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected no flow for a static response.html() body")
	}
}
