package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// JavaScript SnkHeader (HTTP header injection, CWE-113) tests
// =========================================================================

func TestJS_HeaderInjection_WriteHead(t *testing.T) {
	code := `
const http = require('http');

const server = http.createServer((req, res) => {
    const userAgent = req.headers['user-agent'];
    res.writeHead(200, { 'X-Custom': userAgent });
    res.end('ok');
});
`
	flows := Analyze(code, "/app/server.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for req.headers -> res.writeHead")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_HeaderInjection_ExpressSet(t *testing.T) {
	code := `
const express = require('express');

function handler(req, res) {
    const origin = req.headers['origin'];
    res.set('Access-Control-Allow-Origin', origin);
    res.send('ok');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for req.headers -> res.set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_HeaderInjection_ExpressAppend(t *testing.T) {
	code := `
const express = require('express');

function handler(req, res) {
    const value = req.query.link;
    res.append('Link', value);
    res.send('ok');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for req.query -> res.append")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_HeaderInjection_FastifyReplyHeader(t *testing.T) {
	code := `
const fastify = require('fastify');

fastify.get('/test', async (request, reply) => {
    const token = request.headers['x-token'];
    reply.header('X-Echo-Token', token);
    return { ok: true };
});
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for request.headers -> reply.header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_HeaderInjection_FastifyReplyHeaders(t *testing.T) {
	code := `
const fastify = require('fastify');

fastify.get('/test', async (request, reply) => {
    const customHeaders = request.body;
    reply.headers(customHeaders);
    return { ok: true };
});
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for request.body -> reply.headers")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_HeaderInjection_KoaCtxSet(t *testing.T) {
	code := `
const Koa = require('koa');

async function handler(ctx) {
    const origin = ctx.headers['origin'];
    ctx.set('Access-Control-Allow-Origin', origin);
    ctx.body = 'ok';
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for ctx.headers -> ctx.set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_HeaderInjection_KoaCtxAppend(t *testing.T) {
	code := `
const Koa = require('koa');

async function handler(ctx) {
    const value = ctx.query.link;
    ctx.append('Link', value);
    ctx.body = 'ok';
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for ctx.query -> ctx.append")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative test: safe header value (literal string, no taint source)
func TestJS_HeaderInjection_SafeLiteral(t *testing.T) {
	code := `
const express = require('express');

function handler(req, res) {
    res.set('X-Frame-Options', 'DENY');
    res.send('ok');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected NO header injection flow when value is a literal")
	}
}
