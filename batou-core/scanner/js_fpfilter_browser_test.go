package scanner

import "testing"

// TestIsBrowserSideJSFile_DetectsCommonShapes covers the canonical
// browser/bundler signals that suppress CWE-918 SSRF: Vite env, React
// imports, "use client" directive, JSX returns, window/document
// globals.
func TestIsBrowserSideJSFile_DetectsCommonShapes(t *testing.T) {
	cases := map[string]string{
		"vite import.meta.env": `
const API_KEY = import.meta.env.VITE_API_KEY;
export function getCoin(id) { return fetch('/api/' + id); }
`,
		"react import": `
import React from 'react';
export default function Coin({ id }) { return fetch('/api/' + id); }
`,
		"use client directive": `'use client';
export async function load(id) { return fetch('/api/' + id); }
`,
		"window.location.hostname": `
const host = window.location.hostname;
export function call(p) { return fetch(p); }
`,
		"JSX return": `
export default function App() {
    return (
        <div onClick={() => fetch('/api/coin')}>Hello</div>
    );
}
`,
		"Next.js NEXT_PUBLIC env": `
const url = process.env.NEXT_PUBLIC_API_URL;
export function load(id) { return fetch(url + '/' + id); }
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			if !isBrowserSideJSFile(code) {
				t.Errorf("expected browser detection for %s", name)
			}
		})
	}
}

// TestIsBrowserSideJSFile_DoesNotMisfireOnServerCode keeps the gate
// narrow: an Express / Node server file must NOT be classified as
// browser, so CWE-918 still fires on its server-side fetch.
func TestIsBrowserSideJSFile_DoesNotMisfireOnServerCode(t *testing.T) {
	cases := map[string]string{
		"express + node-fetch": `
const express = require('express');
const fetch = require('node-fetch');
const app = express();
app.get('/proxy', async (req, res) => {
    const r = await fetch(req.query.url);
    res.send(await r.text());
});
`,
		"plain http.get server": `
const http = require('http');
http.createServer((req, res) => {
    http.get(req.url, () => {});
}).listen(3000);
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			if isBrowserSideJSFile(code) {
				t.Errorf("server code %q should not be classified as browser", name)
			}
		})
	}
}

// TestJSFetchArgIsRelativeLiteral checks the per-line guard that
// suppresses CWE-918 SSRF even outside browser context when the URL
// argument is a string literal starting with '/'.
func TestJSFetchArgIsRelativeLiteral(t *testing.T) {
	yes := []string{
		`return fetch('/api/coins');`,
		`fetch("/api/coins/" + id);`,
		"const r = fetch(`/api/${id}`);",
		`axios.get('/api/coins');`,
		`got.post('/api/coins');`,
	}
	no := []string{
		`fetch(req.query.url);`,
		`fetch(url);`,
		`fetch('https://example.com/api');`,
		`fetch("//attacker.example/api");`,
	}
	for _, line := range yes {
		if !jsFetchArgIsRelativeLiteral(line) {
			t.Errorf("expected relative-literal match for %q", line)
		}
	}
	for _, line := range no {
		if jsFetchArgIsRelativeLiteral(line) {
			t.Errorf("did NOT expect relative-literal match for %q", line)
		}
	}
}

// TestJSScanHasXSSGuard_JSONContextSinkLineScoped is the load-bearing test
// for the segment/sink-line-scoped XSS guard. JSON-context signals
// (res.json / JSON.stringify / application/json content-type) describe how
// the response on THEIR line is encoded; they must only suppress an XSS
// finding when they sit on the sink line itself. Counting them anywhere in
// a raw look-back window let a JSON response on a sibling branch suppress a
// genuine reflected-XSS sink a few lines away (the recovered true positive).
// HTML value-sanitizers (escapeHtml/DOMPurify.sanitize/…) keep the bounded
// look-back because a sanitized value can be assigned then used a line later.
func TestJSScanHasXSSGuard_JSONContextSinkLineScoped(t *testing.T) {
	// Sibling-branch reflected XSS: res.json on a different branch must NOT
	// suppress the raw-HTML res.send sink. Without the fix, the window scan
	// sees res.json above the sink and drops the finding to zero.
	siblingBranch := []string{
		`app.get('/profile', (req, res) => {`,
		`  const name = req.query.name;`,
		`  if (req.query.format === 'json') {`,
		`    res.json({ profile: name });`,
		`  } else {`,
		`    res.send('<h1>' + name + '</h1>');`, // sink line (index 5)
		`  }`,
		`});`,
	}
	sinkLine := 5
	if jsScanHasXSSGuard(siblingBranch, sinkLine) {
		t.Errorf("LOAD-BEARING: sibling-branch res.json (line %d) wrongly suppressed "+
			"the raw-HTML res.send sink at line %d (real CWE-79 dropped to zero)",
			3, sinkLine)
	}

	// Negative gate (the filter's real job must survive): a JSON response on
	// the sink line itself IS auto-escaped — keep it suppressed.
	jsonOnSinkLine := []string{
		`app.get('/profile', (req, res) => {`,
		`  const username = req.query.name;`,
		`  res.json({ username, profile: {} });`, // sink line (index 2)
	}
	if !jsScanHasXSSGuard(jsonOnSinkLine, 2) {
		t.Error("FP-FLIP: res.json on the sink line should still suppress XSS " +
			"(JSON serialization auto-escapes the value)")
	}

	// Negative gate: JSON.stringify on the sink line stays suppressed.
	stringifyOnSinkLine := []string{
		`function send(req, res) {`,
		`  res.send(JSON.stringify({ user: req.params.id }));`, // sink line (index 1)
	}
	if !jsScanHasXSSGuard(stringifyOnSinkLine, 1) {
		t.Error("FP-FLIP: JSON.stringify on the sink line should still suppress XSS")
	}

	// Negative gate: an HTML value-sanitizer applied a line above the sink
	// (assign-then-use) must still suppress — the look-back is retained.
	sanitizedAbove := []string{
		`function render(req, res) {`,
		`  const safe = escapeHtml(req.query.q);`,
		`  res.send('<p>' + safe + '</p>');`, // sink line (index 2)
	}
	if !jsScanHasXSSGuard(sanitizedAbove, 2) {
		t.Error("escapeHtml applied one line above the sink should still suppress XSS")
	}
}
