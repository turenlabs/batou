package header

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// Direct-Scan helpers for the UNREGISTERED rules (HDR-001..HDR-008).
//
// Only HDR-009..HDR-012 are wired into the global registry via init(), so
// testutil.ScanContent never exercises HDR-001..HDR-008. We invoke their
// Scan() methods directly with a hand-built ScanContext. This is the only
// way to cover the bulk of header.go.
// ==========================================================================

func ctxFor(path, content string, lang rules.Language) *rules.ScanContext {
	return &rules.ScanContext{
		FilePath: path,
		Content:  content,
		Language: lang,
		IsNew:    true,
	}
}

// findIDs returns the set of rule IDs present in a finding slice.
func findIDs(fs []rules.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func hasID(fs []rules.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// A Go server-setup file (not a route-only file, has a server listener) that
// sets a response header but no security headers — the canonical "vulnerable"
// shape for the missing-header rules.
const goServerVuln = `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func main() {
	http.ListenAndServe(":8080", nil)
}`

// ==========================================================================
// BATOU-HDR-001 MissingCSP
// ==========================================================================

func TestMissingCSP_Vulnerable(t *testing.T) {
	r := &MissingCSP{}
	ctx := ctxFor("/app/server.go", goServerVuln, rules.LangGo)
	got := r.Scan(ctx)
	if !hasID(got, "BATOU-HDR-001") {
		t.Fatalf("expected BATOU-HDR-001, got %v", findIDs(got))
	}
	f := got[0]
	if f.LineNumber != 6 {
		t.Errorf("expected finding on line 6 (the Header().Set line), got %d", f.LineNumber)
	}
	if f.CWEID != "CWE-693" {
		t.Errorf("expected CWE-693, got %q", f.CWEID)
	}
	if f.Severity != rules.Medium {
		t.Errorf("expected Medium severity, got %v", f.Severity)
	}
}

func TestMissingCSP_CSPAlreadySet_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingCSP{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-001") {
		t.Fatalf("CSP is present; should not flag, got %v", findIDs(got))
	}
}

func TestMissingCSP_NotHTTPHandler_Safe(t *testing.T) {
	// No http/request/response/handler/router tokens -> isHTTPHandlerFile false.
	content := `package math

func Add(a, b int) int { return a + b }`
	r := &MissingCSP{}
	got := r.Scan(ctxFor("/app/math.go", content, rules.LangGo))
	if got != nil {
		t.Fatalf("non-HTTP file should yield no findings, got %v", findIDs(got))
	}
}

func TestMissingCSP_RouteHandlerFile_Safe(t *testing.T) {
	// Route-only express file (no server setup) -> middleware assumed.
	content := `const router = require('express').Router();
router.get('/users', (req, res) => {
	res.setHeader('Content-Type', 'application/json');
	res.json(users);
});
module.exports = router;`
	r := &MissingCSP{}
	got := r.Scan(ctxFor("/app/routes/users.js", content, rules.LangJavaScript))
	if hasID(got, "BATOU-HDR-001") {
		t.Fatalf("route-only file should be suppressed, got %v", findIDs(got))
	}
}

func TestMissingCSP_NoResponseHeaders_Safe(t *testing.T) {
	// HTTP-ish file (mentions "request") but never sets a response header.
	content := `package main

func process(request string) string {
	return request + "!"
}

func main() { _ = process("x") }`
	r := &MissingCSP{}
	got := r.Scan(ctxFor("/app/proc.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-001") {
		t.Fatalf("no response headers set; should not flag, got %v", findIDs(got))
	}
}

func TestMissingCSP_FrontendJS_Safe(t *testing.T) {
	// Browser JS: uses document/window APIs and no server-side APIs.
	content := `document.addEventListener('DOMContentLoaded', () => {
	const el = document.querySelector('#root');
	window.fetch('/api').then(r => r.json());
});`
	r := &MissingCSP{}
	got := r.Scan(ctxFor("/static/app.js", content, rules.LangJavaScript))
	if got != nil {
		t.Fatalf("frontend JS cannot set response headers; expected nil, got %v", findIDs(got))
	}
}

func TestMissingCSP_HelmetCSP_Safe(t *testing.T) {
	// helmet.contentSecurityPolicy present and a server setup present -> safe.
	content := `const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet.contentSecurityPolicy({ directives: {} }));
function h(req, res) {
	res.setHeader('Content-Type', 'application/json');
}
app.listen(3000);`
	r := &MissingCSP{}
	got := r.Scan(ctxFor("/app/server.js", content, rules.LangJavaScript))
	if hasID(got, "BATOU-HDR-001") {
		t.Fatalf("helmet CSP present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-002 MissingXFrameOptions
// ==========================================================================

func TestMissingXFrameOptions_Vulnerable(t *testing.T) {
	r := &MissingXFrameOptions{}
	got := r.Scan(ctxFor("/app/server.go", goServerVuln, rules.LangGo))
	if !hasID(got, "BATOU-HDR-002") {
		t.Fatalf("expected BATOU-HDR-002, got %v", findIDs(got))
	}
	if got[0].CWEID != "CWE-1021" {
		t.Errorf("expected CWE-1021, got %q", got[0].CWEID)
	}
}

func TestMissingXFrameOptions_FrameAncestorsCSP_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingXFrameOptions{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-002") {
		t.Fatalf("frame-ancestors present; should not flag, got %v", findIDs(got))
	}
}

func TestMissingXFrameOptions_HeaderSet_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Frame-Options", "DENY")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingXFrameOptions{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-002") {
		t.Fatalf("X-Frame-Options present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-003 MissingXContentTypeOptions
// ==========================================================================

func TestMissingXContentTypeOptions_Vulnerable(t *testing.T) {
	r := &MissingXContentTypeOptions{}
	got := r.Scan(ctxFor("/app/server.go", goServerVuln, rules.LangGo))
	if !hasID(got, "BATOU-HDR-003") {
		t.Fatalf("expected BATOU-HDR-003, got %v", findIDs(got))
	}
	if got[0].Severity != rules.Low {
		t.Errorf("expected Low severity, got %v", got[0].Severity)
	}
}

func TestMissingXContentTypeOptions_HeaderSet_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingXContentTypeOptions{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-003") {
		t.Fatalf("nosniff present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-004 MissingHSTS
// ==========================================================================

func TestMissingHSTS_Vulnerable(t *testing.T) {
	r := &MissingHSTS{}
	got := r.Scan(ctxFor("/app/server.go", goServerVuln, rules.LangGo))
	if !hasID(got, "BATOU-HDR-004") {
		t.Fatalf("expected BATOU-HDR-004, got %v", findIDs(got))
	}
	if got[0].CWEID != "CWE-319" {
		t.Errorf("expected CWE-319, got %q", got[0].CWEID)
	}
}

func TestMissingHSTS_HeaderSet_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingHSTS{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-004") {
		t.Fatalf("HSTS present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-005 PermissiveCSP
// ==========================================================================

func TestPermissiveCSP_UnsafeInline_Vulnerable(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &PermissiveCSP{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if !hasID(got, "BATOU-HDR-005") {
		t.Fatalf("expected BATOU-HDR-005, got %v", findIDs(got))
	}
	if !strings.Contains(got[0].Title, "unsafe-inline") {
		t.Errorf("title should name the matched token, got %q", got[0].Title)
	}
	if got[0].Severity != rules.High {
		t.Errorf("expected High severity, got %v", got[0].Severity)
	}
}

func TestPermissiveCSP_UnsafeEval_NearbyContext_Vulnerable(t *testing.T) {
	// 'unsafe-eval' on a line WITHOUT a CSP keyword, but a CSP keyword is on a
	// nearby line (within window 3) -> still flagged via nearbyLines context.
	content := `package main

func policy() string {
	directive := "default-src 'self'"
	value := "'unsafe-eval'"
	_ = directive
	return value
}`
	r := &PermissiveCSP{}
	got := r.Scan(ctxFor("/app/policy.go", content, rules.LangGo))
	if !hasID(got, "BATOU-HDR-005") {
		t.Fatalf("expected BATOU-HDR-005 via nearby CSP context, got %v", findIDs(got))
	}
}

func TestPermissiveCSP_UnsafeInline_NoCSPContext_Safe(t *testing.T) {
	// 'unsafe-inline' string with NO csp/script-src/etc context anywhere nearby.
	content := `package main

func note() string {
	return "this value is unsafe-inline by nature"
}`
	r := &PermissiveCSP{}
	got := r.Scan(ctxFor("/app/note.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-005") {
		t.Fatalf("no CSP context; should not flag, got %v", findIDs(got))
	}
}

func TestPermissiveCSP_CommentLine_Safe(t *testing.T) {
	// The unsafe token only appears in a comment-only line -> skipped.
	content := `package main

// CSP note: never use 'unsafe-inline' in script-src
func handler() {}`
	r := &PermissiveCSP{}
	got := r.Scan(ctxFor("/app/h.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-005") {
		t.Fatalf("comment-only line should be skipped, got %v", findIDs(got))
	}
}

func TestPermissiveCSP_RouteHandlerFile_Safe(t *testing.T) {
	content := `const router = require('express').Router();
router.get('/x', (req, res) => {
	res.setHeader('Content-Security-Policy', "script-src 'unsafe-inline'");
});
module.exports = router;`
	r := &PermissiveCSP{}
	got := r.Scan(ctxFor("/app/routes/x.js", content, rules.LangJavaScript))
	if hasID(got, "BATOU-HDR-005") {
		t.Fatalf("route-only file is suppressed, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-006 MissingXXSSProtection
// ==========================================================================

func TestMissingXXSSProtection_Vulnerable(t *testing.T) {
	r := &MissingXXSSProtection{}
	got := r.Scan(ctxFor("/app/server.go", goServerVuln, rules.LangGo))
	if !hasID(got, "BATOU-HDR-006") {
		t.Fatalf("expected BATOU-HDR-006, got %v", findIDs(got))
	}
	if got[0].CWEID != "CWE-79" {
		t.Errorf("expected CWE-79, got %q", got[0].CWEID)
	}
}

func TestMissingXXSSProtection_CSPPresent_Safe(t *testing.T) {
	// CSP replaces X-XSS-Protection: when CSP is set, rule stays silent.
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingXXSSProtection{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-006") {
		t.Fatalf("CSP present; should not flag X-XSS-Protection, got %v", findIDs(got))
	}
}

func TestMissingXXSSProtection_HeaderSet_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-XSS-Protection", "0")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingXXSSProtection{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-006") {
		t.Fatalf("X-XSS-Protection present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-007 MissingReferrerPolicy
// ==========================================================================

func TestMissingReferrerPolicy_Vulnerable(t *testing.T) {
	r := &MissingReferrerPolicy{}
	got := r.Scan(ctxFor("/app/server.go", goServerVuln, rules.LangGo))
	if !hasID(got, "BATOU-HDR-007") {
		t.Fatalf("expected BATOU-HDR-007, got %v", findIDs(got))
	}
	if got[0].CWEID != "CWE-200" {
		t.Errorf("expected CWE-200, got %q", got[0].CWEID)
	}
}

func TestMissingReferrerPolicy_HeaderSet_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingReferrerPolicy{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-007") {
		t.Fatalf("Referrer-Policy present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-008 MissingPermissionsPolicy
// ==========================================================================

func TestMissingPermissionsPolicy_Vulnerable(t *testing.T) {
	r := &MissingPermissionsPolicy{}
	got := r.Scan(ctxFor("/app/server.go", goServerVuln, rules.LangGo))
	if !hasID(got, "BATOU-HDR-008") {
		t.Fatalf("expected BATOU-HDR-008, got %v", findIDs(got))
	}
}

func TestMissingPermissionsPolicy_FeaturePolicy_Safe(t *testing.T) {
	// Legacy Feature-Policy header counts as present.
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Feature-Policy", "camera 'none'")
}

func main() { http.ListenAndServe(":8080", nil) }`
	r := &MissingPermissionsPolicy{}
	got := r.Scan(ctxFor("/app/server.go", content, rules.LangGo))
	if hasID(got, "BATOU-HDR-008") {
		t.Fatalf("Feature-Policy present; should not flag, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-009 CacheControlSensitive (registered)
// ==========================================================================

func TestCacheControlSensitive_Vulnerable(t *testing.T) {
	// Sensitive path in FilePath + Cache-Control set without no-store.
	content := `package main

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "max-age=3600")
}`
	result := testutil.ScanContent(t, "/app/auth/login.go", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-009")
}

func TestCacheControlSensitive_NoStorePresent_Safe(t *testing.T) {
	content := `package main

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
}`
	result := testutil.ScanContent(t, "/app/auth/login.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-009")
}

func TestCacheControlSensitive_NonSensitivePath_Safe(t *testing.T) {
	// No sensitive keyword in path or content -> rule short-circuits.
	content := `package main

func widgetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "max-age=3600")
}`
	result := testutil.ScanContent(t, "/app/widgets/list.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-009")
}

func TestCacheControlSensitive_SensitiveInContent_Vulnerable(t *testing.T) {
	// Non-sensitive PATH but sensitive keyword in the file content.
	content := `package main

func handler(w http.ResponseWriter, r *http.Request) {
	// serves the user dashboard
	dashboard := loadDashboard()
	_ = dashboard
	w.Header().Set("Cache-Control", "public, max-age=600")
}`
	result := testutil.ScanContent(t, "/app/pages/view.go", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-009")
}

func TestCacheControlSensitive_DirectScan_RouteFile_Safe(t *testing.T) {
	// Route-only file suppresses HDR-009 even on a sensitive path.
	content := `const router = require('express').Router();
router.get('/login', (req, res) => {
	res.setHeader('Cache-Control', 'max-age=60');
});
module.exports = router;`
	r := &CacheControlSensitive{}
	got := r.Scan(ctxFor("/app/routes/login.js", content, rules.LangJavaScript))
	if hasID(got, "BATOU-HDR-009") {
		t.Fatalf("route-only file should suppress HDR-009, got %v", findIDs(got))
	}
}

// ==========================================================================
// BATOU-HDR-010 ServerHeaderDisclosure (registered)
// ==========================================================================

func TestServerHeaderDisclosure_Vulnerable(t *testing.T) {
	content := `package main

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "MyApp/1.0")
}`
	result := testutil.ScanContent(t, "/app/server.go", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-010")
}

func TestServerHeaderDisclosure_BeingRemoved_Safe(t *testing.T) {
	// removeHeader('Server') present anywhere -> whole rule suppressed.
	content := `const app = require('express')();
app.use((req, res, next) => {
	res.removeHeader('Server');
	res.setHeader('Server', 'temp');
	next();
});`
	result := testutil.ScanContent(t, "/app/mw.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-010")
}

func TestServerHeaderDisclosure_NoServerHeader_Safe(t *testing.T) {
	content := `package main

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
}`
	result := testutil.ScanContent(t, "/app/server.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-010")
}

// ==========================================================================
// BATOU-HDR-011 XPoweredByDisclosure (registered)
// ==========================================================================

func TestXPoweredByDisclosure_Vulnerable(t *testing.T) {
	content := `const app = require('express')();
app.use((req, res, next) => {
	res.setHeader('X-Powered-By', 'Express');
	next();
});`
	result := testutil.ScanContent(t, "/app/mw.js", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-011")
}

func TestXPoweredByDisclosure_ExpressDisable_Safe(t *testing.T) {
	content := `const app = require('express')();
app.disable('x-powered-by');
app.use((req, res, next) => {
	res.setHeader('X-Powered-By', 'Express');
	next();
});`
	result := testutil.ScanContent(t, "/app/mw.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-011")
}

func TestXPoweredByDisclosure_HelmetHidePowered_Safe(t *testing.T) {
	content := `const app = require('express')();
app.use(helmet.hidePoweredBy());
app.use((req, res, next) => {
	res.setHeader('X-Powered-By', 'Express');
	next();
});`
	result := testutil.ScanContent(t, "/app/mw.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-011")
}

func TestXPoweredByDisclosure_Removed_Safe(t *testing.T) {
	content := `const app = require('express')();
app.use((req, res, next) => {
	res.removeHeader('X-Powered-By');
	res.setHeader('X-Powered-By', 'temp');
	next();
});`
	result := testutil.ScanContent(t, "/app/mw.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-011")
}

// ==========================================================================
// BATOU-HDR-012 CRLFHeaderInjection (registered)
// ==========================================================================

func TestCRLFHeaderInjection_TaintedHeader_Vulnerable(t *testing.T) {
	content := `const app = require('express')();
app.get('/redir', (req, res) => {
	res.setHeader('X-Custom', req.query.name);
});`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-012")
	fs := testutil.FindingsByRule(result, "BATOU-HDR-012")
	if fs[0].CWEID != "CWE-113" {
		t.Errorf("expected CWE-113, got %q", fs[0].CWEID)
	}
	if fs[0].Severity != rules.High {
		t.Errorf("expected High severity, got %v", fs[0].Severity)
	}
}

func TestCRLFHeaderInjection_ConcatTaint_Vulnerable(t *testing.T) {
	content := `function h(req, res) {
	res.setHeader("X-Foo", "prefix" + req.params.id);
}`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-012")
}

func TestCRLFHeaderInjection_PHPHeader_Vulnerable(t *testing.T) {
	content := `<?php
header("Location: " . $_GET['url']);
?>`
	result := testutil.ScanContent(t, "/app/redirect.php", content)
	testutil.MustFindRule(t, result, "BATOU-HDR-012")
}

func TestCRLFHeaderInjection_StaticValue_Safe(t *testing.T) {
	content := `function h(req, res) {
	res.setHeader("X-Foo", "static-value");
}`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-012")
}

func TestCRLFHeaderInjection_CommentLine_Safe(t *testing.T) {
	// The injection pattern appears only in a comment-only line -> skipped.
	content := `function h(req, res) {
	// res.setHeader('X-Custom', req.query.name);
	res.json({ok: true});
}`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-HDR-012")
}

// ==========================================================================
// Unexported helper functions
// ==========================================================================

func TestIsHTTPHandlerFile(t *testing.T) {
	cases := []struct {
		content string
		want    bool
	}{
		{"package main\nfunc Add(a, b int) int { return a + b }", false},
		{"w.Header().Set(\"X\", \"y\") // http response", true},
		{"const router = express.Router()", true},
		{"from flask import Flask", true},
		{"class MyServlet extends HttpServlet {}", true},
		{"app.get('/x')", true},
		{"def handler(req): pass", true},
		{"plain text with no markers", false},
	}
	for _, c := range cases {
		if got := isHTTPHandlerFile(c.content); got != c.want {
			t.Errorf("isHTTPHandlerFile(%q) = %v, want %v", c.content, got, c.want)
		}
	}
}

func TestIsRouteHandlerFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"helmet middleware", "app.use(helmet())", true},
		{"secure_headers", "use SecureHeaders", true},
		{"EnableWebSecurity", "@EnableWebSecurity", true},
		{"route only, no server", "router.get('/x', h)\nmodule.exports = router", true},
		{"route plus server listen", "app.get('/x', h)\napp.listen(3000)", false},
		{"server only", "http.ListenAndServe(\":8080\", nil)", false},
		{"plain file", "package main\nfunc x() {}", false},
	}
	for _, c := range cases {
		if got := isRouteHandlerFile(c.content); got != c.want {
			t.Errorf("%s: isRouteHandlerFile = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsComment(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"// slash comment", true},
		{"# hash comment", true},
		{"* star continuation", true},
		{"/* block open", true},
		{"<!-- html comment", true},
		{"code(); // trailing not a leading comment", false},
		{"  indented (already trimmed by callers)", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isComment(c.line); got != c.want {
			t.Errorf("isComment(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 100); got != "short" {
		t.Errorf("short string should be unchanged, got %q", got)
	}
	long := strings.Repeat("a", 130)
	got := truncate(long, 120)
	if len(got) != 123 { // 120 chars + "..."
		t.Errorf("expected 123-char result (120 + ellipsis), got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncated string should end with ellipsis, got %q", got)
	}
	// Exact-boundary: len == maxLen is NOT truncated.
	exact := strings.Repeat("b", 10)
	if got := truncate(exact, 10); got != exact {
		t.Errorf("len==maxLen should not truncate, got %q", got)
	}
}

func TestNearbyLines(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	// Window 1 around index 2 -> b,c,d
	if got := nearbyLines(lines, 2, 1); got != "b\nc\nd" {
		t.Errorf("middle window: got %q", got)
	}
	// Start clamp: index 0, window 2 -> a,b,c
	if got := nearbyLines(lines, 0, 2); got != "a\nb\nc" {
		t.Errorf("start clamp: got %q", got)
	}
	// End clamp: index 4, window 2 -> c,d,e
	if got := nearbyLines(lines, 4, 2); got != "c\nd\ne" {
		t.Errorf("end clamp: got %q", got)
	}
	// Window larger than slice -> whole slice.
	if got := nearbyLines(lines, 2, 10); got != "a\nb\nc\nd\ne" {
		t.Errorf("oversize window: got %q", got)
	}
}

func TestIsFrontendJSFile(t *testing.T) {
	// Backend Go file is never "frontend JS".
	if isFrontendJSFile(ctxFor("/app/s.go", goServerVuln, rules.LangGo)) {
		t.Error("Go file should not be frontend JS")
	}
	// Browser JS using DOM APIs and no server-side APIs -> frontend.
	fe := `document.querySelector('#x'); window.addEventListener('load', () => {});`
	if !isFrontendJSFile(ctxFor("/static/app.js", fe, rules.LangJavaScript)) {
		t.Error("DOM-only JS should be detected as frontend")
	}
}

// ==========================================================================
// Rule metadata sanity (each rule reports a stable, distinct identity)
// ==========================================================================

func TestRuleMetadata(t *testing.T) {
	type ruleMeta interface {
		ID() string
		Name() string
		Description() string
		DefaultSeverity() rules.Severity
		Languages() []rules.Language
	}
	all := []ruleMeta{
		&MissingCSP{}, &MissingXFrameOptions{}, &MissingXContentTypeOptions{},
		&MissingHSTS{}, &PermissiveCSP{}, &MissingXXSSProtection{},
		&MissingReferrerPolicy{}, &MissingPermissionsPolicy{},
		&CacheControlSensitive{}, &ServerHeaderDisclosure{},
		&XPoweredByDisclosure{}, &CRLFHeaderInjection{},
	}
	seen := map[string]bool{}
	for _, r := range all {
		id := r.ID()
		if !strings.HasPrefix(id, "BATOU-HDR-") {
			t.Errorf("rule %T has unexpected ID prefix: %q", r, id)
		}
		if seen[id] {
			t.Errorf("duplicate rule ID %q", id)
		}
		seen[id] = true
		if r.Name() == "" {
			t.Errorf("rule %s has empty Name()", id)
		}
		if r.Description() == "" {
			t.Errorf("rule %s has empty Description()", id)
		}
		if len(r.Languages()) == 0 {
			t.Errorf("rule %s declares no languages", id)
		}
	}
	if len(seen) != 12 {
		t.Errorf("expected 12 distinct header rule IDs, got %d", len(seen))
	}
}
