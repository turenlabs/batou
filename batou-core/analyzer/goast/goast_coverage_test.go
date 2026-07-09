package goast

import (
	"strings"
	"testing"
)

func hasFindingCWE(t *testing.T, code, ruleID, cwe string) bool {
	t.Helper()
	for _, f := range scanGo(code) {
		if f.RuleID == ruleID && f.CWEID == cwe {
			return true
		}
	}
	return false
}

func hasRule(code, ruleID string) bool {
	for _, f := range scanGo(code) {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// =========================================================================
// BATOU-AST-012: Insecure cookie / session flags
// =========================================================================

func TestAST012_CookieMissingHttpOnly(t *testing.T) {
	code := `package main

import "net/http"

func login(w http.ResponseWriter) {
	c := &http.Cookie{Name: "session", Value: "abc123", Secure: true}
	http.SetCookie(w, c)
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-012", "CWE-1004") {
		t.Error("expected AST-012 CWE-1004 for http.Cookie missing HttpOnly")
	}
}

func TestAST012_CookieMissingSecure(t *testing.T) {
	code := `package main

import "net/http"

func login(w http.ResponseWriter) {
	c := &http.Cookie{Name: "session", Value: "abc123", HttpOnly: true}
	http.SetCookie(w, c)
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-012", "CWE-614") {
		t.Error("expected AST-012 CWE-614 for http.Cookie missing Secure")
	}
}

func TestAST012_CookieSecureFalse(t *testing.T) {
	code := `package main

import "net/http"

func login(w http.ResponseWriter) {
	c := &http.Cookie{Name: "session", Value: "abc123", HttpOnly: true, Secure: false}
	http.SetCookie(w, c)
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-012", "CWE-614") {
		t.Error("expected AST-012 CWE-614 for http.Cookie Secure:false")
	}
}

func TestAST012_CookieSameSiteNoneWithoutSecure(t *testing.T) {
	code := `package main

import "net/http"

func login(w http.ResponseWriter) {
	c := &http.Cookie{Name: "session", Value: "abc123", HttpOnly: true, SameSite: http.SameSiteNoneMode}
	http.SetCookie(w, c)
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-012", "CWE-1275") {
		t.Error("expected AST-012 CWE-1275 for SameSite=None without Secure")
	}
}

func TestAST012_SecureHttpOnlyCookie_Safe(t *testing.T) {
	code := `package main

import "net/http"

func login(w http.ResponseWriter) {
	c := &http.Cookie{Name: "session", Value: "abc123", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
	http.SetCookie(w, c)
}
`
	if hasRule(code, "BATOU-AST-012") {
		t.Error("did not expect AST-012 for a fully secure cookie")
	}
}

func TestAST012_SameSiteNoneWithSecure_Safe(t *testing.T) {
	code := `package main

import "net/http"

func login(w http.ResponseWriter) {
	c := &http.Cookie{Name: "csrf", Value: "abc123", HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode}
	http.SetCookie(w, c)
}
`
	if hasRule(code, "BATOU-AST-012") {
		t.Error("did not expect AST-012 for SameSite=None WITH Secure:true")
	}
}

func TestAST012_CookieDeletion_Safe(t *testing.T) {
	// Clearing a cookie (MaxAge < 0) does not require Secure/HttpOnly.
	code := `package main

import "net/http"

func logout(w http.ResponseWriter) {
	c := &http.Cookie{Name: "session", Value: "", MaxAge: -1}
	http.SetCookie(w, c)
}
`
	if hasRule(code, "BATOU-AST-012") {
		t.Error("did not expect AST-012 for a cookie-deletion literal (MaxAge:-1)")
	}
}

func TestAST012_BarePlaceholder_Safe(t *testing.T) {
	// A bare/partial literal that does not set Name+Value is not a cookie
	// being established here — skip to avoid FPs on field-assignment patterns.
	code := `package main

import "net/http"

func f() {
	c := &http.Cookie{Name: "session"}
	_ = c
}
`
	if hasRule(code, "BATOU-AST-012") {
		t.Error("did not expect AST-012 for a bare placeholder cookie literal")
	}
}

func TestAST012_UnrelatedStructWithSecureField_Safe(t *testing.T) {
	// A non-http.Cookie struct that happens to have Secure/HttpOnly fields
	// must NOT match — ObjectType anchoring.
	code := `package main

type Config struct {
	Name     string
	Value    string
	HttpOnly bool
	Secure   bool
}

func f() {
	c := Config{Name: "x", Value: "y", HttpOnly: false, Secure: false}
	_ = c
}
`
	if hasRule(code, "BATOU-AST-012") {
		t.Error("did not expect AST-012 on an unrelated struct with HttpOnly/Secure fields")
	}
}

func TestAST012_GorillaSessionsOptions(t *testing.T) {
	code := `package main

import "github.com/gorilla/sessions"

func opts() *sessions.Options {
	return &sessions.Options{Path: "/", MaxAge: 3600, HttpOnly: true}
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-012", "CWE-614") {
		t.Error("expected AST-012 CWE-614 for gorilla sessions.Options missing Secure")
	}
}

// =========================================================================
// BATOU-AST-013: net/http/pprof exposed
// =========================================================================

func TestAST013_PprofImport(t *testing.T) {
	code := `package main

import (
	"net/http"
	_ "net/http/pprof"
)

func main() {
	http.ListenAndServe(":6060", nil)
}
`
	if !hasRule(code, "BATOU-AST-013") {
		t.Error("expected AST-013 for blank import of net/http/pprof")
	}
}

func TestAST013_NoPprof_Safe(t *testing.T) {
	code := `package main

import "net/http"

func main() {
	http.ListenAndServe(":8080", nil)
}
`
	if hasRule(code, "BATOU-AST-013") {
		t.Error("did not expect AST-013 without net/http/pprof import")
	}
}

// =========================================================================
// BATOU-AST-014: net/http/cgi (httpoxy)
// =========================================================================

func TestAST014_CGIImport(t *testing.T) {
	code := `package main

import "net/http/cgi"

func run(h *cgi.Handler) {
	_ = h
}
`
	if !hasRule(code, "BATOU-AST-014") {
		t.Error("expected AST-014 for net/http/cgi import")
	}
}

func TestAST014_RuntimePprofNotCGI_Safe(t *testing.T) {
	code := `package main

import "runtime/pprof"

func f() {
	_ = pprof.Lookup("heap")
}
`
	if hasRule(code, "BATOU-AST-014") || hasRule(code, "BATOU-AST-013") {
		t.Error("did not expect AST-013/014 for runtime/pprof (not net/http/pprof or cgi)")
	}
}

// =========================================================================
// BATOU-AST-015: weak RSA key size
// =========================================================================

func TestAST015_RSA1024(t *testing.T) {
	code := `package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func gen() {
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-015", "CWE-326") {
		t.Error("expected AST-015 for rsa.GenerateKey with 1024 bits")
	}
}

func TestAST015_RSA2048_Safe(t *testing.T) {
	code := `package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func gen() {
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
}
`
	if hasRule(code, "BATOU-AST-015") {
		t.Error("did not expect AST-015 for rsa.GenerateKey with 2048 bits")
	}
}

func TestAST015_RSAVariableBits_Safe(t *testing.T) {
	// Non-literal bit count is out of scope for a constant-misconfig rule.
	code := `package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func gen(bits int) {
	_, _ = rsa.GenerateKey(rand.Reader, bits)
}
`
	if hasRule(code, "BATOU-AST-015") {
		t.Error("did not expect AST-015 for variable bit count")
	}
}

func TestAST015_UnrelatedGenerateKey_Safe(t *testing.T) {
	// ecdsa.GenerateKey / a custom GenerateKey are not crypto/rsa.
	code := `package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func gen() {
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
`
	if hasRule(code, "BATOU-AST-015") {
		t.Error("did not expect AST-015 for ecdsa.GenerateKey")
	}
}

// =========================================================================
// BATOU-AST-016: http.FileServer directory listing
// =========================================================================

func TestAST016_FileServerDir(t *testing.T) {
	code := `package main

import "net/http"

func mount(mux *http.ServeMux) {
	mux.Handle("/static/", http.FileServer(http.Dir("/var/www")))
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-016", "CWE-548") {
		t.Error("expected AST-016 for http.FileServer(http.Dir(...))")
	}
}

func TestAST016_FileServerFS_Safe(t *testing.T) {
	// http.FileServer(http.FS(embed)) does not autoindex from a real dir.
	code := `package main

import (
	"embed"
	"net/http"
)

var assets embed.FS

func mount(mux *http.ServeMux) {
	mux.Handle("/static/", http.FileServer(http.FS(assets)))
}
`
	if hasRule(code, "BATOU-AST-016") {
		t.Error("did not expect AST-016 for http.FileServer(http.FS(...))")
	}
}

// =========================================================================
// BATOU-AST-017: SHA-224 digest
// =========================================================================

func TestAST017_SHA224(t *testing.T) {
	code := `package main

import "crypto/sha256"

func digest(b []byte) [28]byte {
	return sha256.Sum224(b)
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-017", "CWE-328") {
		t.Error("expected AST-017 for sha256.Sum224")
	}
}

func TestAST017_SHA256_Safe(t *testing.T) {
	code := `package main

import "crypto/sha256"

func digest(b []byte) [32]byte {
	return sha256.Sum256(b)
}
`
	if hasRule(code, "BATOU-AST-017") {
		t.Error("did not expect AST-017 for sha256.Sum256")
	}
}

// =========================================================================
// BATOU-AST-018: ReverseProxy Director copies inbound host
// =========================================================================

func TestAST018_DirectorCopiesInboundHost(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/http/httputil"
)

func proxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
		},
	}
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-018", "CWE-918") {
		t.Error("expected AST-018 for Director copying req.Host into req.URL.Host")
	}
}

func TestAST018_FixedUpstreamDirector_Safe(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/http/httputil"
)

func proxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "backend.internal:8080"
		},
	}
}
`
	if hasRule(code, "BATOU-AST-018") {
		t.Error("did not expect AST-018 for a fixed-upstream Director")
	}
}

// =========================================================================
// BATOU-AST-019: bound to all interfaces (0.0.0.0)
// =========================================================================

func TestAST019_NetListenAllInterfaces(t *testing.T) {
	code := `package main

import "net"

func serve() {
	l, _ := net.Listen("tcp", "0.0.0.0:8080")
	_ = l
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-019", "CWE-200") {
		t.Error("expected AST-019 for net.Listen on 0.0.0.0")
	}
}

func TestAST019_ServerAddrAllInterfaces(t *testing.T) {
	code := `package main

import "net/http"

func serve() {
	s := &http.Server{Addr: "0.0.0.0:9090"}
	_ = s
}
`
	if !hasFindingCWE(t, code, "BATOU-AST-019", "CWE-200") {
		t.Error("expected AST-019 for http.Server.Addr on 0.0.0.0")
	}
}

func TestAST019_LocalhostBind_Safe(t *testing.T) {
	code := `package main

import "net"

func serve() {
	l, _ := net.Listen("tcp", "127.0.0.1:8080")
	_ = l
}
`
	if hasRule(code, "BATOU-AST-019") {
		t.Error("did not expect AST-019 for a localhost bind")
	}
}

func TestAST019_PortOnlyBind_Safe(t *testing.T) {
	// The idiomatic ":port" form is the common default and is NOT flagged.
	code := `package main

import "net"

func serve() {
	l, _ := net.Listen("tcp", ":8080")
	_ = l
}
`
	if hasRule(code, "BATOU-AST-019") {
		t.Error("did not expect AST-019 for the idiomatic :port form")
	}
}

func TestAST019_VariableAddr_Safe(t *testing.T) {
	code := `package main

import "net"

func serve(addr string) {
	l, _ := net.Listen("tcp", addr)
	_ = l
}
`
	if hasRule(code, "BATOU-AST-019") {
		t.Error("did not expect AST-019 for a variable address")
	}
}

func TestAST018_DescriptionMentionsSSRF(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/http/httputil"
)

func proxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = r.Host
		},
	}
}
`
	var got string
	for _, f := range scanGo(code) {
		if f.RuleID == "BATOU-AST-018" {
			got = f.Description
		}
	}
	if !strings.Contains(strings.ToLower(got), "forgery") && !strings.Contains(strings.ToLower(got), "upstream") {
		t.Errorf("AST-018 description should explain the SSRF risk, got: %q", got)
	}
}
