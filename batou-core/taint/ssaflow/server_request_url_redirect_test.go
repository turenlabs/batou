package ssaflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"

	// Register Go language catalog so source/sink/sanitizer lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasRedirectFlowSSA(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			return true
		}
	}
	return false
}

// Load-bearing FP test. A redirect target rendered from a *net/http.Request's
// own URL — req.URL.String() — is a same-origin relative path (the net/http
// server never sets Scheme/Host on a server request URL), so feeding it to
// http.Redirect is not an open redirect. This is gin's redirectRequest shape
// (req := c.Request; rURL := req.URL.String(); http.Redirect(..., rURL, ...)).
// The CWE-601 flow must be pruned by callIsServerRequestURLRedirectSafe.
func TestSSA_ServerRequestURLString_Redirect_SameOrigin(t *testing.T) {
	code := `package main

import "net/http"

func redirectRequest(w http.ResponseWriter, req *http.Request) {
	rURL := req.URL.String()
	http.Redirect(w, req, rURL, http.StatusMovedPermanently)
}
`
	flows := AnalyzeGo(code, "/app/router.go")
	if hasRedirectFlowSSA(flows) {
		t.Error("expected req.URL.String() -> http.Redirect to be pruned as same-origin (server request URL has no Scheme/Host)")
		for _, f := range flows {
			t.Logf("  flow -> %s (conf %.2f)", f.Sink.Category, f.Confidence)
		}
	}
}

// Positive control A: a redirect target read from a request query value is
// attacker-controllable (the client can supply an absolute URL), so it MUST
// still flag. This proves the prune is provenance-scoped to the .URL field
// render, not a blanket suppression of every redirect off an *http.Request.
func TestSSA_QueryParam_Redirect_StillFlags(t *testing.T) {
	code := `package main

import "net/http"

func redirectNext(w http.ResponseWriter, req *http.Request) {
	target := req.URL.Query().Get("next")
	http.Redirect(w, req, target, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/router_query.go")
	if !hasRedirectFlowSSA(flows) {
		t.Error("expected req.URL.Query().Get(\"next\") -> http.Redirect to flag open redirect (attacker-controlled absolute URL)")
	}
}
