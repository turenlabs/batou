package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasRedirectFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			return true
		}
	}
	return false
}

// Load-bearing FP test: cleanPath() (the httprouter/gin URL-path canonicalizer)
// forces a single-slash-rooted path, so a redirect target derived from
// req.URL.Path and passed through cleanPath cannot retarget an external host.
// The CWE-601 flow must be suppressed.
func TestAnalyzeGo_CleanPath_Redirect_Sanitized(t *testing.T) {
	code := `package main

import "net/http"

func redirect(w http.ResponseWriter, req *http.Request) {
	rPath := req.URL.Path
	target := cleanPath(rPath)
	http.Redirect(w, req, target, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/router.go")
	if hasRedirectFlow(flows) {
		t.Error("expected cleanPath() to neutralize the open-redirect flow (output is single-slash-rooted, cannot reach an external host)")
		for _, f := range flows {
			t.Logf("  flow -> %s (conf %.2f)", f.Sink.Category, f.Confidence)
		}
	}
}

// Positive control: WITHOUT cleanPath the same req.URL.Path -> http.Redirect
// flow MUST still fire, proving the suppression above is load-bearing on the
// sanitizer call, not on some unrelated shape difference.
func TestAnalyzeGo_RawURLPath_Redirect_StillFlags(t *testing.T) {
	code := `package main

import "net/http"

func redirect(w http.ResponseWriter, req *http.Request) {
	target := req.URL.Path
	http.Redirect(w, req, target, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/router_unsafe.go")
	if !hasRedirectFlow(flows) {
		t.Error("expected raw req.URL.Path -> http.Redirect to flag open redirect (no sanitizer)")
	}
}
