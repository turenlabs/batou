package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go safehtml URL-sanitizer tests (github.com/google/safehtml).
//
// Completes the safehtml family — previously only safehtml.HTMLEscaped was
// modeled. URLSanitized / URLSetSanitized apply a scheme allowlist that
// neutralizes dangerous-scheme XSS (javascript:, vbscript:, data:text/html,
// file:) when a tainted URL is rendered into an href/src/srcset attribute.
//
//   go.safehtml.urlsanitized      safehtml.URLSanitized(url) -> SnkHTMLOutput
//   go.safehtml.urlsetsanitized   safehtml.URLSetSanitized(s) -> SnkHTMLOutput
// =========================================================================

func TestCatalogMatcher_SafehtmlURLSanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sanitizers := cat.Sanitizers()
	matcher := NewCatalogMatcher(nil, nil, sanitizers, nil)

	expected := map[string]string{
		"go.safehtml.urlsanitized":    "URLSanitized",
		"go.safehtml.urlsetsanitized": "URLSetSanitized",
	}

	for id, method := range expected {
		found := false
		for _, s := range matcher.sanitizersByMethod[method] {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sanitizer %q to be indexed by method %q", id, method)
		}
	}
}

// --- safehtml.URLSanitized ---

func TestAnalyzeGo_SafehtmlURLSanitized_NeutralizesXSS(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/google/safehtml"
)

func handler(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	safe := safehtml.URLSanitized(next)
	w.Write([]byte(safe))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTMLOutput flow when safehtml.URLSanitized is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SafehtmlURLSanitized_NoSanitizer_StillFlags(t *testing.T) {
	code := `package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	w.Write([]byte(next))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HTMLOutput flow without sanitizer (negative control)")
	}
}

// --- safehtml.URLSetSanitized ---

func TestAnalyzeGo_SafehtmlURLSetSanitized_NeutralizesXSS(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/google/safehtml"
)

func handler(w http.ResponseWriter, r *http.Request) {
	srcset := r.FormValue("srcset")
	safe := safehtml.URLSetSanitized(srcset)
	w.Write([]byte(safe))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTMLOutput flow when safehtml.URLSetSanitized is used; got id=%s", f.Sink.ID)
		}
	}
}
