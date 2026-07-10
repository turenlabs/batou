package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

func TestAnalyzeGo_OpenRedirect_HTTPRedirectHandler(t *testing.T) {
	code := `package main

import "net/http"

func register(r *http.Request) http.Handler {
	target := r.FormValue("next")
	return http.RedirectHandler(target, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.http.redirecthandler") {
		t.Errorf("expected go.http.redirecthandler sink for FormValue -> http.RedirectHandler; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_OpenRedirect_FiberRedirectRoute(t *testing.T) {
	code := `package main

import "github.com/gofiber/fiber/v3"

func handler(c fiber.Ctx) error {
	name := c.Query("route")
	return c.Redirect().Route(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.fiber.redirect.route") {
		t.Errorf("expected go.fiber.redirect.route sink for Query -> Redirect().Route; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_OpenRedirect_FiberRedirectBack(t *testing.T) {
	code := `package main

import "github.com/gofiber/fiber/v3"

func handler(c fiber.Ctx) error {
	fallback := c.Query("fallback")
	return c.Redirect().Back(fallback)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.fiber.redirect.back") {
		t.Errorf("expected go.fiber.redirect.back sink for Query -> Redirect().Back; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Safe fixture: url.Parse validates host before http.RedirectHandler — should NOT fire.
func TestAnalyzeGo_SafeRedirect_RedirectHandler_URLParse(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/url"
)

func register(r *http.Request) http.Handler {
	target := r.FormValue("next")
	u, err := url.Parse(target)
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.RedirectHandler(u.Path, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.http.redirecthandler" {
			t.Errorf("expected url.Parse to sanitize before RedirectHandler, but flow was found: %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}
