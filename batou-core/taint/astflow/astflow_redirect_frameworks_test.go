package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
)

// These tests cover open-redirect sinks added for Go web frameworks beyond
// the core net/http/Gin/Echo/Fiber set: fasthttp.RedirectBytes, iris,
// and buffalo. They also exercise the matcher fix that enables
// receiver-type-precise sink matching for frameworks that share the
// "Redirect" method name.

func TestAnalyzeGo_FasthttpRedirectBytes(t *testing.T) {
	code := `package main

import (
	"io"
	"os"

	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	f, _ := os.Open("/etc/motd")
	b, _ := io.ReadAll(f)
	ctx.RedirectBytes(b, fasthttp.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect taint flow for fasthttp ctx.RedirectBytes(tainted, code)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisRedirect(t *testing.T) {
	code := `package main

import (
	"os"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	target := os.Getenv("REDIRECT_TARGET")
	ctx.Redirect(target, 302)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect taint flow for iris ctx.Redirect(tainted, code)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_BuffaloRedirect(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"

	"github.com/gobuffalo/buffalo"
)

func handler(c buffalo.Context) error {
	target := os.Getenv("REDIRECT_TARGET")
	return c.Redirect(http.StatusFound, target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect taint flow for buffalo c.Redirect(code, tainted)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// TestAnalyzeGo_GinRedirect_Matcher verifies the matcher fix: a method call
// on a typed receiver no longer falls through to the package-level
// go.http.redirect sink (which has DangerousArgs=[2] and would silently
// swallow Gin's two-arg signature). Before the fix, this test would return
// zero flows.
func TestAnalyzeGo_GinRedirect_Matcher(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func handler(c *gin.Context) {
	target := os.Getenv("REDIRECT_TARGET")
	c.Redirect(http.StatusFound, target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect taint flow for gin c.Redirect(code, tainted) — matcher fix regression?")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
