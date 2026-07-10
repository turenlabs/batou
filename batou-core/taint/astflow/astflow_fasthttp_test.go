package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestAnalyzeGo_Fasthttp_SSRF_Get verifies that fasthttp.Get with a tainted URL
// derived from a fasthttp RequestCtx source flows to the SSRF sink.
func TestAnalyzeGo_Fasthttp_SSRF_Get(t *testing.T) {
	code := `package main

import (
	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	raw := ctx.FormValue("target")
	url := string(raw)
	_, _, _ = fasthttp.Get(nil, url)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF taint flow for ctx.FormValue -> fasthttp.Get, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Fasthttp_SSRF_Post verifies that fasthttp.Post with a tainted URL
// flows to the SSRF sink.
func TestAnalyzeGo_Fasthttp_SSRF_Post(t *testing.T) {
	code := `package main

import (
	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	raw := ctx.PostBody()
	url := string(raw)
	_, _, _ = fasthttp.Post(nil, url, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF taint flow for ctx.PostBody -> fasthttp.Post, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Fasthttp_SSRF_GetTimeout verifies that fasthttp.GetTimeout with a
// tainted URL flows to the SSRF sink.
func TestAnalyzeGo_Fasthttp_SSRF_GetTimeout(t *testing.T) {
	code := `package main

import (
	"time"

	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	raw := ctx.RequestURI()
	url := string(raw)
	_, _, _ = fasthttp.GetTimeout(nil, url, 5*time.Second)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF taint flow for ctx.RequestURI -> fasthttp.GetTimeout, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Fasthttp_OpenRedirect verifies that ctx.Redirect with a tainted
// URL flows to the open-redirect sink.
func TestAnalyzeGo_Fasthttp_OpenRedirect(t *testing.T) {
	code := `package main

import (
	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	raw := ctx.FormValue("next")
	target := string(raw)
	ctx.Redirect(target, fasthttp.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Errorf("expected open-redirect flow for ctx.FormValue -> ctx.Redirect, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Fasthttp_XSS_SetBodyString verifies that ctx.SetBodyString with a
// tainted input flows to the HTML-output (XSS) sink.
func TestAnalyzeGo_Fasthttp_XSS_SetBodyString(t *testing.T) {
	code := `package main

import (
	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	raw := ctx.FormValue("name")
	name := string(raw)
	ctx.SetBodyString("<h1>Hello, " + name + "</h1>")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("expected XSS flow for ctx.FormValue -> ctx.SetBodyString, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Fasthttp_UserAgentSource verifies that ctx.UserAgent is recognized
// as a user-input source (flowing to any sink).
func TestAnalyzeGo_Fasthttp_UserAgentSource(t *testing.T) {
	code := `package main

import (
	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	raw := ctx.UserAgent()
	ua := string(raw)
	ctx.SetBodyString(ua)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSourceCategory(flows, taint.SrcUserInput) {
		t.Errorf("expected SrcUserInput flow for ctx.UserAgent -> ctx.SetBodyString, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Fasthttp_SafePackageCall_NoFalsePositive verifies that a
// hardcoded URL in fasthttp.Get does not produce a finding.
func TestAnalyzeGo_Fasthttp_SafePackageCall_NoFalsePositive(t *testing.T) {
	code := `package main

import (
	"github.com/valyala/fasthttp"
)

func handler(ctx *fasthttp.RequestCtx) {
	_, _, _ = fasthttp.Get(nil, "https://example.com/api")
	ctx.SetBodyString("ok")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO SSRF flow for hardcoded URL, got sink=%s source=%s", f.Sink.ID, f.Source.ID)
		}
	}
}
