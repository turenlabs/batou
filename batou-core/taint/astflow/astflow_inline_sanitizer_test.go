package astflow

import (
	"testing"

	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// redirectFlows reports whether AnalyzeGo finds a redirect (CWE-601) flow for
// the given source. Reuses hasRedirectFlow (astflow_cleanpath_redirect_test.go).
func redirectFlows(code string) bool {
	return hasRedirectFlow(AnalyzeGo(code, "/app/handler.go"))
}

// A sanitizer (url.QueryEscape / url.PathEscape / util.PathEscapeSegments)
// applied INLINE inside a redirect sink call neutralizes the open-redirect for
// that argument exactly as it would on an assignment RHS. This is the precision
// fix: astflow previously only applied sanitizers on assignment and fired a
// false block here.
func TestAnalyzeGo_InlineSanitizer_QueryEscapeAtRedirect_NoFlow(t *testing.T) {
	code := `package main

func handler(ctx *Context) {
	q := ctx.FormString("q")
	ctx.Redirect(url.QueryEscape(q))
}
`
	if redirectFlows(code) {
		t.Error("expected NO redirect flow when url.QueryEscape wraps the tainted value inline at the sink")
	}
}

func TestAnalyzeGo_InlineSanitizer_PathEscapeAtRedirect_NoFlow(t *testing.T) {
	code := `package main

func handler(ctx *Context) {
	ctx.Redirect(setting.AppSubURL + "/-/admin/users/" + url.PathEscape(ctx.PathParam("userid")))
}
`
	if redirectFlows(code) {
		t.Error("expected NO redirect flow when url.PathEscape wraps the tainted value inline at the sink")
	}
}

func TestAnalyzeGo_InlineSanitizer_PathEscapeSegmentsAtRedirect_NoFlow(t *testing.T) {
	code := `package main

func handler(ctx *Context) {
	branch := ctx.FormString("branch")
	ctx.Redirect(ctx.Repo.RepoLink + "/branches/" + util.PathEscapeSegments(branch))
}
`
	if redirectFlows(code) {
		t.Error("expected NO redirect flow when util.PathEscapeSegments wraps the tainted value inline at the sink")
	}
}

// TP preservation: a raw tainted value passed straight to the redirect sink
// (no sanitizer) must STILL fire.
func TestAnalyzeGo_InlineSanitizer_RawTaintedRedirect_FlowPresent(t *testing.T) {
	code := `package main

func handler(ctx *Context) {
	q := ctx.FormString("q")
	ctx.Redirect(q)
}
`
	if !redirectFlows(code) {
		t.Error("expected a redirect flow for raw tainted value passed directly to the sink (no sanitizer)")
	}
}

// TP preservation: a sibling escape over a CONSTANT does not neutralize the
// tainted operand concatenated next to it — url.QueryEscape("const") + tainted
// must STILL fire.
func TestAnalyzeGo_InlineSanitizer_SiblingEscapeOverConstant_FlowPresent(t *testing.T) {
	code := `package main

func handler(ctx *Context) {
	q := ctx.FormString("q")
	ctx.Redirect(url.QueryEscape("constant") + q)
}
`
	if !redirectFlows(code) {
		t.Error("expected a redirect flow when the escape wraps only a constant and the tainted operand is a bare sibling")
	}
}
