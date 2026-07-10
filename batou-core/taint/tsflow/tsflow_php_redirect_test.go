package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP redirect sink tests — wp_redirect, wp_safe_redirect, http_redirect,
// header(Refresh:), PSR-7 withRedirect, Laravel Redirect::to
// =========================================================================

func TestPHP_Redirect_WpRedirect(t *testing.T) {
	code := `<?php
function handle_login() {
    $url = $_GET["redirect_to"];
    wp_redirect($url);
    exit;
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for $_GET -> wp_redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redirect_WpSafeRedirect(t *testing.T) {
	code := `<?php
function handle_login() {
    $url = $_GET["redirect_to"];
    wp_safe_redirect($url);
    exit;
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for $_GET -> wp_safe_redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redirect_HttpRedirect(t *testing.T) {
	code := `<?php
function handle_callback() {
    $url = $_POST["return_url"];
    http_redirect($url, array(), true, HTTP_REDIRECT_FOUND);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for $_POST -> http_redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redirect_HeaderRefresh(t *testing.T) {
	// header("Refresh: 0; url=<tainted>") is an open redirect (CWE-601). The
	// php.header.refresh sink is now keyed under MethodName "header" and ordered
	// ahead of the generic CWE-113 php.header sink, so tsflow classifies it as
	// SnkRedirect (CWE-601) at dataflow tier — not merely SnkHeader. (Previously
	// the sink was keyed under a parenthesised "header(Refresh)" name no call node
	// ever has, leaving it dead, so only the generic header-injection sink fired.)
	code := `<?php
function handle_redirect() {
    $url = $_GET["next"];
    header("Refresh: 0; url=" . $url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect (CWE-601) flow for $_GET -> header(Refresh:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// header("Location: <tainted>") is the canonical PHP open redirect (CWE-601) —
// the form DVWA's open_redirect and file-inclusion modules use. Before the
// keying/ordering/case fix the php.header.location sink was dead (keyed under
// "header(Location)") and only the generic CWE-113 php.header header-injection
// sink fired. These three cases assert the SnkRedirect classification now
// reaches dataflow tier for the canonical, lowercase, and spaced call forms.
func TestPHP_Redirect_HeaderLocation_Canonical(t *testing.T) {
	code := `<?php
function go() {
    $url = $_GET["next"];
    header("Location: " . $url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect (CWE-601) flow for $_GET -> header(\"Location: \")")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redirect_HeaderLocation_Lowercase(t *testing.T) {
	// HTTP header names are case-insensitive; real code (and DVWA's
	// open_redirect/low.php) writes the name lowercase with a space before "(".
	code := `<?php
function go() {
    $file = $_GET["page"];
    header ("location: " . $file);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect (CWE-601) flow for $_GET -> header(\"location: \") (lowercase, spaced)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: a hardcoded Location target carries no taint, so no redirect flow.
func TestPHP_Redirect_HeaderLocation_HardcodedURL(t *testing.T) {
	code := `<?php
function go() {
    header("Location: /dashboard");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("hardcoded Location header should not produce a redirect taint flow")
	}
}

// Safe: an allowlist-checked value (in_array) before the redirect is not an
// open redirect. The DVWA fi/impossible.php hardening shape.
func TestPHP_Redirect_HeaderLocation_Allowlist(t *testing.T) {
	code := `<?php
function go() {
    $page = $_GET["page"];
    $allowed = array("home.php", "about.php");
    if (in_array($page, $allowed)) {
        header("Location: " . $page);
    }
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("in_array-allowlisted page in Location header should not produce a redirect taint flow")
	}
}

// Precision: a plain header() call whose name is NOT Location/Refresh (e.g.
// Content-Type) must remain a CWE-113 header-injection sink (SnkHeader), not be
// misclassified as an open redirect. Confirms the ordering disambiguation —
// php.header.location/refresh only win when the header value matches.
func TestPHP_Redirect_HeaderContentType_NotRedirect(t *testing.T) {
	code := `<?php
function emit() {
    $ct = $_GET["ct"];
    header("Content-Type: " . $ct);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("header(\"Content-Type: \") must not be classified as an open redirect")
	}
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("header(\"Content-Type: \") should still be a header-injection (CWE-113) sink")
	}
}

func TestPHP_Redirect_Psr7WithRedirect(t *testing.T) {
	code := `<?php
function handle($request, $response) {
    $url = $_GET["next"];
    return $response->withRedirect($url, 302);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for $_GET -> withRedirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Redirect_LaravelFacade(t *testing.T) {
	code := `<?php
function handle() {
    $url = $_GET["next"];
    return Redirect::to($url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for $_GET -> Redirect::to")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe variants — should NOT produce redirect flows

func TestPHP_Redirect_WpRedirect_HardcodedURL(t *testing.T) {
	code := `<?php
function handle_login() {
    wp_redirect("/dashboard");
    exit;
}
?>`
	flows := Analyze(code, "/app/plugin.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("hardcoded URL in wp_redirect should not produce redirect taint flow")
	}
}

func TestPHP_Redirect_LaravelFacade_HardcodedURL(t *testing.T) {
	code := `<?php
function handle() {
    return Redirect::to("/home");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("hardcoded URL in Redirect::to should not produce redirect taint flow")
	}
}
