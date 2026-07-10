package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ==========================================================================
// C / C++ libcurl SSRF tests (CWE-918).
//
// These exercise the revival of catalog sinks whose MethodName was a
// descriptive label ("curl_easy_setopt(CURLOPT_URL)", "curl_url_set(CURLUPART_URL)").
// The tsflow matcher keys sinks on the bare call token extracted from
// MethodName, and a label containing "(...)" reduces to an unmatchable key —
// so before the fix these sinks were registered under a dead key and could
// never match a real `curl_easy_setopt(...)` call (zero dataflow findings).
// After re-keying MethodName to the bare call token (the tight Pattern still
// disambiguates CURLOPT_URL vs PROXY vs RESOLVE via weakSinkPatternOK), the
// genuine SSRF flow is detected. Reverting the catalog (restoring the
// descriptive MethodName) makes every _Tainted case below fail.
// ==========================================================================

// hasURLFetchFlowConf reports whether any flow is a url_fetch (SSRF) sink whose
// confidence is at least minConf.
func hasURLFetchFlowConf(flows []taint.TaintFlow, minConf float64) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence >= minConf {
			return true
		}
	}
	return false
}

func TestC_CurlSetoptURL_Tainted(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <stdlib.h>

void do_fetch(CURL *h) {
    char *u = getenv("QUERY_STRING");
    curl_easy_setopt(h, CURLOPT_URL, u);
}
`
	flows := Analyze(code, "/app/fetch.c", rules.LangC)
	if !hasURLFetchFlowConf(flows, 0.85) {
		t.Error("expected SSRF flow (conf>=0.85) for getenv -> curl_easy_setopt(CURLOPT_URL)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_CurlSetoptProxy_Tainted(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <stdlib.h>

void do_fetch(CURL *h) {
    char *p = getenv("QUERY_STRING");
    curl_easy_setopt(h, CURLOPT_PROXY, p);
}
`
	flows := Analyze(code, "/app/fetch.c", rules.LangC)
	if !hasURLFetchFlowConf(flows, 0.85) {
		t.Error("expected SSRF flow (conf>=0.85) for getenv -> curl_easy_setopt(CURLOPT_PROXY)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_CurlSetoptResolve_Tainted(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <stdlib.h>

void do_fetch(CURL *h) {
    char *r = getenv("QUERY_STRING");
    curl_easy_setopt(h, CURLOPT_RESOLVE, r);
}
`
	flows := Analyze(code, "/app/fetch.c", rules.LangC)
	if !hasURLFetchFlowConf(flows, 0.85) {
		t.Error("expected SSRF flow (conf>=0.85) for getenv -> curl_easy_setopt(CURLOPT_RESOLVE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_CurlURLSet_Tainted(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <stdlib.h>

void do_fetch(CURLU *cu) {
    char *u = getenv("QUERY_STRING");
    curl_url_set(cu, CURLUPART_URL, u, 0);
}
`
	flows := Analyze(code, "/app/fetch.c", rules.LangC)
	if !hasURLFetchFlowConf(flows, 0.85) {
		t.Error("expected SSRF flow (conf>=0.85) for getenv -> curl_url_set(CURLUPART_URL)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_CurlSetoptURL_Safe(t *testing.T) {
	// A hardcoded internal URL is not attacker-controlled — no SSRF flow.
	code := `
#include <curl/curl.h>

void do_fetch(CURL *h) {
    const char *u = "https://api.internal.example.com/v1";
    curl_easy_setopt(h, CURLOPT_URL, u);
}
`
	flows := Analyze(code, "/app/fetch.c", rules.LangC)
	if hasURLFetchFlowConf(flows, 0.0) {
		t.Error("expected NO SSRF flow when the URL is a string literal")
	}
}

func TestCPP_CurlSetoptURL_Tainted(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <cstdlib>

void do_fetch(CURL *h) {
    char *u = getenv("QUERY_STRING");
    curl_easy_setopt(h, CURLOPT_URL, u);
}
`
	flows := Analyze(code, "/app/fetch.cpp", rules.LangCPP)
	if !hasURLFetchFlowConf(flows, 0.85) {
		t.Error("expected SSRF flow (conf>=0.85) for getenv -> curl_easy_setopt(CURLOPT_URL) [C++]")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_CurlSetoptURL_Safe(t *testing.T) {
	code := `
#include <curl/curl.h>

void do_fetch(CURL *h) {
    const char *u = "https://api.internal.example.com/v1";
    curl_easy_setopt(h, CURLOPT_URL, u);
}
`
	flows := Analyze(code, "/app/fetch.cpp", rules.LangCPP)
	if hasURLFetchFlowConf(flows, 0.0) {
		t.Error("expected NO SSRF flow when the URL is a string literal [C++]")
	}
}
