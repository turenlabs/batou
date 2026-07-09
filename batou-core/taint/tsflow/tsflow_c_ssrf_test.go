package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C SSRF / URL fetch sink tests — libsoup, libcurl extras, WinINet/WinHTTP,
// POSIX DNS resolver. Companion to tsflow_c_ssh_test.go (which already
// covers libssh2/libssh tunnel SSRF).
// =========================================================================

func TestC_SoupMessageNew_SSRF(t *testing.T) {
	code := `
#include <libsoup/soup.h>
#include <stdlib.h>

void fetch_user_url(SoupSession *session) {
    char *url = getenv("TARGET_URL");
    SoupMessage *msg = soup_message_new("GET", url);
    soup_session_send_message(session, msg);
}
`
	flows := Analyze(code, "/app/soup_fetch.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> soup_message_new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SoupUriNew_SSRF(t *testing.T) {
	code := `
#include <libsoup/soup.h>
#include <stdlib.h>

void parse_user_uri(void) {
    char *uri = getenv("USER_URI");
    SoupURI *parsed = soup_uri_new(uri);
    (void)parsed;
}
`
	flows := Analyze(code, "/app/soup_uri.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> soup_uri_new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SoupSessionRequest_SSRF(t *testing.T) {
	code := `
#include <libsoup/soup.h>
#include <stdlib.h>

void request_user_url(SoupSession *session) {
    char *url = getenv("FEED_URL");
    SoupRequest *req = soup_session_request(session, url, NULL);
    (void)req;
}
`
	flows := Analyze(code, "/app/soup_request.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> soup_session_request")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SoupMessageNewFromUri_SSRF(t *testing.T) {
	code := `
#include <libsoup/soup.h>
#include <stdlib.h>

void fetch_from_uri(SoupSession *session) {
    char *user_uri = getenv("FEED_URI");
    SoupURI *uri = soup_uri_new(user_uri);
    SoupMessage *msg = soup_message_new_from_uri("GET", uri);
    (void)msg;
}
`
	flows := Analyze(code, "/app/soup_msg_uri.c", rules.LangC)
	// Either soup_uri_new or soup_message_new_from_uri should trip the SSRF flow.
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> soup_message_new_from_uri")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_InternetOpenUrl_SSRF(t *testing.T) {
	code := `
#include <windows.h>
#include <wininet.h>
#include <stdlib.h>

void download(HINTERNET h) {
    char *url = getenv("DOWNLOAD_URL");
    HINTERNET req = InternetOpenUrlA(h, url, NULL, 0, 0, 0);
    (void)req;
}
`
	flows := Analyze(code, "/app/wininet_open.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> InternetOpenUrlA")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_HttpOpenRequest_SSRF(t *testing.T) {
	code := `
#include <windows.h>
#include <wininet.h>
#include <stdlib.h>

void open_request(HINTERNET h) {
    char *path = getenv("REQ_PATH");
    HINTERNET req = HttpOpenRequestA(h, "GET", path, NULL, NULL, NULL, 0, 0);
    (void)req;
}
`
	flows := Analyze(code, "/app/wininet_request.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> HttpOpenRequestA")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_WinHttpConnect_SSRF(t *testing.T) {
	code := `
#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>

void connect_target(HINTERNET h) {
    char *host = getenv("TARGET_HOST");
    HINTERNET conn = WinHttpConnect(h, host, 80, 0);
    (void)conn;
}
`
	flows := Analyze(code, "/app/winhttp_connect.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> WinHttpConnect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ResQuery_SSRF(t *testing.T) {
	code := `
#include <resolv.h>
#include <stdlib.h>

void resolve(unsigned char *ans, int anslen) {
    char *domain = getenv("LOOKUP_DOMAIN");
    res_query(domain, 1, 1, ans, anslen);
}
`
	flows := Analyze(code, "/app/dns_query.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> res_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ResSearch_SSRF(t *testing.T) {
	code := `
#include <resolv.h>
#include <stdlib.h>

void search_dns(unsigned char *ans, int anslen) {
    char *name = getenv("LOOKUP_NAME");
    res_search(name, 1, 1, ans, anslen);
}
`
	flows := Analyze(code, "/app/dns_search.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> res_search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: hardcoded constants should NOT trigger an SSRF finding even
// though the sink functions are invoked. (Soup is the simplest because it has
// the cleanest tsflow integration of the new entries.)
func TestC_SoupMessageNew_HardcodedURL_NoFlow(t *testing.T) {
	code := `
#include <libsoup/soup.h>

void fetch_known(SoupSession *session) {
    SoupMessage *msg = soup_message_new("GET", "https://api.example.com/health");
    soup_session_send_message(session, msg);
}
`
	flows := Analyze(code, "/app/soup_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("did not expect SSRF flow for hardcoded URL in soup_message_new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
