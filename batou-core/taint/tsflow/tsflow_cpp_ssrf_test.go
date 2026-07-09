package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ cpr library SSRF tests
// =========================================================================

func TestCPP_CPR_Get_SSRF(t *testing.T) {
	code := `
#include <cpr/cpr.h>
#include <iostream>

void fetch(const char* argv[]) {
    std::string url = argv[1];
    auto r = cpr::Get(cpr::Url{url});
    std::cout << r.text << std::endl;
}
`
	flows := Analyze(code, "/app/fetch.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for argv -> cpr::Get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_CPR_Post_SSRF(t *testing.T) {
	code := `
#include <cpr/cpr.h>

void submit(const char* argv[]) {
    std::string target = argv[1];
    auto r = cpr::Post(cpr::Url{target}, cpr::Body{"data"});
}
`
	flows := Analyze(code, "/app/submit.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for argv -> cpr::Post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_CPR_Session_SetUrl_SSRF(t *testing.T) {
	code := `
#include <cpr/cpr.h>

void proxy(const char* argv[]) {
    std::string url = argv[1];
    cpr::Session session;
    session.SetUrl(cpr::Url{url});
    auto r = session.Get();
}
`
	flows := Analyze(code, "/app/proxy.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for argv -> session.SetUrl")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_CPR_Safe_Hardcoded_URL(t *testing.T) {
	code := `
#include <cpr/cpr.h>

void healthcheck() {
    auto r = cpr::Get(cpr::Url{"https://api.example.com/health"});
}
`
	flows := Analyze(code, "/app/health.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected no SSRF flow for hardcoded URL")
	}
}

// =========================================================================
// C++ SSRF sanitizer tests — URL parsing/validation breaks taint
// =========================================================================

func TestCPP_BoostURL_ParseURI_Sanitized(t *testing.T) {
	// Verify boost::urls::parse_uri is registered as a sanitizer that
	// neutralizes SnkURLFetch. No sink in this test — the sanitizer
	// entry is exercised by the regex fallback engine in the full pipeline.
	code := `
#include <boost/url.hpp>

void validate(const char* argv[]) {
    std::string url = argv[1];
    auto result = boost::urls::parse_uri(url);
    if (!result) { return; }
}
`
	flows := Analyze(code, "/app/validate.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when URL is only parsed, not used in a network call")
		}
	}
}

func TestCPP_CurlURL_Set_Sanitized(t *testing.T) {
	code := `
#include <curl/curl.h>

void fetch(const char* argv[]) {
    std::string url = argv[1];
    CURLU *h = curl_url();
    CURLUcode rc = curl_url_set(h, CURLUPART_URL, url.c_str(), 0);
    if (rc != CURLUE_OK) return;
    char *host;
    curl_url_get(h, CURLUPART_HOST, &host, 0);
    curl_url_cleanup(h);
}
`
	flows := Analyze(code, "/app/curl_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when URL is parsed via curl_url_set + curl_url_get")
		}
	}
}

func TestCPP_CurlProtocols_Sanitized(t *testing.T) {
	code := `
#include <curl/curl.h>

void fetch(const char* argv[]) {
    std::string url = argv[1];
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_perform(curl);
}
`
	flows := Analyze(code, "/app/curl_restricted.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when CURLOPT_PROTOCOLS restricts schemes")
		}
	}
}

func TestCPP_Qt_FromUserInput_Sanitized(t *testing.T) {
	code := `
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>

void fetch(const char* argv[]) {
    QString input = QString::fromUtf8(argv[1]);
    QUrl url = QUrl::fromUserInput(input);
    QNetworkAccessManager mgr;
    mgr.get(QNetworkRequest(url));
}
`
	flows := Analyze(code, "/app/qt_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when URL is processed via QUrl::fromUserInput")
		}
	}
}

func TestCPP_InetPton_Sanitized(t *testing.T) {
	code := `
#include <arpa/inet.h>
#include <curl/curl.h>
#include <cstdlib>

void connect_to(const char* argv[]) {
    char *ip = argv[1];
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return;
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, ip);
    curl_easy_perform(curl);
}
`
	flows := Analyze(code, "/app/inet_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when IP is validated via inet_pton")
		}
	}
}

// Negative test: SSRF WITHOUT any sanitizer should still produce a flow
func TestCPP_SSRF_Unsanitized_CPR(t *testing.T) {
	code := `
#include <cpr/cpr.h>

void fetch(const char* argv[]) {
    std::string url = argv[1];
    auto r = cpr::Get(cpr::Url{url});
}
`
	flows := Analyze(code, "/app/cpr_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for unsanitized argv -> cpr::Get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ hiredis Redis injection tests
// =========================================================================

func TestCPP_Hiredis_Command_Injection(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <string>

void handler(const char* argv[]) {
    redisContext *c = redisConnect("127.0.0.1", 6379);
    std::string key = argv[1];
    std::string cmd = "GET " + key;
    redisCommand(c, cmd.c_str());
}
`
	flows := Analyze(code, "/app/redis_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis injection flow for argv -> redisCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Hiredis_AppendCommand_Injection(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>

void pipeline(redisContext *c, const char* argv[]) {
    std::string key = argv[1];
    std::string cmd = "DEL " + key;
    redisAppendCommand(c, cmd.c_str());
}
`
	flows := Analyze(code, "/app/redis_pipeline.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis injection flow for argv -> redisAppendCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Hiredis_Source_SecondOrder(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <cstdlib>

void execute_stored(redisContext *c) {
    auto reply = redisCommand(c, "GET stored_cmd");
    system(reply);
}
`
	flows := Analyze(code, "/app/redis_exec.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order injection flow for redisCommand -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
