package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ Abseil string-escape sanitizer tests (CWE-93, CWE-117, CWE-601)
// All Abseil escape functions have a return-value form
// `std::string out = absl::Foo(input);` which tsflow's sanitizer model handles.
// =========================================================================

// ── Negative control ───────────────────────────────────────────────────
// Without sanitizer: getenv -> spdlog::info should produce a log-injection flow.
func TestCPP_Absl_NegativeControl_Spdlog_Unsanitized(t *testing.T) {
	code := `
#include <spdlog/spdlog.h>
#include <cstdlib>

void log_user() {
    char *userInput = getenv("USER_INPUT");
    spdlog::info(userInput);
}
`
	flows := Analyze(code, "/app/log_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> spdlog::info without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Positive sanitizer tests (each Abseil escape neutralizes its targets) ──

func TestCPP_Absl_CEscape_NeutralizesLog(t *testing.T) {
	code := `
#include <spdlog/spdlog.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void log_user() {
    char *userInput = getenv("USER_INPUT");
    std::string safe = absl::CEscape(userInput);
    spdlog::info(safe);
}
`
	flows := Analyze(code, "/app/log_cescape.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO log flow when input is sanitized via absl::CEscape (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestCPP_Absl_CEscape_NeutralizesHeader(t *testing.T) {
	code := `
#include <crow.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void set_session_header(crow::response &res) {
    char *userInput = getenv("SESSION_TAG");
    std::string safe = absl::CEscape(userInput);
    res.set_header("X-Session", safe);
}
`
	flows := Analyze(code, "/app/header_cescape.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when input is sanitized via absl::CEscape (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestCPP_Absl_Utf8SafeCEscape_NeutralizesLog(t *testing.T) {
	code := `
#include <spdlog/spdlog.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void log_user() {
    char *userInput = getenv("USER_INPUT");
    std::string safe = absl::Utf8SafeCEscape(userInput);
    spdlog::warn(safe);
}
`
	flows := Analyze(code, "/app/log_utf8safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO log flow when input is sanitized via absl::Utf8SafeCEscape (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestCPP_Absl_CHexEscape_NeutralizesLog(t *testing.T) {
	code := `
#include <spdlog/spdlog.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void log_user() {
    char *userInput = getenv("USER_INPUT");
    std::string safe = absl::CHexEscape(userInput);
    spdlog::error(safe);
}
`
	flows := Analyze(code, "/app/log_chexescape.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO log flow when input is sanitized via absl::CHexEscape (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestCPP_Absl_Base64Escape_NeutralizesHeader(t *testing.T) {
	code := `
#include <crow.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void set_blob_header(crow::response &res) {
    char *userBlob = getenv("BLOB_TAG");
    std::string safe = absl::Base64Escape(userBlob);
    res.set_header("X-Blob", safe);
}
`
	flows := Analyze(code, "/app/header_base64.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when input is sanitized via absl::Base64Escape (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestCPP_Absl_WebSafeBase64Escape_NeutralizesURLFetch(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void fetch_resource(CURL *curl) {
    char *userToken = getenv("RESOURCE_TOKEN");
    std::string safe = absl::WebSafeBase64Escape(userToken);
    std::string url = "https://api.example.com/r?t=" + safe;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
}
`
	flows := Analyze(code, "/app/url_websafe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO URL fetch flow when input is sanitized via absl::WebSafeBase64Escape (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestCPP_Absl_BytesToHexString_NeutralizesLog(t *testing.T) {
	code := `
#include <spdlog/spdlog.h>
#include <absl/strings/escaping.h>
#include <cstdlib>
#include <string>

void log_blob() {
    char *userInput = getenv("USER_INPUT");
    std::string safe = absl::BytesToHexString(userInput);
    spdlog::info(safe);
}
`
	flows := Analyze(code, "/app/log_hex.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("expected NO log flow when input is sanitized via absl::BytesToHexString (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

