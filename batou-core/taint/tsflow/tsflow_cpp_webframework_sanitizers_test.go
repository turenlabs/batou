package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ web-framework URL/path sanitizer tests
// (cpp-httplib free-function encoders, drogon::utils encoders, crow::utility
// URL-safe base64). All entries are return-value form `auto safe = enc(input);`
// which tsflow's sanitizer model handles via assignment-LHS taint clearing.
//
// IMPORTANT (cycle #759 isWebHandlerFunc gotcha): keep all identifiers
// (envvar names, variable names, header names) free of the uppercase
// substrings GET, POST, PUT, DELETE, PATCH — any of those auto-taint every
// function parameter at confidence 0.9 and break sanitizer-side negative
// controls. Hence env names like "DEST_HOST" / "BLOB_VALUE" / "TAG_DATA"
// rather than "USER_INPUT" or "USER_TARGET".
// =========================================================================

// ── Negative control: unsanitized path → SSRF flow via httplib::Client.Get ──
// Uses httplib::Client.Get(path) sink (DangerousArgs[0]) — exercises the
// same SnkURLFetch surface that the encode_uri_component / drogon::utils::*
// sanitizers below claim to neutralize.
func TestCPP_WebFw_NegativeControl_HttplibGet_Unsanitized(t *testing.T) {
	code := `
#include <httplib.h>
#include <cstdlib>

void fetch_resource() {
    httplib::Client cli("https://api.example.com");
    char *userPath = getenv("REMOTE_FILE");
    cli.Get(userPath);
}
`
	flows := Analyze(code, "/app/fetch_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected URL fetch flow for getenv -> httplib::Client.Get without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── cpp-httplib::encode_uri neutralizes header injection ───────────────
func TestCPP_WebFw_HttplibEncodeUri_NeutralizesHeader(t *testing.T) {
	code := `
#include <httplib.h>
#include <cstdlib>
#include <string>

void set_tag_header(httplib::Response &res) {
    char *userTag = getenv("SESSION_TAG");
    std::string safe = httplib::encode_uri(userTag);
    res.set_header("X-Tag", safe);
}
`
	flows := Analyze(code, "/app/header_encode_uri.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when input is sanitized via httplib::encode_uri (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── cpp-httplib::encode_uri_component neutralizes URL-fetch SSRF ──────
func TestCPP_WebFw_HttplibEncodeUriComponent_NeutralizesURLFetch(t *testing.T) {
	code := `
#include <httplib.h>
#include <cstdlib>
#include <string>

void fetch_with_token() {
    httplib::Client cli("https://api.example.com");
    char *userTok = getenv("BLOB_VALUE");
    std::string safe = httplib::encode_uri_component(userTok);
    cli.Get(safe);
}
`
	flows := Analyze(code, "/app/fetch_encode_uri_component.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO URL fetch flow when input is sanitized via httplib::encode_uri_component (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── cpp-httplib::encode_query_component neutralizes header injection ──
func TestCPP_WebFw_HttplibEncodeQueryComponent_NeutralizesHeader(t *testing.T) {
	code := `
#include <httplib.h>
#include <cstdlib>
#include <string>

void set_query_header(httplib::Response &res) {
    char *userQ = getenv("QUERY_VALUE");
    std::string safe = httplib::encode_query_component(userQ);
    res.set_header("X-Query", safe);
}
`
	flows := Analyze(code, "/app/header_encode_query.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when input is sanitized via httplib::encode_query_component (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── cpp-httplib::encode_path_component neutralizes file-write traversal ──
func TestCPP_WebFw_HttplibEncodePathComponent_NeutralizesFileWrite(t *testing.T) {
	code := `
#include <httplib.h>
#include <cstdlib>
#include <cstdio>
#include <string>

void write_user_file() {
    char *userName = getenv("FNAME");
    std::string safe = httplib::encode_path_component(userName);
    std::string path = "/var/data/" + safe;
    fopen(path.c_str(), "w");
}
`
	flows := Analyze(code, "/app/write_encode_path.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected NO file write flow when input is sanitized via httplib::encode_path_component (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── cpp-httplib::sanitize_filename neutralizes file-write traversal ────
func TestCPP_WebFw_HttplibSanitizeFilename_NeutralizesFileWrite(t *testing.T) {
	code := `
#include <httplib.h>
#include <cstdlib>
#include <cstdio>
#include <string>

void save_upload() {
    char *userName = getenv("UPLOAD_NAME");
    std::string safe = httplib::sanitize_filename(userName);
    std::string path = "/var/uploads/" + safe;
    fopen(path.c_str(), "w");
}
`
	flows := Analyze(code, "/app/save_sanitize_filename.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Errorf("expected NO file write flow when input is sanitized via httplib::sanitize_filename (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── drogon::utils::urlEncode neutralizes header injection ──────────────
// Uses a LOCAL variable (not function parameter) for the response object —
// keeping `resp` as a function parameter would trip the cycle #759
// isWebHandlerFunc gotcha (any TAG/INPUT identifier with PUT/GET substring
// auto-taints all params). A locally-constructed resp also keeps the sink
// receiver name `resp` so matcher's prefix-of-"response" heuristic fires.
func TestCPP_WebFw_DrogonUrlEncode_NeutralizesHeader(t *testing.T) {
	code := `
#include <drogon/HttpResponse.h>
#include <drogon/utils/Utilities.h>
#include <cstdlib>
#include <string>

void set_drogon_header() {
    auto resp = drogon::HttpResponse::newHttpResponse();
    char *userVal = getenv("TAG_DATA");
    std::string safe = drogon::utils::urlEncode(userVal);
    resp->addHeader("X-User", safe);
}
`
	flows := Analyze(code, "/app/header_drogon_urlencode.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when input is sanitized via drogon::utils::urlEncode (got %s [%s] -> %s [%s])", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// ── drogon::utils::urlEncodeComponent neutralizes URL-fetch SSRF ───────
func TestCPP_WebFw_DrogonUrlEncodeComponent_NeutralizesURLFetch(t *testing.T) {
	code := `
#include <httplib.h>
#include <drogon/utils/Utilities.h>
#include <cstdlib>
#include <string>

void fetch_drogon_component() {
    httplib::Client cli("https://api.example.com");
    char *userTok = getenv("DRO_TOKEN");
    std::string safe = drogon::utils::urlEncodeComponent(userTok);
    cli.Get(safe);
}
`
	flows := Analyze(code, "/app/fetch_drogon_component.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO URL fetch flow when input is sanitized via drogon::utils::urlEncodeComponent (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── crow::utility::base64encode_urlsafe neutralizes header injection ───
func TestCPP_WebFw_CrowBase64UrlSafe_NeutralizesHeader(t *testing.T) {
	code := `
#include <crow.h>
#include <cstdlib>
#include <string>

void set_blob_header(crow::response &res) {
    char *userBlob = getenv("USER_BLOB");
    std::string safe = crow::utility::base64encode_urlsafe(userBlob, 32);
    res.set_header("X-Blob", safe);
}
`
	flows := Analyze(code, "/app/header_crow_b64.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when input is sanitized via crow::utility::base64encode_urlsafe (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}
