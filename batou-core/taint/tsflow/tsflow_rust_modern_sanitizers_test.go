package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for the modern Rust sanitizer entries added in cycle #671:
//
//   rust.password_hash.hash_password           (RustCrypto PasswordHasher trait)
//   rust.idna.domain_to_ascii                  (IDN normalization for SSRF)
//   rust.idna.domain_to_ascii_strict           (strict IDN validation)
//   rust.percent_encoding.utf8_percent_encode  (URL percent encoding, str)
//   rust.percent_encoding.percent_encode       (URL percent encoding, bytes)
//   rust.htmlescape.encode_minimal             (htmlescape crate body XSS)
//   rust.htmlescape.encode_attribute           (htmlescape crate attribute XSS)
//
// Each sanitizer has a paired "Vulnerable" test (asserting the source -> sink
// flow IS detected without the sanitizer) and a "Safe" test (asserting the
// flow is neutralized when the sanitizer is applied).
//
// For sanitizers whose real-world API returns a Result/iterator (idna,
// password_hash, percent_encoding), the "Safe" test inlines the sanitizer
// call directly inside the sink's argument list so the walker's
// containsInlineSanitizer pass picks it up without depending on
// .unwrap()/.to_string() chain handling.

// --- RustCrypto password_hash trait (CWE-916, CWE-326) ---

func TestRust_PasswordHash_Vulnerable_Md5(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let pw = env::var("PASSWORD").unwrap();
    let _ = md5::compute(pw.as_bytes());
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for env::var -> md5::compute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_PasswordHash_Safe_Scrypt(t *testing.T) {
	code := `
use std::env;
use scrypt::Scrypt;
use scrypt::password_hash::{PasswordHasher, SaltString};

fn handler(salt: SaltString) {
    let pw = env::var("PASSWORD").unwrap();
    let _ = md5::compute(Scrypt.hash_password(pw.as_bytes(), &salt));
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Sink.ID == "rust.crypto.md5" {
			t.Errorf("Scrypt.hash_password should sanitize before md5: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_PasswordHash_Safe_Pbkdf2(t *testing.T) {
	code := `
use std::env;
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::{PasswordHasher, SaltString};

fn handler(salt: SaltString) {
    let pw = env::var("PASSWORD").unwrap();
    let _ = md5::compute(Pbkdf2.hash_password(pw.as_bytes(), &salt));
}
`
	flows := Analyze(code, "/app/auth.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Sink.ID == "rust.crypto.md5" {
			t.Errorf("Pbkdf2.hash_password should sanitize before md5: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- IDN normalization for SSRF / open redirect (CWE-918, CWE-601) ---

func TestRust_Idna_Vulnerable_Reqwest(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let host = env::var("HOST").unwrap();
    let url = format!("https://{}/api", host);
    let _ = reqwest::get(&url).await;
}
`
	flows := Analyze(code, "/app/proxy.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected URL-fetch flow for env::var -> reqwest::get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Idna_Safe_DomainToAscii(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let host = env::var("HOST").unwrap();
    let _ = reqwest::get(idna::domain_to_ascii(&host)).await;
}
`
	flows := Analyze(code, "/app/proxy.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("idna::domain_to_ascii should sanitize host before reqwest: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Idna_Safe_DomainToAsciiStrict(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let host = env::var("HOST").unwrap();
    let _ = reqwest::get(idna::domain_to_ascii_strict(&host)).await;
}
`
	flows := Analyze(code, "/app/proxy.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("idna::domain_to_ascii_strict should sanitize host before reqwest: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- percent-encoding crate (CWE-918, CWE-79) ---

func TestRust_PercentEncoding_Vulnerable_QueryParam(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let q = env::var("QUERY").unwrap();
    let url = format!("https://api.example.com/search?q={}", q);
    let _ = reqwest::get(&url).await;
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected URL-fetch flow for env::var -> reqwest::get with format!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_PercentEncoding_Safe_Utf8PercentEncode(t *testing.T) {
	code := `
use std::env;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

async fn handler() {
    let q = env::var("QUERY").unwrap();
    let _ = reqwest::get(percent_encoding::utf8_percent_encode(&q, NON_ALPHANUMERIC)).await;
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("percent_encoding::utf8_percent_encode should sanitize query param: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_PercentEncoding_Safe_PercentEncode(t *testing.T) {
	code := `
use std::env;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

async fn handler() {
    let q = env::var("QUERY").unwrap();
    let _ = reqwest::get(percent_encoding::percent_encode(q.as_bytes(), NON_ALPHANUMERIC)).await;
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("percent_encoding::percent_encode should sanitize query param: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- htmlescape crate (CWE-79) ---

func TestRust_Htmlescape_Vulnerable_WarpReplyHtml(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let user = env::var("USERNAME").unwrap();
    let body = format!("<div>Welcome {}</div>", user);
    let _ = warp::reply::html(body);
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output flow for env::var -> warp::reply::html")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Htmlescape_Safe_EncodeMinimal(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let user = env::var("USERNAME").unwrap();
    let safe = htmlescape::encode_minimal(&user);
    let body = format!("<div>Welcome {}</div>", safe);
    let _ = warp::reply::html(body);
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("htmlescape::encode_minimal should sanitize before warp::reply::html: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Htmlescape_Safe_EncodeAttribute(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let title = env::var("TITLE").unwrap();
    let safe = htmlescape::encode_attribute(&title);
    let body = format!("<a title=\"{}\">link</a>", safe);
    let _ = warp::reply::html(body);
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("htmlescape::encode_attribute should sanitize before warp::reply::html: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Negative test: literal constant must not produce a flow even without a sanitizer ---
// Guards against over-broadness regression in the new sanitizer entries.
func TestRust_Sanitizers_NegativeNoFlow_Constant(t *testing.T) {
	code := `
fn handler() {
    let host = "example.com";
    let url = format!("https://{}/api", host);
    let _ = reqwest::get(&url);
}
`
	flows := Analyze(code, "/app/proxy.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("constant host should not produce URL-fetch flow: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
