package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestRust_AttohttpcGetSSRF verifies that attohttpc::get with tainted URL is detected.
func TestRust_AttohttpcGetSSRF(t *testing.T) {
	code := `
use std::env;

fn fetch_url() {
    let url = env::var("TARGET_URL").unwrap();
    let resp = attohttpc::get(&url).send().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.attohttpc.method" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SSRF finding for attohttpc::get with tainted URL, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s cat=%v", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_AttohttpcPostSSRF verifies that attohttpc::post with tainted URL is detected.
func TestRust_AttohttpcPostSSRF(t *testing.T) {
	code := `
use std::env;

fn post_data() {
    let url = env::var("API").unwrap();
    let resp = attohttpc::post(&url).text("body").send().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.attohttpc.method" {
			found = true
		}
	}
	if !found {
		t.Error("Expected SSRF finding for attohttpc::post with tainted URL")
	}
}

// TestRust_GlooNetRequestGetSSRF verifies gloo_net::http::Request::get with tainted URL.
func TestRust_GlooNetRequestGetSSRF(t *testing.T) {
	code := `
use std::env;

async fn fetch() {
    let url = env::var("ENDPOINT").unwrap();
    let resp = gloo_net::http::Request::get(&url).send().await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.gloo_net.request.method" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SSRF finding for gloo_net::http::Request::get, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s cat=%v", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_TonicEndpointFromSharedSSRF verifies tonic::transport::Endpoint::from_shared
// with tainted URI is detected as SSRF.
func TestRust_TonicEndpointFromSharedSSRF(t *testing.T) {
	code := `
use std::env;

async fn connect_grpc() {
    let target = env::var("GRPC_TARGET").unwrap();
    let endpoint = tonic::transport::Endpoint::from_shared(target).unwrap();
    let channel = endpoint.connect().await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.tonic.endpoint.from" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SSRF finding for tonic::transport::Endpoint::from_shared, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s cat=%v", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_TonicChannelFromSharedSSRF verifies tonic::transport::Channel::from_shared
// with tainted URI is detected as SSRF.
func TestRust_TonicChannelFromSharedSSRF(t *testing.T) {
	code := `
use std::env;

async fn connect() {
    let target = env::var("GRPC_URL").unwrap();
    let channel = tonic::transport::Channel::from_shared(target).unwrap().connect().await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.tonic.channel.from" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SSRF finding for tonic::transport::Channel::from_shared, got %d flows", len(flows))
	}
}

// TestRust_HttpReqRequestGetSSRF verifies http_req::request::get with tainted URL.
func TestRust_HttpReqRequestGetSSRF(t *testing.T) {
	code := `
use std::env;
use http_req::request;

fn fetch() {
    let url = env::var("URL").unwrap();
    let mut body = Vec::new();
    let res = request::get(&url, &mut body).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.http_req.request.method" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SSRF finding for http_req::request::get, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s cat=%v", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_AttohttpcSafe verifies that hardcoded URL is NOT flagged.
func TestRust_AttohttpcSafe(t *testing.T) {
	code := `
fn fetch() {
    let resp = attohttpc::get("https://api.example.com/v1/status").send().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.attohttpc.method" {
			t.Errorf("hardcoded URL should not produce SSRF flow, got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
