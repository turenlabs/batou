package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — Open-redirect (CWE-601) sink tests
// =========================================================================

func TestSwift_NSWorkspace_Open_OpenRedirect(t *testing.T) {
	code := `
import AppKit
import Vapor

func handler(req: Request) {
    let target = req.query["next"]
    NSWorkspace.shared.open(URL(string: target)!)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for req.query -> NSWorkspace.shared.open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_UIWebView_LoadRequest_OpenRedirect(t *testing.T) {
	code := `
import UIKit
import Vapor

func handler(req: Request, webView: UIWebView) {
    let dest = req.query["dest"]
    webView.loadRequest(URLRequest(url: URL(string: dest)!))
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for req.query -> UIWebView.loadRequest")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_ASWebAuthenticationSession_OpenRedirect(t *testing.T) {
	code := `
import AuthenticationServices
import Vapor

func startAuth(req: Request) {
    let raw = req.query["oauth_url"]
    let session = ASWebAuthenticationSession(url: URL(string: raw)!, callbackURLScheme: "myapp") { _, _ in }
    _ = session
}
`
	flows := Analyze(code, "/app/auth.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for req.query -> ASWebAuthenticationSession(url:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_LSOpenCFURLRef_OpenRedirect(t *testing.T) {
	code := `
import CoreServices
import Vapor

func handler(req: Request) {
    let raw = req.query["url"]
    LSOpenCFURLRef(URL(string: raw)! as CFURL, nil)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for req.query -> LSOpenCFURLRef")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_NSWorkspace_Open_Sanitized_AllowlistCheck(t *testing.T) {
	code := `
import AppKit
import Vapor

func handler(req: Request) {
    let target = req.query["next"]
    guard let url = URL(string: target), url.scheme == "https" else { return }
    let allowedHosts = ["example.com", "docs.example.com"]
    if let host = url.host, allowedHosts.contains(host) {
        NSWorkspace.shared.open(url)
    }
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected NO redirect flow when URL is validated against HTTPS scheme + host allowlist")
		}
	}
}
