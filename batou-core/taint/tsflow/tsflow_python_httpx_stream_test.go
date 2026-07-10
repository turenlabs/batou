package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python httpx streaming SSRF — httpx.stream / Client.stream / AsyncClient.stream
//
// The streaming API signature is stream(method, url, ...), so the tainted URL
// is the 2nd positional argument (index 1), unlike the get/post/... verb
// methods where it is index 0. These flows were previously undetected: no
// catalog entry covered the "stream" method name at all.
// =========================================================================

func TestPython_SSRF_HttpxModuleStream(t *testing.T) {
	code := `
from flask import request
import httpx

def handler():
    url = request.args.get("url")
    with httpx.stream("GET", url) as r:
        for chunk in r.iter_bytes():
            pass
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> httpx.stream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_HttpxClientStream(t *testing.T) {
	code := `
from flask import request
import httpx

def handler():
    url = request.args.get("url")
    client = httpx.Client()
    with client.stream("GET", url) as r:
        pass
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> httpx.Client().stream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSRF_HttpxAsyncClientStream(t *testing.T) {
	code := `
from flask import request
import httpx

async def handler():
    url = request.args.get("url")
    client = httpx.AsyncClient()
    async with client.stream("GET", url) as r:
        pass
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for request.args -> httpx.AsyncClient().stream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative control: a constant URL must not produce a flow, confirming the
// entry is driven by taint and not by the call shape alone.
func TestPython_SSRF_HttpxStreamConstantURL_NoFlow(t *testing.T) {
	code := `
import httpx

def handler():
    with httpx.stream("GET", "https://api.internal/health") as r:
        pass
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("did not expect SSRF flow for constant URL -> httpx.stream()")
	}
}
