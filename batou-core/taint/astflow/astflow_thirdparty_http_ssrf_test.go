package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Third-party Go HTTP clients (go-retryablehttp, gorequest, imroc/req) all wrap
// net/http and take the request URL as an argument. A tainted URL reaching any
// of them is SSRF (CWE-918). These tests verify the new go_sinks.go entries fire
// via astflow's typeEnv ObjectType matching when the receiver is a typed
// parameter (e.g. `client *retryablehttp.Client`).

// ssrfCase is one taint fixture: code with a request source flowing (or not)
// into a third-party HTTP client sink.
type ssrfCase struct {
	name string
	body string // statements inside handler(); has access to w, r, and the typed client param
}

// buildSSRF wraps body statements in a handler with the given extra typed
// parameters and imports, producing a complete Go source file for AnalyzeGo.
func buildSSRF(imports, params, body string) string {
	return `package main

import (
	"net/http"
` + imports + `
)

func handler(w http.ResponseWriter, r *http.Request` + params + `) {
` + body + `
}
`
}

// --- go-retryablehttp ---

func TestAnalyzeGo_RetryableHTTP_SSRF(t *testing.T) {
	imports := "\t\"github.com/hashicorp/go-retryablehttp\""
	params := ", client *retryablehttp.Client"
	cases := []ssrfCase{
		{"client.Get", `	target := r.URL.Query().Get("u")
	_, _ = client.Get(target)`},
		{"client.Head", `	target := r.URL.Query().Get("u")
	_, _ = client.Head(target)`},
		{"client.Post", `	target := r.FormValue("u")
	_, _ = client.Post(target, "application/json", nil)`},
		{"client.PostForm", `	target := r.URL.Query().Get("u")
	_, _ = client.PostForm(target, nil)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := AnalyzeGo(buildSSRF(imports, params, tc.body), "/app/handler.go")
			if !hasTaintFlow(flows, taint.SnkURLFetch) {
				t.Errorf("%s: expected SSRF flow, got %d flows", tc.name, len(flows))
			}
		})
	}
}

func TestAnalyzeGo_RetryableHTTP_NewRequest(t *testing.T) {
	// retryablehttp.NewRequest(method, url, body) — URL is arg index 1.
	code := `package main

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("u")
	_, _ = retryablehttp.NewRequest("GET", target, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for retryablehttp.NewRequest, got %d flows", len(flows))
	}
}

// --- parnurzeal/gorequest ---

func TestAnalyzeGo_GoRequest_SSRF(t *testing.T) {
	imports := "\t\"github.com/parnurzeal/gorequest\""
	params := ", request *gorequest.SuperAgent"
	cases := []ssrfCase{
		{"Get", `	target := r.URL.Query().Get("u")
	request.Get(target)`},
		{"Post", `	target := r.URL.Query().Get("u")
	request.Post(target)`},
		{"Put", `	target := r.URL.Query().Get("u")
	request.Put(target)`},
		{"Delete", `	target := r.URL.Query().Get("u")
	request.Delete(target)`},
		{"Head", `	target := r.URL.Query().Get("u")
	request.Head(target)`},
		{"Patch", `	target := r.URL.Query().Get("u")
	request.Patch(target)`},
		{"Options", `	target := r.URL.Query().Get("u")
	request.Options(target)`},
		{"Proxy", `	target := r.URL.Query().Get("proxy")
	request.Proxy(target)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := AnalyzeGo(buildSSRF(imports, params, tc.body), "/app/handler.go")
			if !hasTaintFlow(flows, taint.SnkURLFetch) {
				t.Errorf("%s: expected SSRF flow, got %d flows", tc.name, len(flows))
			}
		})
	}
}

// --- imroc/req ---

func TestAnalyzeGo_ImrocReq_Client_SSRF(t *testing.T) {
	imports := "\t\"github.com/imroc/req/v3\""
	params := ", client *req.Client"
	cases := []ssrfCase{
		{"SetBaseURL", `	target := r.URL.Query().Get("u")
	client.SetBaseURL(target)`},
		{"SetProxyURL", `	target := r.URL.Query().Get("proxy")
	client.SetProxyURL(target)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := AnalyzeGo(buildSSRF(imports, params, tc.body), "/app/handler.go")
			if !hasTaintFlow(flows, taint.SnkURLFetch) {
				t.Errorf("%s: expected SSRF flow, got %d flows", tc.name, len(flows))
			}
		})
	}
}

func TestAnalyzeGo_ImrocReq_Request_SSRF(t *testing.T) {
	imports := "\t\"github.com/imroc/req/v3\""
	params := ", request *req.Request"
	cases := []ssrfCase{
		{"Get", `	target := r.URL.Query().Get("u")
	_, _ = request.Get(target)`},
		{"Post", `	target := r.URL.Query().Get("u")
	_, _ = request.Post(target)`},
		{"Put", `	target := r.URL.Query().Get("u")
	_, _ = request.Put(target)`},
		{"Delete", `	target := r.URL.Query().Get("u")
	_, _ = request.Delete(target)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := AnalyzeGo(buildSSRF(imports, params, tc.body), "/app/handler.go")
			if !hasTaintFlow(flows, taint.SnkURLFetch) {
				t.Errorf("%s: expected SSRF flow, got %d flows", tc.name, len(flows))
			}
		})
	}
}

// --- Negative controls: constant URLs must NOT produce SSRF flows ---

func TestAnalyzeGo_ThirdPartyHTTP_ConstantURL_NoFlow(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			"retryablehttp.Client.Get const",
			`package main

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

func handler(w http.ResponseWriter, r *http.Request, client *retryablehttp.Client) {
	_, _ = client.Get("https://api.internal.example.com/health")
}
`,
		},
		{
			"gorequest const",
			`package main

import (
	"net/http"

	"github.com/parnurzeal/gorequest"
)

func handler(w http.ResponseWriter, r *http.Request, request *gorequest.SuperAgent) {
	request.Get("https://api.internal.example.com/health")
}
`,
		},
		{
			"req.Client.SetBaseURL const",
			`package main

import (
	"net/http"

	"github.com/imroc/req/v3"
)

func handler(w http.ResponseWriter, r *http.Request, client *req.Client) {
	client.SetBaseURL("https://api.internal.example.com")
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := AnalyzeGo(tc.code, "/app/handler.go")
			if hasTaintFlow(flows, taint.SnkURLFetch) {
				t.Errorf("%s: expected NO SSRF flow for constant URL, got %d flows", tc.name, len(flows))
			}
		})
	}
}
