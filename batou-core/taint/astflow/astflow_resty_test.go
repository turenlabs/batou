package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestAnalyzeGo_Resty_SSRF_SetBaseURL verifies that resty Client.SetBaseURL
// called with a tainted URL from an HTTP request is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_SetBaseURL(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, client *resty.Client) {
	target := r.URL.Query().Get("upstream")
	client.SetBaseURL(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.URL.Query().Get -> client.SetBaseURL, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_SetHostURL verifies that the deprecated SetHostURL
// alias is still flagged.
func TestAnalyzeGo_Resty_SSRF_SetHostURL(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, client *resty.Client) {
	host := r.FormValue("host")
	client.SetHostURL(host)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.FormValue -> client.SetHostURL, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_SetProxy verifies that resty Client.SetProxy with a
// tainted proxy URL is flagged.
func TestAnalyzeGo_Resty_SSRF_SetProxy(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, client *resty.Client) {
	proxy := r.Header.Get("X-Proxy")
	client.SetProxy(proxy)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.Header.Get -> client.SetProxy, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Execute verifies that resty Request.Execute(method,
// url) flags the URL argument (arg position 1).
func TestAnalyzeGo_Resty_SSRF_Execute(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.URL.Query().Get("url")
	_, _ = req.Execute("GET", target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.URL.Query().Get -> req.Execute, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_Header_SetHeader verifies that tainted values passed to
// resty SetHeader are flagged as CWE-113 header injection.
func TestAnalyzeGo_Resty_Header_SetHeader(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	agent := r.URL.Query().Get("ua")
	req.SetHeader("User-Agent", agent)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Errorf("expected header injection flow for r.URL.Query().Get -> req.SetHeader, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_Header_SetHeaderVerbatim verifies that SetHeaderVerbatim
// is also flagged (preserves header name case but still CRLF-unsafe).
func TestAnalyzeGo_Resty_Header_SetHeaderVerbatim(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	custom := r.FormValue("custom")
	req.SetHeaderVerbatim("X-Custom", custom)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Errorf("expected header injection flow for r.FormValue -> req.SetHeaderVerbatim, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SafeHardcodedURL_NoFalsePositive verifies that resty
// calls with hardcoded string literals do not produce SSRF findings.
func TestAnalyzeGo_Resty_SafeHardcodedURL_NoFalsePositive(t *testing.T) {
	code := `package main

import (
	"github.com/go-resty/resty/v2"
)

func bootstrap(client *resty.Client) {
	client.SetBaseURL("https://api.example.com")
	client.SetProxy("http://corp-proxy.example.com:8080")
}
`
	flows := AnalyzeGo(code, "/app/bootstrap.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO SSRF flow for hardcoded URLs, got sink=%s source=%s", f.Sink.ID, f.Source.ID)
		}
	}
}

// TestAnalyzeGo_Resty_SSRF_Get verifies that resty Request.Get(url) with a
// tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Get(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.URL.Query().Get("url")
	_, _ = req.Get(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.URL.Query().Get -> req.Get, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Post verifies that resty Request.Post(url) with a
// tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Post(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.FormValue("upstream")
	_, _ = req.Post(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.FormValue -> req.Post, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Put verifies that resty Request.Put(url) with a
// tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Put(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.URL.Query().Get("dest")
	_, _ = req.Put(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.URL.Query().Get -> req.Put, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Delete verifies that resty Request.Delete(url) with
// a tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Delete(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.Header.Get("X-Target")
	_, _ = req.Delete(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.Header.Get -> req.Delete, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Patch verifies that resty Request.Patch(url) with a
// tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Patch(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.URL.Query().Get("u")
	_, _ = req.Patch(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.URL.Query().Get -> req.Patch, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Head verifies that resty Request.Head(url) with a
// tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Head(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.URL.Query().Get("probe")
	_, _ = req.Head(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.URL.Query().Get -> req.Head, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SSRF_Options verifies that resty Request.Options(url)
// with a tainted URL is flagged as SSRF.
func TestAnalyzeGo_Resty_SSRF_Options(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request, req *resty.Request) {
	target := r.FormValue("preflight")
	_, _ = req.Options(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for r.FormValue -> req.Options, got %d flows", len(flows))
	}
}

// TestAnalyzeGo_Resty_SafeHardcodedVerbs_NoFalsePositive verifies that
// per-verb resty calls with hardcoded URLs do not produce SSRF findings.
func TestAnalyzeGo_Resty_SafeHardcodedVerbs_NoFalsePositive(t *testing.T) {
	code := `package main

import (
	"github.com/go-resty/resty/v2"
)

func bootstrap(req *resty.Request) {
	_, _ = req.Get("https://api.example.com/health")
	_, _ = req.Post("https://api.example.com/v1/log")
}
`
	flows := AnalyzeGo(code, "/app/bootstrap.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO SSRF flow for hardcoded URLs, got sink=%s source=%s", f.Sink.ID, f.Source.ID)
		}
	}
}
