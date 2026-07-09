package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Receiver-blind Go sink matching — false-positive regression guards.
//
// Real-world smoke test (batou scan on grafana/grafana pkg/services) surfaced
// three systematic FP classes caused by package/receiver-blind catalog sinks:
//
//   1. errors.Join(a, err) mislabeled BATOU-TAINT-file_write (CWE-22) because
//      the filepath.Join sink declared a bare MethodName "Join", which matched
//      ANY package-level Join (errors.Join, strings.Join).
//   2. cache.Get(key) mislabeled BATOU-TAINT-url_fetch (CWE-918) because the
//      http.Get sink declared a bare MethodName "Get", matching any `x.Get(...)`
//      whose receiver name was unresolved (in-memory cache lookups).
//   3. cache.Set(ctx, ...) mislabeled BATOU-TAINT-http_header (CWE-113) because
//      the echo "Response().Header().Set" sink's chain was not verified — only
//      the leaf ".Set" plus a permissive receiver-name heuristic ("c").
//
// The fix qualifies the colliding sinks' MethodName (filepath.Join/path.Join,
// http.Get) and teaches matchesMethodCall to verify "()"-chain MethodNames
// against the actual receiver call chain. Each FP case below must stay CLEAN;
// each paired true-positive must still FIRE (proves we tightened, not disabled).
// =========================================================================

func hasSinkCategory(flows []taint.TaintFlow, cat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == cat {
			return true
		}
	}
	return false
}

// ---- Class 1: errors.Join must NOT be a file-write/path-traversal sink ----

func TestAnalyzeGo_ErrorsJoin_NotFileWriteFP(t *testing.T) {
	// Mirrors grafana pkg/services/authn/clients/password.go:63 —
	// errors.Join aggregating a request-derived error, not a filesystem path.
	code := `package main

import (
	"errors"
	"net/http"
)

func aggregate(w http.ResponseWriter, r *http.Request) error {
	clientErr := errors.New(r.FormValue("e"))
	var errs error
	errs = errors.Join(errs, clientErr)
	return errs
}
`
	flows := AnalyzeGo(code, "/app/password.go")
	if hasSinkCategory(flows, taint.SnkFileWrite) {
		t.Error("FP: errors.Join flagged as file-write/path-traversal sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_FilepathJoin_StillFires(t *testing.T) {
	// Genuine path traversal: request value joined into a filesystem path.
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func readUserFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	full := filepath.Join("/data", name)
	data, _ := os.ReadFile(full)
	_ = data
}
`
	flows := AnalyzeGo(code, "/app/files.go")
	if !hasSinkCategory(flows, taint.SnkFileWrite) {
		t.Error("expected file-write/path-traversal flow for r.URL.Query().Get -> filepath.Join")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// ---- Class 2: in-memory cache.Get must NOT be an SSRF/url_fetch sink ----

func TestAnalyzeGo_CacheGet_NotURLFetchFP(t *testing.T) {
	// Mirrors grafana pkg/services/authz/zanzana/server/server_list.go:288 —
	// an in-memory cache.Get(key), not an HTTP fetch.
	code := `package main

import "net/http"

type store struct {
	cache map[string]any
}

func (s *store) lookup(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if res, ok := s.cache[key]; ok {
		_ = res
	}
}
`
	flows := AnalyzeGo(code, "/app/server_list.go")
	if hasSinkCategory(flows, taint.SnkURLFetch) {
		t.Error("FP: in-memory cache lookup flagged as url_fetch/SSRF sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_CacheGetMethod_NotURLFetchFP(t *testing.T) {
	// A typed-cache method call `s.cache.Get(key)` (receiver is a field
	// selector, not the http package) must not match the http.Get SSRF sink.
	code := `package main

import "net/http"

type cacheIface interface {
	Get(k string) (any, bool)
}

type svc struct {
	cache cacheIface
}

func (s *svc) lookup(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if v, ok := s.cache.Get(key); ok {
		_ = v
	}
}
`
	flows := AnalyzeGo(code, "/app/dashboard.go")
	if hasSinkCategory(flows, taint.SnkURLFetch) {
		t.Error("FP: s.cache.Get(key) flagged as url_fetch/SSRF sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_HTTPGet_StillFires(t *testing.T) {
	// Genuine SSRF: request value passed to net/http.Get.
	code := `package main

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("u")
	resp, _ := http.Get(target)
	_ = resp
}
`
	flows := AnalyzeGo(code, "/app/fetch.go")
	if !hasSinkCategory(flows, taint.SnkURLFetch) {
		t.Error("expected url_fetch/SSRF flow for r.URL.Query().Get -> http.Get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// ---- Class 3: cache.Set must NOT be an http_header sink ----

func TestAnalyzeGo_CacheSet_NotHTTPHeaderFP(t *testing.T) {
	// Mirrors grafana pkg/services/authn/clients/proxy.go:196 —
	// c.cache.Set(ctx, key, ...) on a *Proxy receiver named "c". The bare leaf
	// ".Set" plus the "c" -> echo.Context name heuristic previously misattributed
	// this to the echo Response().Header().Set sink.
	code := `package main

import (
	"context"
	"net/http"
)

type kvCache interface {
	Set(ctx context.Context, k string, v []byte) error
}

type Proxy struct {
	cache kvCache
}

func (c *Proxy) hook(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	userKey := r.URL.Query().Get("k")
	return c.cache.Set(ctx, userKey, []byte("v"))
}
`
	flows := AnalyzeGo(code, "/app/proxy.go")
	if hasSinkCategory(flows, taint.SnkHeader) {
		t.Error("FP: c.cache.Set(ctx, ...) flagged as http_header sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_ResponseHeaderSet_StillFires(t *testing.T) {
	// Genuine header injection: request value written to a real
	// http.ResponseWriter header via w.Header().Set(...).
	code := `package main

import "net/http"

func setHeader(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	w.Header().Set("X-Custom", v)
}
`
	flows := AnalyzeGo(code, "/app/header.go")
	if !hasSinkCategory(flows, taint.SnkHeader) {
		t.Error("expected http_header flow for r.URL.Query().Get -> w.Header().Set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// =========================================================================
// Class 4: builder/fluent CHAIN receivers must NOT match package-level
// bare-name sinks (go.http.post "Post", go.http.head "Head", go.os.create
// "Create"). A package call's receiver is the package alias (*ast.Ident);
// a chain receiver like `builder().Post(u)` is a *ast.CallExpr. Matching the
// bare leaf name receiver-blind produced false SSRF/file-write BLOCK findings
// (conf 1.0) on route builders — e.g. gitea routers/web/web.go's
// `m.Combo("/x").Get(H).Post(web.Bind(...), HPost)`. The fix in
// matchesPackageCall requires an *ast.Ident receiver. Each FP case below must
// stay CLEAN; each paired package-call true-positive must still FIRE.
// =========================================================================

func TestAnalyzeGo_BuilderChainPost_NotURLFetchFP(t *testing.T) {
	// `builder().Post(u)` — a fluent route/HTTP builder, not net/http.Post.
	// The tainted arg must NOT raise an SSRF/url_fetch flow.
	code := `package main

import "net/http"

type routeBuilder struct{}

func (b *routeBuilder) Post(s string) *routeBuilder { return b }

func builder() *routeBuilder { return &routeBuilder{} }

func register(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("x")
	builder().Post(u)
}
`
	flows := AnalyzeGo(code, "/app/web.go")
	if hasSinkCategory(flows, taint.SnkURLFetch) {
		t.Error("FP: builder().Post(u) flagged as url_fetch/SSRF sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_BuilderChainCreate_NotFileWriteFP(t *testing.T) {
	// `getFS().Create(p)` — a fluent filesystem accessor, not os.Create.
	// The tainted arg must NOT raise a file-write/path-traversal flow.
	code := `package main

import "net/http"

type fsHandle struct{}

func (h *fsHandle) Create(p string) error { return nil }

func getFS() *fsHandle { return &fsHandle{} }

func write(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("path")
	_ = getFS().Create(p)
}
`
	flows := AnalyzeGo(code, "/app/store.go")
	if hasSinkCategory(flows, taint.SnkFileWrite) {
		t.Error("FP: getFS().Create(p) flagged as file-write/path-traversal sink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s cwe=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_HTTPPost_StillFires(t *testing.T) {
	// Genuine SSRF: request value passed to net/http.Post (receiver ident
	// "http"). Must still fire after the receiver-shape gate.
	code := `package main

import (
	"net/http"
	"strings"
)

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("u")
	resp, _ := http.Post(target, "text/plain", strings.NewReader("x"))
	_ = resp
}
`
	flows := AnalyzeGo(code, "/app/fetch.go")
	if !hasSinkCategory(flows, taint.SnkURLFetch) {
		t.Error("expected url_fetch/SSRF flow for r.FormValue -> http.Post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_OsCreate_StillFires(t *testing.T) {
	// Genuine zip-slip/path-traversal (gosec G305 ground truth): request
	// value passed to os.Create (receiver ident "os"). Must still fire.
	code := `package main

import (
	"net/http"
	"os"
)

func save(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("path")
	f, _ := os.Create(p)
	_ = f
}
`
	flows := AnalyzeGo(code, "/app/save.go")
	if !hasSinkCategory(flows, taint.SnkFileWrite) {
		t.Error("expected file-write/path-traversal flow for r.FormValue -> os.Create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}
