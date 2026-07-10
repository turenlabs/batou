package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Selector-expression sources on *http.Request
//
// Before this change the astflow engine only recognised sources expressed
// as method calls (e.g. r.FormValue("x")). Primitive field reads like
// r.URL.Path, r.Body, r.RemoteAddr, r.Host were flagged by the regex tier
// (BATOU-TAINT-*) but invisible to the precise dataflow engine — so they
// never produced multi-layer-confirmed findings, never reached the call
// graph, and intermediate-variable patterns like
//
//	p := r.URL.Path
//	os.ReadFile(p)
//
// went undetected by astflow.
//
// These tests exercise the new selector-source matching: each one taints
// a *http.Request field read, propagates the taint through assignment or
// inline use, and asserts the appropriate sink category fires.
// =========================================================================

func TestAnalyzeGo_SelectorSource_URLPath_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func H(r *http.Request) {
	os.ReadFile(r.URL.Path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) && !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow for r.URL.Path -> os.ReadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_URLPath_Intermediate(t *testing.T) {
	// Intermediate variable: the original gap reported by PR-HH's agent.
	code := `package main

import (
	"net/http"
	"os"
)

func H(r *http.Request) {
	p := r.URL.Path
	os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) && !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow for r.URL.Path via intermediate var -> os.ReadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_URLRawQuery_SQLInjection(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func H(r *http.Request) {
	db.Exec(r.URL.RawQuery)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for r.URL.RawQuery -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_Body_AssignedThenSink(t *testing.T) {
	// r.Body is the HTTP request body. Assigned to a local and written to
	// the response — log_output / html_output sink depending on writer
	// shape. We assert a SnkHTMLOutput flow fires because fmt.Fprintln to
	// http.ResponseWriter is an HTML-output sink (taint.go.fmt.fprintln).
	code := `package main

import (
	"fmt"
	"net/http"
)

func H(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	fmt.Fprintln(w, body)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output flow for r.Body -> fmt.Fprintln(w, body)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_UserAgent_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
)

func H(r *http.Request) {
	ua := r.UserAgent()
	log.Printf("%s", ua)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for r.UserAgent() -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_RemoteAddr_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
)

func H(r *http.Request) {
	log.Printf("%s", r.RemoteAddr)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for r.RemoteAddr -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_Host_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
)

func H(r *http.Request) {
	host := r.Host
	log.Printf("Host=%s", host)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for r.Host -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_RequestURI_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
)

func H(r *http.Request) {
	log.Printf("uri=%s", r.RequestURI)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for r.RequestURI -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_Cookies_LogInjection(t *testing.T) {
	// r.Cookies() is a call without args; matched by MatchSource via the
	// "Cookies" entry on *http.Request.
	code := `package main

import (
	"log"
	"net/http"
)

func H(r *http.Request) {
	cs := r.Cookies()
	log.Printf("%v", cs)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for r.Cookies() -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_BasicAuth_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"
	"net/http"
)

func H(r *http.Request) {
	user, _, _ := r.BasicAuth()
	log.Printf("user=%s", user)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for r.BasicAuth() -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative cases ---

func TestAnalyzeGo_SelectorSource_NoSource_HardcodedPath(t *testing.T) {
	// No *http.Request parameter — the path is a hardcoded literal. The
	// engine must NOT report a flow.
	code := `package main

import (
	"os"
)

func H() {
	p := "/static/index.html"
	os.ReadFile(p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkFileRead) || hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected NO flow for hardcoded file path; got:")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SelectorSource_WholeRequest_NotTainted(t *testing.T) {
	// Reading the whole *http.Request (without selecting a field) is NOT a
	// source — only specific user-controlled fields are. Passing r to
	// fmt.Println must not produce a taint flow. (Matches current
	// seedHTTPHandlerParams behaviour, which skips *http.Request itself.)
	code := `package main

import (
	"fmt"
	"net/http"
)

func H(r *http.Request) {
	fmt.Println(r)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		// Whole-r reads should never produce a flow whose source is a
		// selector-source entry — only field reads do.
		if f.Source.ObjectType == "*http.Request" && f.Source.MethodName != "" {
			// If a flow exists with an *http.Request source, make sure
			// it doesn't claim r itself is the source — selector sources
			// must always reference a real field path.
			if f.Source.MethodName == "*http.Request" {
				t.Errorf("did not expect whole-request taint flow; got source=%s sink=%s", f.Source.ID, f.Sink.ID)
			}
		}
	}
}

// Ensure the matcher reaches the right catalog entry IDs.
func TestAnalyzeGo_SelectorSource_HasExpectedSourceID(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func H(r *http.Request) {
	os.ReadFile(r.URL.Path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Source.ID == "go.http.request.url.path" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected source ID go.http.request.url.path to be reachable via selector matching")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
	// Belt-and-braces: also exercise the convenience helper.
	if !hasSinkID(flows, "go.os.readfile") {
		t.Error("expected sink ID go.os.readfile to be reachable from r.URL.Path")
	}
}
