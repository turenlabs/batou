package astflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/taint"

	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou/internal/taint/languages"
)

func hasTaintFlow(flows []taint.TaintFlow, sinkCategory taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == sinkCategory {
			return true
		}
	}
	return false
}

func hasSourceCategory(flows []taint.TaintFlow, srcCat taint.SourceCategory) bool {
	for _, f := range flows {
		if f.Source.Category == srcCat {
			return true
		}
	}
	return false
}

// =========================================================================
// End-to-end flow tests
// =========================================================================

func TestAnalyzeGo_SQLInjection_Concat(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection taint flow for FormValue -> string concat -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_SQLInjection_URLQueryGet(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection taint flow for URL.Query().Get -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_CommandInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command(cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection taint flow for FormValue -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_XSS_Fprintf(t *testing.T) {
	// Catalog's DangerousArgs for Fprintf is []int{1} (the format string position).
	// Tainted data at arg index 1 triggers the flow.
	code := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	msg := "<h1>Hello, " + name + "</h1>"
	fmt.Fprintf(w, msg)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS taint flow for FormValue -> concat -> fmt.Fprintf(w, msg)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_Sanitized_NoFlow(t *testing.T) {
	code := `package main

import (
	"fmt"
	"html"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := html.EscapeString(name)
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS taint flow when html.EscapeString is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_MultiReturn(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	query := "SELECT * FROM users WHERE id = " + id
	rows, err := db.Query(query)
	_ = rows
	_ = err
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow even with multi-return assignment")
	}
}

func TestAnalyzeGo_NoSource_LiteralString(t *testing.T) {
	code := `package main

import "database/sql"

func handler() {
	db.Query("SELECT * FROM users WHERE id = 1")
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO taint flow when query uses only literal strings")
	}
}

func TestAnalyzeGo_OsGetenv(t *testing.T) {
	code := `package main

import (
	"os"
	"os/exec"
)

func handler() {
	cmd := os.Getenv("CMD")
	exec.Command(cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for os.Getenv -> exec.Command")
	}
	if !hasSourceCategory(flows, taint.SrcEnvVar) {
		t.Error("expected source category to be env_var")
	}
}

func TestAnalyzeGo_StringConcatPropagation(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	upper := name
	greeting := "Hello, " + upper
	query := "SELECT * FROM users WHERE greeting = '" + greeting + "'"
	db.Query(query)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through string concatenation chain")
	}
}

func TestAnalyzeGo_Closure(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fn := func() {
		name := r.FormValue("name")
		db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	}
	fn()
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow inside closure")
	}
}

func TestAnalyzeGo_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("file")
	os.Open(path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal taint flow for FormValue -> os.Open")
	}
}

func TestAnalyzeGo_SSRF(t *testing.T) {
	code := `package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	http.Get(url)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF taint flow for FormValue -> http.Get")
	}
}

func TestAnalyzeGo_OpenRedirect(t *testing.T) {
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("redirect")
	http.Redirect(w, r, target, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect taint flow for FormValue -> http.Redirect")
	}
}

func TestAnalyzeGo_StrconvSanitizer(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, _ := strconv.Atoi(idStr)
	_ = id
	db.Query("SELECT * FROM users WHERE id = " + idStr)
}

var db *sql.DB
`
	// Note: strconv.Atoi sanitizes idStr but it's assigned to 'id', not 'idStr'.
	// The query still uses the original tainted 'idStr', so a flow should still be found.
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow since original tainted var is used, not sanitized one")
	}
}

func TestAnalyzeGo_FilepathBaseSanitizer(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userPath := r.FormValue("file")
	safeName := filepath.Base(userPath)
	os.Open(safeName)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Error("expected NO file write taint flow when filepath.Base is used")
		}
	}
}

func TestAnalyzeGo_GinFramework(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gin-gonic/gin"
)

func handler(c *gin.Context) {
	id := c.Query("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Gin c.Query -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_FlowHasCorrectMetadata(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if len(flows) == 0 {
		t.Fatal("expected at least one taint flow")
	}

	flow := flows[0]
	if flow.FilePath != "/app/handler.go" {
		t.Errorf("expected FilePath /app/handler.go, got %s", flow.FilePath)
	}
	if flow.ScopeName != "handler" {
		t.Errorf("expected ScopeName handler, got %s", flow.ScopeName)
	}
	if flow.Source.Category != taint.SrcUserInput {
		t.Errorf("expected source category user_input, got %s", flow.Source.Category)
	}
	if flow.Sink.Category != taint.SnkSQLQuery {
		t.Errorf("expected sink category sql_query, got %s", flow.Sink.Category)
	}
	if flow.Confidence <= 0 || flow.Confidence > 1.0 {
		t.Errorf("expected confidence in (0, 1.0], got %f", flow.Confidence)
	}
	if len(flow.Steps) == 0 {
		t.Error("expected at least one flow step")
	}
}

func TestAnalyzeGo_ToFinding(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if len(flows) == 0 {
		t.Fatal("expected at least one taint flow")
	}

	finding := flows[0].ToFinding()
	if !strings.HasPrefix(finding.RuleID, "BATOU-TAINT-") {
		t.Errorf("expected RuleID to start with BATOU-TAINT-, got %s", finding.RuleID)
	}
	if finding.FilePath != "/app/handler.go" {
		t.Errorf("expected FilePath /app/handler.go, got %s", finding.FilePath)
	}
	if finding.CWEID == "" {
		t.Error("expected CWEID to be set")
	}
}

// =========================================================================
// Concurrency tests
// =========================================================================

func TestAnalyzeGo_ChannelSendReceive(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ch := make(chan string, 1)
	name := r.FormValue("name")
	ch <- name
	val := <-ch
	db.Query("SELECT * FROM users WHERE name = '" + val + "'")
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through channel send/receive")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_SelectReceive(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ch := make(chan string, 1)
	name := r.FormValue("name")
	ch <- name
	select {
	case v := <-ch:
		db.Query("SELECT * FROM users WHERE name = '" + v + "'")
	}
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through select receive")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_GoRoutine(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	go func() {
		db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	}()
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow through goroutine closure")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_DeferSink(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	defer exec.Command(cmd).Run()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow through defer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// CatalogMatcher tests
// =========================================================================

func TestCatalogMatcher_IndexesSources(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	sinks := cat.Sinks()
	sanitizers := cat.Sanitizers()

	matcher := NewCatalogMatcher(sources, sinks, sanitizers, nil)

	// Verify sources are indexed.
	if len(matcher.sourcesByMethod) == 0 {
		t.Error("expected sourcesByMethod to be populated")
	}
	// FormValue should be indexed.
	if len(matcher.sourcesByMethod["FormValue"]) == 0 {
		t.Error("expected FormValue to be indexed as source")
	}

	// Verify sinks are indexed.
	if len(matcher.sinksByMethod) == 0 {
		t.Error("expected sinksByMethod to be populated")
	}
	// Query should be indexed.
	if len(matcher.sinksByMethod["Query"]) == 0 {
		t.Error("expected Query to be indexed as sink")
	}

	// Verify sanitizers are indexed.
	if len(matcher.sanitizersByMethod) == 0 {
		t.Error("expected sanitizersByMethod to be populated")
	}
	// EscapeString should be indexed.
	if len(matcher.sanitizersByMethod["EscapeString"]) == 0 {
		t.Error("expected EscapeString to be indexed as sanitizer")
	}
}

func TestExtractMethodNames(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"FormValue", []string{"FormValue"}},
		{"Query/Param/PostForm", []string{"Query", "Param", "PostForm"}},
		{"os.Args", []string{"Args"}},
		{"URL.Query", []string{"Query"}},
		{"slog.Info", []string{"Info"}},
		{"Header.Get", []string{"Get"}},
	}

	for _, tt := range tests {
		got := extractMethodNames(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("extractMethodNames(%q) = %v, want %v", tt.input, got, tt.expected)
			continue
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("extractMethodNames(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.expected[i])
			}
		}
	}
}

// =========================================================================
// TypeEnv tests
// =========================================================================

func TestTypeEnv_ImportResolution(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	_ = flows // Just checking it parses without panic.
}

func TestAnalyzeGo_EmptyFile(t *testing.T) {
	flows := AnalyzeGo("", "/app/empty.go")
	if len(flows) != 0 {
		t.Errorf("expected no flows for empty file, got %d", len(flows))
	}
}

func TestAnalyzeGo_InvalidGo(t *testing.T) {
	flows := AnalyzeGo("this is not go code {{{", "/app/bad.go")
	if len(flows) != 0 {
		t.Errorf("expected no flows for invalid Go, got %d", len(flows))
	}
}

func TestAnalyzeGo_NoFunctions(t *testing.T) {
	code := `package main

var x = 42
`
	flows := AnalyzeGo(code, "/app/nofunc.go")
	if len(flows) != 0 {
		t.Errorf("expected no flows for file with no functions, got %d", len(flows))
	}
}
