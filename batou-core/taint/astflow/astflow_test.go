package astflow

import (
	"strings"
	"testing"
	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
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

// =========================================================================
// SnkFileRead (path traversal via file reads) tests
// =========================================================================

func TestAnalyzeGo_FileRead_FilepathWalk(t *testing.T) {
	code := `package main

import (
	"net/http"
	"path/filepath"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	dir := r.FormValue("dir")
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		return nil
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read taint flow for FormValue -> filepath.Walk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_FileRead_OsStat(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	_, err := os.Stat(path)
	if err != nil {
		http.Error(w, "not found", 404)
	}
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read taint flow for FormValue -> os.Stat")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_FileRead_ReadDir(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	dir := r.FormValue("dir")
	entries, _ := os.ReadDir(dir)
	_ = entries
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read taint flow for FormValue -> os.ReadDir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_FileRead_TemplateParseGlob(t *testing.T) {
	code := `package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	pattern := r.FormValue("pattern")
	tmpl, _ := template.ParseGlob(pattern)
	tmpl.Execute(w, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read taint flow for FormValue -> template.ParseGlob")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_FileRead_ReadDir_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	dir := r.FormValue("dir")
	safe := filepath.Base(dir)
	entries, _ := os.ReadDir(safe)
	_ = entries
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected filepath.Base to sanitize SnkFileRead, but found a flow")
		}
	}
}

// =========================================================================
// New source tests: framework call-based sources
// =========================================================================

func TestAnalyzeGo_GinDefaultQuery_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gin-gonic/gin"
)

func handler(c *gin.Context) {
	name := c.DefaultQuery("name", "")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Gin DefaultQuery -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_FiberBodyParser_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gofiber/fiber/v2"
)

func handler(c *fiber.Ctx) error {
	name := c.Query("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	return nil
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Fiber c.Query -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// New sink tests: SSRF, header injection
// =========================================================================

func TestAnalyzeGo_SSRF_NewRequestWithContext(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	req, _ := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	_ = req
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for FormValue -> http.NewRequestWithContext")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_SSRF_HttpPost(t *testing.T) {
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("callback")
	http.Post(url, "application/json", nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for FormValue -> http.Post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_GinHeaderInjection(t *testing.T) {
	code := `package main

import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	origin := c.Query("origin")
	c.Header("Access-Control-Allow-Origin", origin)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for Gin c.Query -> c.Header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_GinSetCookie(t *testing.T) {
	code := `package main

import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	val := c.Query("theme")
	c.SetCookie("pref", val, 3600, "/", "", false, true)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for Gin c.Query -> c.SetCookie")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_SSRF_HttpPostForm(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("webhook")
	http.PostForm(target, url.Values{})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for FormValue -> http.PostForm")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe pattern tests (sanitizer verification)
// =========================================================================

func TestAnalyzeGo_SafeRedirect_URLParse(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("redirect")
	u, err := url.Parse(target)
	if err != nil {
		return
	}
	http.Redirect(w, r, u.Path, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected url.Parse to sanitize redirect, but found a flow")
		}
	}
}

// =========================================================================
// New sink category tests: deserialization, command injection, LDAP
// =========================================================================

func TestAnalyzeGo_YAMLDeserialization(t *testing.T) {
	code := `package main

import (
	"net/http"

	"gopkg.in/yaml.v3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("config")
	var data map[string]interface{}
	yaml.Unmarshal([]byte(input), &data)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization taint flow for FormValue -> yaml.Unmarshal")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_MsgpackDeserialization(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/vmihailenco/msgpack/v5"
)

func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("data")
	var result map[string]interface{}
	msgpack.Unmarshal([]byte(input), &result)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization taint flow for FormValue -> msgpack.Unmarshal")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_SyscallExec(t *testing.T) {
	code := `package main

import (
	"net/http"
	"syscall"
)

func handler(w http.ResponseWriter, r *http.Request) {
	bin := r.FormValue("binary")
	syscall.Exec(bin, []string{bin}, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection taint flow for FormValue -> syscall.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_OsStartProcess(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	prog := r.FormValue("program")
	os.StartProcess(prog, []string{prog}, &os.ProcAttr{})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection taint flow for FormValue -> os.StartProcess")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PluginOpen(t *testing.T) {
	code := `package main

import (
	"net/http"
	"plugin"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("plugin_path")
	plugin.Open(path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	// plugin.Open matches both SnkEval (our new entry) and SnkFileWrite (go.os.open)
	// due to shared "Open" method name in the matcher. Either flow confirms taint tracking works.
	if len(flows) == 0 {
		t.Error("expected taint flow for FormValue -> plugin.Open, got none")
	}
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval || f.Sink.Category == taint.SnkFileWrite {
			found = true
		}
	}
	if !found {
		t.Error("expected eval or file_write taint flow for FormValue -> plugin.Open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_LDAPBind(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	conn, _ := ldap.DialURL("ldap://localhost:389")
	dn := "uid=" + username + ",ou=people,dc=example,dc=com"
	conn.Bind(dn, "password")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection taint flow for FormValue -> string concat -> Bind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_LDAPAddRequest(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cn := r.FormValue("cn")
	dn := "cn=" + cn + ",ou=people,dc=example,dc=com"
	addReq := ldap.NewAddRequest(dn, nil)
	_ = addReq
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection taint flow for FormValue -> string concat -> ldap.NewAddRequest")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Sanitizer tests — command injection
// =========================================================================

func TestAnalyzeGo_ShellesscapeQuote_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"

	"github.com/alessio/shellescape"
)

func handler(w http.ResponseWriter, r *http.Request) {
	arg := r.FormValue("arg")
	safe := shellescape.Quote(arg)
	exec.Command("echo", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO command injection flow when shellescape.Quote is used")
		}
	}
}

func TestAnalyzeGo_ShlexSplit_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"

	"github.com/google/shlex"
)

func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("cmd")
	args, _ := shlex.Split(input)
	exec.Command(args[0], args[1:]...)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO command injection flow when shlex.Split is used")
		}
	}
}

// =========================================================================
// Sanitizer tests — UUID validation
// =========================================================================

func TestAnalyzeGo_UUIDParse_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"

	"github.com/google/uuid"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	parsed, err := uuid.Parse(id)
	if err != nil {
		return
	}
	db.Query("SELECT * FROM users WHERE id = '" + parsed.String() + "'")
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when uuid.Parse validates input")
		}
	}
}

// =========================================================================
// Sanitizer tests — hex encoding
// =========================================================================

func TestAnalyzeGo_HexEncodeToString_Sanitized(t *testing.T) {
	code := `package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	safe := hex.EncodeToString([]byte(data))
	fmt.Fprintf(w, "<div>%s</div>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when hex.EncodeToString produces safe alphanumeric output")
		}
	}
}

// =========================================================================
// Sanitizer tests — JSON marshal (HTML safe)
// =========================================================================

func TestAnalyzeGo_JSONMarshal_Sanitized(t *testing.T) {
	code := `package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe, _ := json.Marshal(name)
	fmt.Fprintf(w, "<script>var x = %s;</script>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when json.Marshal escapes <, >, &")
		}
	}
}

// =========================================================================
// Sanitizer tests — filepath.Rel and filepath.Match
// =========================================================================

func TestAnalyzeGo_FilepathRel_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	rel, err := filepath.Rel("/base", name)
	if err != nil {
		return
	}
	os.Stat(rel)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO file read flow when filepath.Rel constrains path")
		}
	}
}

// =========================================================================
// Sanitizer tests — deserialization (DisallowUnknownFields)
// =========================================================================

func TestAnalyzeGo_JSONDisallowUnknownFields_Sanitized(t *testing.T) {
	code := `package main

import (
	"encoding/json"
	"net/http"
)

type Config struct {
	Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var cfg Config
	dec.Decode(&cfg)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("expected NO deserialization flow when DisallowUnknownFields is used")
		}
	}
}

// =========================================================================
// Sanitizer tests — trust boundary (CSRF, JWT)
// =========================================================================

func TestAnalyzeGo_CSRFProtect_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/gorilla/csrf"
)

func handler(w http.ResponseWriter, r *http.Request) {
	token := csrf.Token(r)
	_ = csrf.Protect([]byte("secret"))
	_ = token
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when csrf.Protect/Token is used")
		}
	}
}

func TestAnalyzeGo_JWTParse_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func handler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil || !token.Valid {
		return
	}
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when jwt.Parse validates token")
		}
	}
}

// =========================================================================
// Sanitizer tests — query builders (squirrel)
// =========================================================================

func TestAnalyzeGo_SquirrelSelect_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"

	sq "github.com/Masterminds/squirrel"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	query, args, _ := sq.Select("*").From("users").Where(sq.Eq{"name": name}).ToSql()
	db.Query(query, args...)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when squirrel query builder is used")
		}
	}
}

// =========================================================================
// Negative tests — verify flows still detected WITHOUT sanitizers
// =========================================================================

func TestAnalyzeGo_CommandInjection_Unsanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command("sh", "-c", cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for FormValue -> exec.Command without sanitizer")
	}
}

// =========================================================================
// MongoDB NoSQL Injection (CWE-943) tests
// =========================================================================

func TestAnalyzeGo_MongoDBFindOne_NoSQLInjection(t *testing.T) {
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("user")
	collection.FindOne(ctx, bson.D{{"username", username}})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for FormValue -> collection.FindOne")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_MongoDBAggregate_NoSQLInjection(t *testing.T) {
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	field := r.FormValue("field")
	collection.Aggregate(ctx, bson.D{{"$group", bson.D{{"_id", field}}}})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for FormValue -> collection.Aggregate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_MongoDBFindOne_Safe_Hardcoded(t *testing.T) {
	code := `package main

func handler() {
	collection.FindOne(ctx, bson.D{{"status", "active"}})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.mongo.findone" {
			t.Errorf("expected no NoSQL injection for hardcoded query, got src=%s", f.Source.ID)
		}
	}
}

// =========================================================================
// AWS DynamoDB PartiQL NoSQL Injection (CWE-943) tests
// =========================================================================

func TestAnalyzeGo_DynamoDBExecuteStatement_PartiQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client, r *http.Request) {
	userID := r.URL.Query().Get("id")
	stmt := "SELECT * FROM users WHERE id = '" + userID + "'"
	svc.ExecuteStatement(context.TODO(), &dynamodb.ExecuteStatementInput{
		Statement: aws.String(stmt),
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.dynamodb.executestatement" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PartiQL injection flow for query param -> ExecuteStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_DynamoDBBatchExecuteStatement_PartiQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func handler(client *dynamodb.Client, r *http.Request) {
	name := r.FormValue("name")
	stmt := "SELECT * FROM users WHERE name = '" + name + "'"
	client.BatchExecuteStatement(context.TODO(), &dynamodb.BatchExecuteStatementInput{
		Statements: []types.BatchStatementRequest{
			{Statement: aws.String(stmt)},
		},
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.dynamodb.batchexecutestatement" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PartiQL injection flow for FormValue -> BatchExecuteStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_DynamoDBExecuteTransaction_PartiQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func handler(ddb *dynamodb.Client, r *http.Request) {
	table := r.URL.Query().Get("table")
	stmt := "DELETE FROM " + table + " WHERE id = '1'"
	ddb.ExecuteTransaction(context.TODO(), &dynamodb.ExecuteTransactionInput{
		TransactStatements: []types.ParameterizedStatement{
			{Statement: aws.String(stmt)},
		},
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.dynamodb.executetransaction" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PartiQL injection flow for query param -> ExecuteTransaction")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_DynamoDBExecuteStatement_Safe_Hardcoded(t *testing.T) {
	code := `package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client) {
	svc.ExecuteStatement(context.TODO(), &dynamodb.ExecuteStatementInput{
		Statement: aws.String("SELECT * FROM users WHERE status = 'active'"),
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.dynamodb.executestatement" {
			t.Errorf("expected no PartiQL injection for hardcoded statement, got src=%s", f.Source.ID)
		}
	}
}

// =========================================================================
// Apache Cassandra / ScyllaDB CQL Injection via gocql (CWE-943) tests
// =========================================================================

func TestAnalyzeGo_GocqlSessionQuery_CQLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/gocql/gocql"
)

func handler(session *gocql.Session, r *http.Request) {
	userID := r.URL.Query().Get("id")
	stmt := "SELECT * FROM users WHERE id = '" + userID + "'"
	session.Query(stmt).Exec()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.gocql.session.query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CQL injection flow for query param -> gocql Session.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_GocqlBatchQuery_CQLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/gocql/gocql"
)

func handler(batch *gocql.Batch, r *http.Request) {
	name := r.FormValue("name")
	stmt := "INSERT INTO users (name) VALUES ('" + name + "')"
	batch.Query(stmt)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.gocql.batch.query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CQL injection flow for FormValue -> gocql Batch.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_GocqlSessionQuery_Safe_Hardcoded(t *testing.T) {
	code := `package main

import (
	"github.com/gocql/gocql"
)

func handler(session *gocql.Session) {
	session.Query("SELECT * FROM users WHERE status = 'active'").Exec()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.gocql.session.query" {
			t.Errorf("expected no CQL injection for hardcoded statement, got src=%s", f.Source.ID)
		}
	}
}

// =========================================================================
// Sanitizer tests — base64, pq, sha256, path.Clean
// =========================================================================

func TestAnalyzeGo_Base64Encode_Sanitized(t *testing.T) {
	code := `package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := base64.StdEncoding.EncodeToString([]byte(name))
	fmt.Fprintf(w, "<div>%s</div>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when base64.StdEncoding.EncodeToString encodes data")
		}
	}
}

func TestAnalyzeGo_PqQuoteLiteral_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := pq.QuoteLiteral(name)
	db.Query("SELECT * FROM users WHERE name = " + safe)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection when pq.QuoteLiteral escapes input")
		}
	}
}

func TestAnalyzeGo_SHA256_Sanitized(t *testing.T) {
	code := `package main

import (
	"crypto/sha256"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	hash := sha256.Sum256([]byte(password))
	_ = hash
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when sha256.Sum256 is used")
		}
	}
}

func TestAnalyzeGo_URLJoinPath_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("path")
	safe, _ := url.JoinPath("https://example.com", target)
	http.Redirect(w, r, safe, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected NO redirect flow when url.JoinPath safely constructs the URL")
		}
	}
}

func TestAnalyzeGo_FileRead_Unsanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	os.Stat(name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for FormValue -> os.Stat without sanitizer")
	}
}

// =========================================================================
// Trust boundary — unsanitized flows
// =========================================================================

func TestAnalyzeGo_TrustBoundary_OsSetenv_Unsanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	val := r.FormValue("config")
	os.Setenv("APP_CONFIG", val)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for FormValue -> os.Setenv without sanitizer")
	}
}

func TestAnalyzeGo_TrustBoundary_ContextWithValue_Unsanitized(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("user_id")
	ctx := context.WithValue(r.Context(), "userID", userID)
	_ = ctx
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for FormValue -> context.WithValue without sanitizer")
	}
}

// =========================================================================
// Trust boundary — sanitized flows (strconv, uuid, mail, validator)
// =========================================================================

func TestAnalyzeGo_TrustBoundary_StrconvAtoi_Sanitized(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return
	}
	ctx := context.WithValue(r.Context(), "userID", id)
	_ = ctx
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when strconv.Atoi sanitizes input before context.WithValue")
		}
	}
}

func TestAnalyzeGo_TrustBoundary_UUIDParse_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("secret"))

func handler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	idStr := r.FormValue("session_id")
	parsed, err := uuid.Parse(idStr)
	if err != nil {
		return
	}
	session.Values["session_id"] = parsed.String()
	session.Save(r, w)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when uuid.Parse validates input before session storage")
		}
	}
}

func TestAnalyzeGo_TrustBoundary_MailParseAddress_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/mail"

	"github.com/gorilla/sessions"
)

var store2 = sessions.NewCookieStore([]byte("secret"))

func handler(w http.ResponseWriter, r *http.Request) {
	session, _ := store2.Get(r, "session")
	emailStr := r.FormValue("email")
	addr, err := mail.ParseAddress(emailStr)
	if err != nil {
		return
	}
	session.Values["email"] = addr.Address
	session.Save(r, w)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when mail.ParseAddress validates input before session storage")
		}
	}
}

func TestAnalyzeGo_TrustBoundary_Validator_Sanitized(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

type UserInput struct {
	Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
	input := UserInput{Name: r.FormValue("name")}
	if err := validate.Struct(input); err != nil {
		return
	}
	ctx := context.WithValue(r.Context(), "input", input)
	_ = ctx
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when validate.Struct validates input before context.WithValue")
		}
	}
}

// --- New sanitizer tests (PR #282) ---

func TestAnalyzeGo_TemplateHTMLEscapeString_Sanitized(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := template.HTMLEscapeString(name)
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when template.HTMLEscapeString is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_TemplateJSEscapeString_Sanitized(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("callback")
	safe := template.JSEscapeString(input)
	fmt.Fprintf(w, "<script>var cb = '%s';</script>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when template.JSEscapeString is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_TemplateURLQueryEscaper_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	safe := template.URLQueryEscaper(next)
	http.Redirect(w, r, "/login?next="+safe, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected NO redirect flow when template.URLQueryEscaper is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_StrconvItoa_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	idStr := strconv.Itoa(id)
	query := "SELECT * FROM users WHERE id = " + idStr
	db.Query(query)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when strconv.Itoa is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_FilepathEvalSymlinks_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	clean := filepath.Clean(name)
	real, _ := filepath.EvalSymlinks(clean)
	data, _ := os.ReadFile(real)
	_ = data
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO file read flow when filepath.EvalSymlinks is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_NetipParseAddr_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/netip"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	http.Get("http://" + addr.String() + "/api")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when netip.ParseAddr validates the IP")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_NetipParsePrefix_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"net/netip"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cidr := r.FormValue("cidr")
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	http.Get("http://" + prefix.Addr().String() + "/api")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when netip.ParsePrefix validates the CIDR")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_PathJoin_Sanitized(t *testing.T) {
	code := `package main

import (
	"net/http"
	"path"
)

func handler(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	safe := path.Join("/app", next)
	http.Redirect(w, r, safe, http.StatusFound)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("expected NO redirect flow when path.Join normalizes the path")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_SqlNamed_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	arg := sql.Named("name", name)
	db.Query("SELECT * FROM users WHERE name = @name", arg)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when sql.Named is used for parameterized query")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ChaCha20Poly1305_Sanitized(t *testing.T) {
	code := `package main

import (
	"crypto/rand"
	"net/http"

	"golang.org/x/crypto/chacha20poly1305"
)

func handler(w http.ResponseWriter, r *http.Request) {
	secret := r.FormValue("secret")
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	aead, _ := chacha20poly1305.New(key)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	_ = aead.Seal(nil, nonce, []byte(secret), nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when chacha20poly1305 is used")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestAnalyzeGo_HKDF_Sanitized(t *testing.T) {
	code := `package main

import (
	"crypto/sha256"
	"net/http"

	"golang.org/x/crypto/hkdf"
)

func handler(w http.ResponseWriter, r *http.Request) {
	passphrase := r.FormValue("passphrase")
	reader := hkdf.New(sha256.New, []byte(passphrase), nil, nil)
	key := make([]byte, 32)
	reader.Read(key)
	_ = key
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO weak crypto flow when hkdf.New is used for key derivation")
			t.Logf("  flow: %s -> %s (confidence: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
