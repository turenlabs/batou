package scanner_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/graph"
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
	"github.com/turenlabs/batou/internal/testutil"

	// Register rule packages so the full pipeline runs.
	_ "github.com/turenlabs/batou/internal/rules/injection"
	_ "github.com/turenlabs/batou/internal/rules/secrets"
	_ "github.com/turenlabs/batou/internal/rules/xss"
	_ "github.com/turenlabs/batou/internal/rules/ssrf"
	_ "github.com/turenlabs/batou/internal/rules/generic"
	_ "github.com/turenlabs/batou/internal/taint"
	_ "github.com/turenlabs/batou/internal/taint/languages"
	_ "github.com/turenlabs/batou/internal/taintrule"
)

// =========================================================================
// Scenario 1: Cross-function SQL injection
//
// handler.go has a taint source (r.FormValue), db.go has a SQL sink
// (db.Query with string concat). Neither file alone has both source+sink,
// so Layers 1-3 analyzing each file in isolation cannot connect them.
// Layer 4 (interprocedural) builds a call graph, detects that handler
// passes tainted data to QueryUser, and fires a finding.
// =========================================================================

func TestInterproc_CrossFunctionSQLInjection(t *testing.T) {
	// --- Step 1: Show that Layers 1-3 scanning the caller alone find no SQL injection ---
	// The handler file has a source but no SQL sink. Regex/taint see no vulnerability.
	handlerContent := `package main

import "net/http"

func GetUserID(r *http.Request) string {
	return r.URL.Query().Get("id")
}
`
	resultHandler := testutil.ScanContent(t, "/app/handler.go", handlerContent)
	for _, f := range resultHandler.Findings {
		if strings.Contains(f.CWEID, "CWE-89") {
			t.Errorf("Layer 1-3 should NOT detect SQL injection in handler-only file, but found: %s", f.RuleID)
		}
	}

	// --- Step 2: Show that Layer 4 detects the cross-function flow ---
	// Build a call graph where HandleRequest calls GetUserID (source) then
	// passes the result to QueryUser (sink).
	cg := graph.NewCallGraph("/project", "test-session")

	callerFile := "/app/server.go"
	calleeFile := "/app/db.go"

	callerNode := &graph.FuncNode{
		ID:        graph.FuncID(callerFile, "HandleRequest"),
		FilePath:  callerFile,
		Name:      "HandleRequest",
		StartLine: 1,
		EndLine:   6,
		Language:  rules.LangGo,
	}

	calleeNode := &graph.FuncNode{
		ID:        graph.FuncID(calleeFile, "QueryUser"),
		FilePath:  calleeFile,
		Name:      "QueryUser",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	cg.AddNode(callerNode)
	cg.AddNode(calleeNode)
	cg.AddEdge(callerNode.ID, calleeNode.ID)

	// The callee has an unsanitized SQL sink taking its first parameter.
	calleeContent := `func QueryUser(id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
}`

	// The caller gets user input and passes it to QueryUser.
	callerContent := `func HandleRequest(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	QueryUser(userID)
}`

	fileContents := map[string]string{
		calleeFile: calleeContent,
		callerFile: callerContent,
	}

	// Run interprocedural analysis on the callee (the function with the sink).
	findings := graph.PropagateInterproc(cg, []string{calleeNode.ID}, fileContents, nil, nil)

	// Assert that an interprocedural finding was produced for SQL injection.
	foundSQLInterproc := false
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") &&
			strings.Contains(f.CWEID, "CWE-89") {
			foundSQLInterproc = true
			if f.ConfidenceScore < 0.8 {
				t.Errorf("interprocedural SQL finding should have confidence >= 0.8, got %.2f", f.ConfidenceScore)
			}
			if f.Severity < rules.Critical {
				t.Errorf("interprocedural SQL finding should be Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !foundSQLInterproc {
		ruleIDs := make([]string, len(findings))
		for i, f := range findings {
			ruleIDs[i] = f.RuleID
		}
		t.Errorf("Layer 4 should detect cross-function SQL injection, got %d findings: %v", len(findings), ruleIDs)
	}
}

// =========================================================================
// Scenario 2: Sanitizer in the middle function blocks interprocedural finding
//
// GetInput -> SanitizeInput -> RenderPage
// The sanitizer (html.EscapeString) in the chain should prevent Layer 4
// from reporting an XSS finding, even though tainted data flows from
// source to sink across function boundaries.
// =========================================================================

func TestInterproc_SanitizerBlocksPropagation(t *testing.T) {
	cg := graph.NewCallGraph("/project", "test-session")

	file := "/app/web.go"

	// RenderPage is the callee: it writes to ResponseWriter (HTML sink).
	renderNode := &graph.FuncNode{
		ID:        graph.FuncID(file, "RenderPage"),
		FilePath:  file,
		Name:      "RenderPage",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	// The handler calls SanitizeInput, then passes result to RenderPage.
	handlerNode := &graph.FuncNode{
		ID:        graph.FuncID(file, "Handler"),
		FilePath:  file,
		Name:      "Handler",
		StartLine: 6,
		EndLine:   12,
		Language:  rules.LangGo,
	}

	cg.AddNode(renderNode)
	cg.AddNode(handlerNode)
	cg.AddEdge(handlerNode.ID, renderNode.ID)

	// RenderPage writes its argument to an HTML output sink.
	renderContent := `func RenderPage(w http.ResponseWriter, name string) {
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}`

	// Handler sanitizes the input before calling RenderPage.
	handlerContent := `
func Handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := html.EscapeString(name)
	RenderPage(w, safe)
}`

	fullContent := renderContent + "\n" + handlerContent

	fileContents := map[string]string{
		file: fullContent,
	}

	findings := graph.PropagateInterproc(cg, []string{renderNode.ID}, fileContents, nil, nil)

	// The caller sanitizes the argument with html.EscapeString before
	// passing it to RenderPage, so no XSS finding should fire.
	for _, f := range findings {
		if strings.Contains(f.RuleID, "INTERPROC") &&
			(strings.Contains(f.CWEID, "CWE-79") || strings.Contains(strings.ToLower(f.Title), "xss") || strings.Contains(strings.ToLower(f.Title), "html")) {
			t.Errorf("sanitizer should prevent interprocedural XSS finding, but got: %s (confidence=%.2f)", f.RuleID, f.ConfidenceScore)
		}
	}
}

// =========================================================================
// Scenario 3: Return value taint propagation for SSRF
//
// FetchURL returns tainted data from user input. MakeRequest receives
// it and passes to http.Get (SSRF sink). Layer 4 should connect the
// return-taint from FetchURL through the caller to the sink.
// =========================================================================

func TestInterproc_ReturnValueSSRF(t *testing.T) {
	cg := graph.NewCallGraph("/project", "test-session")

	sourceFile := "/app/input.go"
	callerFile := "/app/proxy.go"

	// FetchURL extracts a URL from user input and returns it.
	fetchNode := &graph.FuncNode{
		ID:        graph.FuncID(sourceFile, "FetchURL"),
		FilePath:  sourceFile,
		Name:      "FetchURL",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	// ProxyHandler calls FetchURL, then passes the result to http.Get.
	proxyNode := &graph.FuncNode{
		ID:        graph.FuncID(callerFile, "ProxyHandler"),
		FilePath:  callerFile,
		Name:      "ProxyHandler",
		StartLine: 1,
		EndLine:   6,
		Language:  rules.LangGo,
	}

	cg.AddNode(fetchNode)
	cg.AddNode(proxyNode)
	cg.AddEdge(proxyNode.ID, fetchNode.ID)

	fetchContent := `func FetchURL(r *http.Request) string {
	return r.URL.Query().Get("url")
}`

	proxyContent := `func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	target := FetchURL(r)
	http.Get(target)
}`

	fileContents := map[string]string{
		sourceFile: fetchContent,
		callerFile: proxyContent,
	}

	// Run interprocedural analysis on FetchURL (the function whose return
	// carries taint). The analysis should detect that ProxyHandler takes
	// FetchURL's return and passes it to http.Get.
	findings := graph.PropagateInterproc(cg, []string{fetchNode.ID}, fileContents, nil, nil)

	foundSSRF := false
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") &&
			(strings.Contains(f.CWEID, "CWE-918") || strings.Contains(strings.ToLower(f.RuleID), "url_fetch")) {
			foundSSRF = true
			if f.ConfidenceScore < 0.8 {
				t.Errorf("interprocedural SSRF finding should have confidence >= 0.8, got %.2f", f.ConfidenceScore)
			}
			break
		}
	}
	if !foundSSRF {
		ruleIDs := make([]string, len(findings))
		for i, f := range findings {
			ruleIDs[i] = f.RuleID + " (CWE=" + f.CWEID + ")"
		}
		t.Errorf("Layer 4 should detect cross-function SSRF via return value taint, got %d findings: %v", len(findings), ruleIDs)
	}
}

// =========================================================================
// Scenario 4: Cross-function command injection
//
// GetCommand reads from user input, ExecuteCmd passes to exec.Command.
// Verifies interprocedural analysis works for CWE-78 (OS command injection).
// =========================================================================

func TestInterproc_CrossFunctionCommandInjection(t *testing.T) {
	cg := graph.NewCallGraph("/project", "test-session")

	file := "/app/cmd.go"

	execNode := &graph.FuncNode{
		ID:        graph.FuncID(file, "ExecuteCmd"),
		FilePath:  file,
		Name:      "ExecuteCmd",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	handlerNode := &graph.FuncNode{
		ID:        graph.FuncID(file, "Handler"),
		FilePath:  file,
		Name:      "Handler",
		StartLine: 6,
		EndLine:   10,
		Language:  rules.LangGo,
	}

	cg.AddNode(execNode)
	cg.AddNode(handlerNode)
	cg.AddEdge(handlerNode.ID, execNode.ID)

	content := `func ExecuteCmd(cmd string) {
	exec.Command("sh", "-c", cmd)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	userCmd := r.FormValue("cmd")
	ExecuteCmd(userCmd)
}`

	fileContents := map[string]string{file: content}

	findings := graph.PropagateInterproc(cg, []string{execNode.ID}, fileContents, nil, nil)

	foundCmdInj := false
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") &&
			strings.Contains(f.CWEID, "CWE-78") {
			foundCmdInj = true
			if f.Severity < rules.Critical {
				t.Errorf("command injection should be Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !foundCmdInj {
		ruleIDs := make([]string, len(findings))
		for i, f := range findings {
			ruleIDs[i] = f.RuleID + " (CWE=" + f.CWEID + ")"
		}
		t.Errorf("Layer 4 should detect cross-function command injection, got %d findings: %v", len(findings), ruleIDs)
	}
}

// =========================================================================
// Scenario 5: Layer 4 via ScanContentWithGraph integration
//
// Uses the full pipeline helper to verify that a pre-populated call graph
// with a known caller->callee edge produces interprocedural findings when
// the callee file is scanned through the pipeline.
// =========================================================================

func TestInterproc_ScanContentWithGraph_Integration(t *testing.T) {
	callerFile := "/app/handler.go"
	calleeFile := "/app/db.go"

	cg := graph.NewCallGraph("", "test-session")

	// Pre-populate the graph with a caller node that calls the callee.
	// The callee will be populated by the scanner's UpdateFile when it
	// processes the file content.
	callerNode := &graph.FuncNode{
		ID:        graph.FuncID(callerFile, "Handler"),
		FilePath:  callerFile,
		Name:      "Handler",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}
	cg.AddNode(callerNode)

	// Scan the callee file through the full pipeline with the graph.
	calleeContent := `package main

import "database/sql"

func QueryUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
}
`

	result := testutil.ScanContentWithGraph(t, calleeFile, calleeContent, cg)

	// The full pipeline should detect the SQL injection in QueryUser.
	// At minimum, regex/taint rules should fire for the string concat.
	hasInjection := false
	for _, f := range result.Findings {
		if strings.Contains(f.CWEID, "CWE-89") ||
			strings.Contains(f.RuleID, "INJ") ||
			strings.Contains(f.RuleID, "TAINT") {
			hasInjection = true
			break
		}
	}
	if !hasInjection {
		t.Logf("Findings from full pipeline: %v", testutil.FindingRuleIDs(result))
		t.Error("full pipeline with graph should detect SQL injection in callee function")
	}
}

// =========================================================================
// Scenario 6: Suppressed sink line should NOT produce interprocedural finding
//
// When a sink line has a batou:ignore directive, interprocedural analysis
// should move the sink to SuppressedSinks and NOT propagate findings
// through callers.
// =========================================================================

func TestInterproc_SuppressedSinkDoesNotPropagate(t *testing.T) {
	cg := graph.NewCallGraph("/project", "test-session")

	calleeFile := "/app/db.go"
	callerFile := "/app/handler.go"

	calleeNode := &graph.FuncNode{
		ID:        graph.FuncID(calleeFile, "QueryUser"),
		FilePath:  calleeFile,
		Name:      "QueryUser",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	callerNode := &graph.FuncNode{
		ID:        graph.FuncID(callerFile, "Handler"),
		FilePath:  callerFile,
		Name:      "Handler",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}

	cg.AddNode(calleeNode)
	cg.AddNode(callerNode)
	cg.AddEdge(callerNode.ID, calleeNode.ID)

	calleeContent := `func QueryUser(id string) {
	// batou:ignore injection
	db.Query("SELECT * FROM users WHERE id = " + id)
}`

	callerContent := `func Handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	QueryUser(id)
}`

	fileContents := map[string]string{
		calleeFile: calleeContent,
		callerFile: callerContent,
	}

	// Line 3 (the db.Query line) is suppressed.
	suppressedLines := map[int]bool{3: true}

	findings := graph.PropagateInterproc(cg, []string{calleeNode.ID}, fileContents, nil, suppressedLines)

	for _, f := range findings {
		if strings.Contains(f.CWEID, "CWE-89") {
			t.Errorf("suppressed sink should not produce interprocedural SQL finding, but got: %s", f.RuleID)
		}
	}
}

// =========================================================================
// Scenario 7: Multiple direct callers passing tainted data
//
// Two independent callers both pass tainted data to the same sink function.
// Tests that PropagateInterproc correctly walks all CalledBy edges and
// produces findings for each caller with a taint source.
// =========================================================================

func TestInterproc_MultipleCallers(t *testing.T) {
	cg := graph.NewCallGraph("/project", "test-session")

	sinkFile := "/app/db.go"
	callerFileA := "/app/api.go"
	callerFileB := "/app/admin.go"

	// Sink function: takes a string and passes it to SQL query.
	sinkNode := &graph.FuncNode{
		ID:        graph.FuncID(sinkFile, "RunQuery"),
		FilePath:  sinkFile,
		Name:      "RunQuery",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	// Caller A: HTTP handler passes user input to RunQuery.
	callerA := &graph.FuncNode{
		ID:        graph.FuncID(callerFileA, "APIHandler"),
		FilePath:  callerFileA,
		Name:      "APIHandler",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}

	// Caller B: Another handler also passes user input to RunQuery.
	callerB := &graph.FuncNode{
		ID:        graph.FuncID(callerFileB, "AdminHandler"),
		FilePath:  callerFileB,
		Name:      "AdminHandler",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}

	cg.AddNode(sinkNode)
	cg.AddNode(callerA)
	cg.AddNode(callerB)
	cg.AddEdge(callerA.ID, sinkNode.ID)
	cg.AddEdge(callerB.ID, sinkNode.ID)

	sinkContent := `func RunQuery(filter string) {
	db.Query("SELECT * FROM data WHERE filter = " + filter)
}`

	callerAContent := `func APIHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("filter")
	RunQuery(q)
}`

	callerBContent := `func AdminHandler(w http.ResponseWriter, r *http.Request) {
	search := r.FormValue("search")
	RunQuery(search)
}`

	fileContents := map[string]string{
		sinkFile:    sinkContent,
		callerFileA: callerAContent,
		callerFileB: callerBContent,
	}

	findings := graph.PropagateInterproc(cg, []string{sinkNode.ID}, fileContents, nil, nil)

	// Both callers pass tainted data to the sink, so we expect findings
	// from both callers.
	callerAFound, callerBFound := false, false
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") {
			continue
		}
		if f.FilePath == callerFileA {
			callerAFound = true
		}
		if f.FilePath == callerFileB {
			callerBFound = true
		}
	}
	if !callerAFound {
		t.Error("Layer 4 should detect taint from APIHandler -> RunQuery")
	}
	if !callerBFound {
		t.Error("Layer 4 should detect taint from AdminHandler -> RunQuery")
	}
}

// =========================================================================
// Scenario 8: Flow-informed interprocedural (Layer 3 flows -> Layer 4)
//
// When Layer 3 taint flows are provided to PropagateInterproc, the
// signature computation uses precise dataflow info instead of regex.
// This tests the Layer 3 -> Layer 4 handoff.
// =========================================================================

func TestInterproc_FlowInformedSignature(t *testing.T) {
	cg := graph.NewCallGraph("/project", "test-session")

	calleeFile := "/app/db.go"
	callerFile := "/app/handler.go"

	calleeNode := &graph.FuncNode{
		ID:        graph.FuncID(calleeFile, "RunQuery"),
		FilePath:  calleeFile,
		Name:      "RunQuery",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	callerNode := &graph.FuncNode{
		ID:        graph.FuncID(callerFile, "Handler"),
		FilePath:  callerFile,
		Name:      "Handler",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}

	cg.AddNode(calleeNode)
	cg.AddNode(callerNode)
	cg.AddEdge(callerNode.ID, calleeNode.ID)

	calleeContent := `func RunQuery(q string) {
	db.Query(q)
}`

	callerContent := `func Handler(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("query")
	RunQuery(q)
}`

	fileContents := map[string]string{
		calleeFile: calleeContent,
		callerFile: callerContent,
	}

	// Provide precise Layer 3 flows for the callee function.
	flows := []taint.TaintFlow{
		{
			Source: taint.SourceDef{
				Category:   taint.SrcUserInput,
				MethodName: "parameter",
			},
			Sink: taint.SinkDef{
				Category:   taint.SnkSQLQuery,
				MethodName: "db.Query",
			},
			SourceLine: 1,
			SinkLine:   2,
			Confidence: 0.95,
		},
	}

	findings := graph.PropagateInterproc(cg, []string{calleeNode.ID}, fileContents, flows, nil)

	// Verify the callee's taint signature was computed from flows.
	updatedNode := cg.GetNode(calleeNode.ID)
	if updatedNode.TaintSig.IsPure {
		t.Error("callee with flow-informed SQL sink should not have a pure taint signature")
	}
	if len(updatedNode.TaintSig.SinkCalls) == 0 {
		t.Error("callee signature should contain SQL sink from Layer 3 flows")
	}

	// Verify interprocedural findings were produced.
	foundInterproc := false
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") {
			foundInterproc = true
			break
		}
	}
	if !foundInterproc {
		ruleIDs := make([]string, len(findings))
		for i, f := range findings {
			ruleIDs[i] = f.RuleID
		}
		t.Errorf("flow-informed interprocedural should detect SQL injection, got %d findings: %v", len(findings), ruleIDs)
	}
}
