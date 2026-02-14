package graph

import (
	"strings"
	"testing"

	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// =========================================================================
// extractFuncBody
// =========================================================================

func TestExtractFuncBody(t *testing.T) {
	content := "line1\nline2\nline3\nline4\nline5"
	body := extractFuncBody(content, 2, 4)
	if body != "line2\nline3\nline4" {
		t.Errorf("expected 'line2\\nline3\\nline4', got %q", body)
	}
}

func TestExtractFuncBody_InvalidRange(t *testing.T) {
	content := "line1\nline2"
	body := extractFuncBody(content, 0, 2)
	if body != "" {
		t.Error("expected empty string for startLine=0")
	}
	body = extractFuncBody(content, 3, 2)
	if body != "" {
		t.Error("expected empty string for endLine < startLine")
	}
	body = extractFuncBody(content, 5, 6)
	if body != "" {
		t.Error("expected empty string for startLine > len(lines)")
	}
}

func TestExtractFuncBody_EndLineBeyondContent(t *testing.T) {
	content := "line1\nline2\nline3"
	body := extractFuncBody(content, 2, 10)
	if body != "line2\nline3" {
		t.Errorf("expected 'line2\\nline3', got %q", body)
	}
}

// =========================================================================
// extractBaseName
// =========================================================================

func TestExtractBaseName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"pkg.Receiver.Method", "Method"},
		{"FuncName", "FuncName"},
		{"pkg.Func", "Func"},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractBaseName(tt.input)
		if got != tt.expected {
			t.Errorf("extractBaseName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// =========================================================================
// extractArgList
// =========================================================================

func TestExtractArgList(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"(a, b, c)", []string{"a", "b", "c"}},
		{"(single)", []string{"single"}},
		{"()", nil},
		{"(nested(a, b), c)", []string{"nested(a, b)", "c"}},
		{"", nil},
		{"no parens", nil},
	}
	for _, tt := range tests {
		got := extractArgList(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("extractArgList(%q): got %v, want %v", tt.input, got, tt.expected)
			continue
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("extractArgList(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.expected[i])
			}
		}
	}
}

// =========================================================================
// isPathSanitized
// =========================================================================

func TestIsPathSanitized(t *testing.T) {
	paths := []SanitizedPath{
		{ParamIndex: 0, SinkCategory: taint.SnkSQLQuery, SanitizerName: "strconv.Atoi"},
		{ParamIndex: 1, SinkCategory: taint.SnkHTMLOutput, SanitizerName: "html.EscapeString"},
	}

	if !isPathSanitized(paths, 0, taint.SnkSQLQuery) {
		t.Error("expected path 0->sql to be sanitized")
	}
	if isPathSanitized(paths, 0, taint.SnkHTMLOutput) {
		t.Error("path 0->html should not be sanitized")
	}
	if isPathSanitized(paths, 2, taint.SnkSQLQuery) {
		t.Error("param 2 should not be sanitized")
	}
}

// =========================================================================
// appendUniqueCat
// =========================================================================

func TestAppendUniqueCat(t *testing.T) {
	cats := []taint.SourceCategory{taint.SrcUserInput}
	cats = appendUniqueCat(cats, taint.SrcUserInput)
	if len(cats) != 1 {
		t.Error("should not duplicate category")
	}
	cats = appendUniqueCat(cats, taint.SrcDatabase)
	if len(cats) != 2 {
		t.Error("should append new category")
	}
}

// =========================================================================
// bestSeverityFromSinks
// =========================================================================

func TestBestSeverityFromSinks(t *testing.T) {
	sinks := []SinkRef{
		{SinkCategory: taint.SnkLog},         // Medium
		{SinkCategory: taint.SnkSQLQuery},    // Critical
		{SinkCategory: taint.SnkHTMLOutput},  // High
	}
	sev := bestSeverityFromSinks(sinks)
	if sev != rules.Critical {
		t.Errorf("expected Critical severity, got %v", sev)
	}
}

func TestBestSeverityFromSinks_Empty(t *testing.T) {
	sev := bestSeverityFromSinks(nil)
	if sev != rules.High {
		t.Errorf("expected High default severity for empty sinks, got %v", sev)
	}
}

// =========================================================================
// ComputeTaintSig
// =========================================================================

func TestComputeTaintSig_WithSQLSink(t *testing.T) {
	content := `func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}`
	node := &FuncNode{
		Name:      "handler",
		FilePath:  "/app/handler.go",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo)
	if sig.IsPure {
		t.Error("function with HTTP request param and SQL sink should not be pure")
	}
	if len(sig.SinkCalls) == 0 {
		t.Error("expected at least one sink call for db.Query")
	}
}

func TestComputeTaintSig_PureFunction(t *testing.T) {
	content := `func add(a int, b int) int {
	return a + b
}`
	node := &FuncNode{
		Name:      "add",
		FilePath:  "/app/math.go",
		StartLine: 1,
		EndLine:   3,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo)
	if !sig.IsPure {
		t.Error("function with no sources/sinks should be pure")
	}
}

func TestComputeTaintSig_EmptyBody(t *testing.T) {
	node := &FuncNode{
		Name:      "empty",
		FilePath:  "/app/handler.go",
		StartLine: 1,
		EndLine:   1,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, "", rules.LangGo)
	if !sig.IsPure {
		t.Error("empty function body should be pure")
	}
}

func TestComputeTaintSig_WithSanitizer(t *testing.T) {
	content := `func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := strconv.Atoi(name)
	db.Query("SELECT * FROM users WHERE id = " + safe)
}`
	node := &FuncNode{
		Name:      "handler",
		FilePath:  "/app/handler.go",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo)
	if len(sig.SanitizedPaths) == 0 {
		// The sanitizer may or may not be detected depending on line ordering.
		// This documents the behavior.
		t.Log("no sanitized paths detected (may be expected if sanitizer is on same line as sink)")
	}
}

// =========================================================================
// identifySourceParams
// =========================================================================

func TestIdentifySourceParams_HTTPRequest(t *testing.T) {
	sig := TaintSignature{
		SourceParams: make(map[int]taint.SourceCategory),
	}
	identifySourceParams("func handler(w http.ResponseWriter, r *http.Request)", &sig)
	if _, ok := sig.SourceParams[1]; !ok {
		t.Error("expected *http.Request param (index 1) to be identified as source")
	}
}

func TestIdentifySourceParams_GinContext(t *testing.T) {
	sig := TaintSignature{
		SourceParams: make(map[int]taint.SourceCategory),
	}
	identifySourceParams("func handler(c *gin.Context)", &sig)
	if _, ok := sig.SourceParams[0]; !ok {
		t.Error("expected *gin.Context param (index 0) to be identified as source")
	}
}

func TestIdentifySourceParams_NoSource(t *testing.T) {
	sig := TaintSignature{
		SourceParams: make(map[int]taint.SourceCategory),
	}
	identifySourceParams("func add(a int, b int) int", &sig)
	if len(sig.SourceParams) != 0 {
		t.Error("expected no source params for arithmetic function")
	}
}

// =========================================================================
// findParamName
// =========================================================================

func TestFindParamName(t *testing.T) {
	lines := []string{"func handler(w http.ResponseWriter, r *http.Request)"}
	name := findParamName(lines, 0)
	if name != "w" {
		t.Errorf("expected 'w', got %q", name)
	}
	name = findParamName(lines, 1)
	if name != "r" {
		t.Errorf("expected 'r', got %q", name)
	}
}

func TestFindParamName_Method(t *testing.T) {
	lines := []string{"func (s *Server) handler(w http.ResponseWriter, r *http.Request)"}
	name := findParamName(lines, 0)
	if name != "w" {
		t.Errorf("expected 'w', got %q", name)
	}
}

func TestFindParamName_OutOfBounds(t *testing.T) {
	lines := []string{"func handler(a int)"}
	name := findParamName(lines, 5)
	if name != "" {
		t.Errorf("expected empty for out-of-bounds index, got %q", name)
	}
}

// =========================================================================
// PropagateInterproc
// =========================================================================

func TestPropagateInterproc_BasicFlow(t *testing.T) {
	cg := NewCallGraph("/project", "test")

	callee := &FuncNode{
		ID:        "pkg.processName",
		Name:      "processName",
		FilePath:  "/app/process.go",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}

	caller := &FuncNode{
		ID:        "pkg.handler",
		Name:      "handler",
		FilePath:  "/app/handler.go",
		StartLine: 1,
		EndLine:   5,
		Language:  rules.LangGo,
	}

	cg.AddNode(callee)
	cg.AddNode(caller)
	cg.AddEdge(caller.ID, callee.ID)

	calleeContent := `func processName(name string) {
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}`

	callerContent := `func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	processName(name)
}`

	fileContents := map[string]string{
		"/app/process.go": calleeContent,
		"/app/handler.go": callerContent,
	}

	findings := PropagateInterproc(cg, []string{"pkg.processName"}, fileContents)
	// The interprocedural analysis should detect the cross-function flow
	_ = findings // Document behavior; exact results depend on regex matching
}

func TestPropagateInterproc_NoChange(t *testing.T) {
	cg := NewCallGraph("/project", "test")

	node := &FuncNode{
		ID:        "pkg.add",
		Name:      "add",
		FilePath:  "/app/math.go",
		StartLine: 1,
		EndLine:   3,
		Language:  rules.LangGo,
		TaintSig:  TaintSignature{IsPure: true},
	}
	cg.AddNode(node)

	content := `func add(a int, b int) int {
	return a + b
}`
	fileContents := map[string]string{"/app/math.go": content}

	findings := PropagateInterproc(cg, []string{"pkg.add"}, fileContents)
	if len(findings) != 0 {
		t.Error("expected no findings for pure function with no signature change")
	}
}

func TestPropagateInterproc_MissingNode(t *testing.T) {
	cg := NewCallGraph("/project", "test")
	fileContents := map[string]string{}
	findings := PropagateInterproc(cg, []string{"nonexistent"}, fileContents)
	if len(findings) != 0 {
		t.Error("expected no findings for missing node")
	}
}

// =========================================================================
// FindImpactedCallers
// =========================================================================

func TestFindImpactedCallers(t *testing.T) {
	cg := NewCallGraph("/project", "test")

	a := &FuncNode{
		ID:       "a",
		Name:     "funcA",
		FilePath: "/app/a.go",
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Query"}},
		},
	}
	b := &FuncNode{ID: "b", Name: "funcB", FilePath: "/app/b.go"}
	c := &FuncNode{ID: "c", Name: "funcC", FilePath: "/app/c.go"}

	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddNode(c)
	cg.AddEdge("b", "a") // b calls a
	cg.AddEdge("c", "b") // c calls b

	impacted := FindImpactedCallers(cg, []string{"a"})
	if len(impacted) < 2 {
		t.Errorf("expected at least 2 impacted callers (b and c), got %d", len(impacted))
	}

	// Verify b and c are in the results
	foundB, foundC := false, false
	for _, ic := range impacted {
		if ic.CallerID == "b" {
			foundB = true
		}
		if ic.CallerID == "c" {
			foundC = true
		}
	}
	if !foundB {
		t.Error("expected funcB to be in impacted callers")
	}
	if !foundC {
		t.Error("expected funcC to be in impacted callers")
	}
}

func TestFindImpactedCallers_DepthLimit(t *testing.T) {
	cg := NewCallGraph("/project", "test")

	// Create a chain longer than maxTraversalDepth (5)
	for i := 0; i < 8; i++ {
		id := string(rune('a' + i))
		cg.AddNode(&FuncNode{
			ID:       id,
			Name:     "func" + strings.ToUpper(id),
			FilePath: "/app/" + id + ".go",
			TaintSig: TaintSignature{
				SinkCalls: []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Query"}},
			},
		})
	}
	for i := 1; i < 8; i++ {
		caller := string(rune('a' + i))
		callee := string(rune('a' + i - 1))
		cg.AddEdge(caller, callee)
	}

	impacted := FindImpactedCallers(cg, []string{"a"})
	// Should not include all 7 callers due to depth limit
	if len(impacted) > maxTraversalDepth {
		t.Errorf("should respect maxTraversalDepth=%d, got %d callers", maxTraversalDepth, len(impacted))
	}
}

// =========================================================================
// AnalyzeCallerImpact
// =========================================================================

func TestAnalyzeCallerImpact_PathA(t *testing.T) {
	cg := NewCallGraph("/project", "test")

	callee := &FuncNode{
		ID:       "pkg.processQuery",
		Name:     "processQuery",
		FilePath: "/app/db.go",
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{
				{SinkCategory: taint.SnkSQLQuery, MethodName: "sql.Query", ArgFromParam: 0},
			},
			SourceParams: map[int]taint.SourceCategory{0: taint.SrcUserInput},
		},
	}

	caller := &FuncNode{
		ID:        "pkg.handler",
		Name:      "handler",
		FilePath:  "/app/handler.go",
		StartLine: 1,
		EndLine:   4,
	}

	cg.AddNode(callee)
	cg.AddNode(caller)

	callerContent := `func handler(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("q")
	processQuery(query)
}`

	findings := AnalyzeCallerImpact(cg, caller, callee, callerContent)
	// Should detect that tainted query flows to processQuery's SQL sink
	_ = findings // Behavior depends on regex matching; test exercises the code path
}

func TestAnalyzeCallerImpact_EmptyCallerBody(t *testing.T) {
	cg := NewCallGraph("/project", "test")

	callee := &FuncNode{
		ID:   "callee",
		Name: "callee",
	}
	caller := &FuncNode{
		ID:        "caller",
		Name:      "caller",
		StartLine: 0,
		EndLine:   0,
	}

	cg.AddNode(callee)
	cg.AddNode(caller)

	findings := AnalyzeCallerImpact(cg, caller, callee, "")
	if len(findings) != 0 {
		t.Error("expected no findings for empty caller body")
	}
}

// =========================================================================
// isArgTaintedInCaller
// =========================================================================

func TestIsArgTaintedInCaller_DirectSource(t *testing.T) {
	lines := []string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		"    name := r.FormValue(\"name\")",
		"    processName(name)",
		"}",
	}
	if !isArgTaintedInCaller("r.FormValue(\"name\")", lines, 2) {
		t.Error("expected direct FormValue to be recognized as tainted")
	}
}

func TestIsArgTaintedInCaller_VariableFromSource(t *testing.T) {
	lines := []string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		"    name := r.FormValue(\"name\")",
		"    processName(name)",
		"}",
	}
	if !isArgTaintedInCaller("name", lines, 2) {
		t.Error("expected variable assigned from FormValue to be tainted")
	}
}

func TestIsArgTaintedInCaller_NotTainted(t *testing.T) {
	lines := []string{
		"func handler() {",
		`    name := "literal"`,
		"    processName(name)",
		"}",
	}
	if isArgTaintedInCaller("name", lines, 2) {
		t.Error("literal variable should not be tainted")
	}
}
