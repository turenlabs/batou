package graph

import (
	"strings"
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
)

// =========================================================================
// Behavioral tests for typed Go summaries (Phase 1).
//
// These cover the architect-specified contract:
//   1. Aliased *http.Request param → recognized as a source via the catalog.
//   2. *sql.DB param → recognized as a sink-bearing type.
//   3. Legacy TypesVersion=0 signature still works without typed info.
//   4. Source-typed return value populates Returns + TaintedReturns.
// =========================================================================

// buildTypedForFile is a test helper that parses a Go file and returns the
// GoTypeInfo the scanner would produce. Returns nil on parse failure.
func buildTypedForFile(t *testing.T, content, path string) *GoTypeInfo {
	t.Helper()
	parsed := astflow.ParseGo(content, path)
	if parsed == nil || parsed.File == nil {
		t.Fatalf("ParseGo(%q) returned nil", path)
	}
	return BuildGoTypeInfo(parsed.File)
}

// findParam locates a ParamTaint by parameter name.
func findParam(sig TaintSignature, name string) (ParamTaint, bool) {
	for _, p := range sig.Params {
		if p.Name == name {
			return p, true
		}
	}
	return ParamTaint{}, false
}

// Test 1: Aliased *http.Request parameter is recognized as a typed source.
//
// The import is `import h "net/http"` and the parameter is `r *h.Request`.
// Canonicalization must rewrite `*h.Request` → `*http.Request` so the
// KnownGoSourceTypes lookup succeeds.
func TestTypedSummary_HTTPRequestParam_IsSource(t *testing.T) {
	content := `package app

import h "net/http"

func handler(w h.ResponseWriter, r *h.Request) {
	_ = r
}
`
	typed := buildTypedForFile(t, content, "/app/handler.go")

	node := &FuncNode{
		Name:      "handler",
		FilePath:  "/app/handler.go",
		StartLine: 5,
		EndLine:   7,
		Language:  rules.LangGo,
	}

	sig := ComputeTaintSigTyped(node, content, rules.LangGo, nil, nil, typed)

	if sig.TypesVersion != TypesSchemaVersion {
		t.Errorf("expected TypesVersion=%d, got %d", TypesSchemaVersion, sig.TypesVersion)
	}

	rParam, ok := findParam(sig, "r")
	if !ok {
		t.Fatalf("expected param 'r' in Params, got %+v", sig.Params)
	}
	if rParam.CanonicalType != "*http.Request" {
		t.Errorf("expected canonical type '*http.Request' for aliased import, got %q", rParam.CanonicalType)
	}
	if !rParam.IsSourceType {
		t.Error("*http.Request should be flagged as a source type")
	}
	if rParam.SourceCategory != taint.SrcUserInput {
		t.Errorf("expected SrcUserInput for *http.Request, got %q", rParam.SourceCategory)
	}

	// Legacy SourceParams map must also be populated at index 1 (after w).
	if _, ok := sig.SourceParams[rParam.Index]; !ok {
		t.Errorf("legacy SourceParams[%d] not populated for source-typed param", rParam.Index)
	}

	if sig.IsPure {
		t.Error("function receiving *http.Request should not be pure")
	}
}

// Test 2: *sql.DB parameter is flagged as a sink-bearing type.
//
// The catalog marks *sql.DB as SnkSQLQuery. A function whose parameter is
// *sql.DB should have IsSinkType=true in its typed metadata, and the
// caller-side analysis can use this to boost confidence when the arg type
// at the call site matches.
func TestTypedSummary_SQLDBParam_IsSinkType(t *testing.T) {
	content := `package app

import "database/sql"

func runQuery(db *sql.DB, q string) {
	db.Query(q)
}
`
	typed := buildTypedForFile(t, content, "/app/db.go")

	node := &FuncNode{
		Name:      "runQuery",
		FilePath:  "/app/db.go",
		StartLine: 5,
		EndLine:   7,
		Language:  rules.LangGo,
	}

	sig := ComputeTaintSigTyped(node, content, rules.LangGo, nil, nil, typed)

	if sig.TypesVersion != TypesSchemaVersion {
		t.Errorf("expected TypesVersion=%d, got %d", TypesSchemaVersion, sig.TypesVersion)
	}

	dbParam, ok := findParam(sig, "db")
	if !ok {
		t.Fatalf("expected param 'db' in Params, got %+v", sig.Params)
	}
	if dbParam.CanonicalType != "*sql.DB" {
		t.Errorf("expected canonical type '*sql.DB', got %q", dbParam.CanonicalType)
	}
	if !dbParam.IsSinkType {
		t.Error("*sql.DB should be flagged as a sink-bearing type")
	}
	if dbParam.SinkCategory != taint.SnkSQLQuery {
		t.Errorf("expected SnkSQLQuery for *sql.DB, got %q", dbParam.SinkCategory)
	}
	// A sink-typed parameter is not itself a source.
	if dbParam.IsSourceType {
		t.Error("*sql.DB should not be marked as source-type")
	}

	qParam, ok := findParam(sig, "q")
	if !ok {
		t.Fatalf("expected param 'q', got %+v", sig.Params)
	}
	if qParam.IsSinkType || qParam.IsSourceType {
		t.Errorf("plain string param should have no typed flags, got src=%v sink=%v",
			qParam.IsSourceType, qParam.IsSinkType)
	}
}

// Test 3: Legacy path — nil GoTypeInfo produces TypesVersion=0 and leaves
// the regex-inferred behavior untouched. This is the backward-compat
// guarantee for nodes that existed before typed summaries.
func TestTypedSummary_UntypedFallback_StillWorks(t *testing.T) {
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

	// Pass nil for GoTypeInfo: this is the legacy code path.
	sig := ComputeTaintSigTyped(node, content, rules.LangGo, nil, nil, nil)

	if sig.TypesVersion != 0 {
		t.Errorf("expected TypesVersion=0 for untyped fallback, got %d", sig.TypesVersion)
	}
	if len(sig.Params) != 0 {
		t.Errorf("expected no typed Params for legacy path, got %d", len(sig.Params))
	}
	if len(sig.Returns) != 0 {
		t.Errorf("expected no typed Returns for legacy path, got %d", len(sig.Returns))
	}

	// Regex heuristics still fire: SourceParams populated, SinkCalls present,
	// function is not pure.
	if len(sig.SourceParams) == 0 {
		t.Error("regex fallback should still identify *http.Request as a source param")
	}
	if len(sig.SinkCalls) == 0 {
		t.Error("regex fallback should still detect db.Query sink")
	}
	if sig.IsPure {
		t.Error("regex fallback should not flag this function pure")
	}

	// PropagateInterproc (the legacy public API) should still operate,
	// producing no panics when typed info is absent.
	cg := NewCallGraph("/project", "test")
	cg.AddNode(node)
	fileContents := map[string]string{"/app/handler.go": content}
	_ = PropagateInterproc(cg, []string{node.ID}, fileContents, nil, nil)
}

// Test 4: A source-typed return value populates Returns[*] with
// IsSourceType and mirrors into TaintedReturns so existing callers that
// read TaintedReturns see the taint.
func TestTypedSummary_ReturnTypeFlag(t *testing.T) {
	content := `package app

import "net/http"

func newReq() *http.Request {
	return nil
}
`
	typed := buildTypedForFile(t, content, "/app/make.go")

	node := &FuncNode{
		Name:      "newReq",
		FilePath:  "/app/make.go",
		StartLine: 5,
		EndLine:   7,
		Language:  rules.LangGo,
	}

	sig := ComputeTaintSigTyped(node, content, rules.LangGo, nil, nil, typed)

	if sig.TypesVersion != TypesSchemaVersion {
		t.Errorf("expected TypesVersion=%d, got %d", TypesSchemaVersion, sig.TypesVersion)
	}
	if len(sig.Returns) != 1 {
		t.Fatalf("expected exactly 1 typed return, got %d: %+v", len(sig.Returns), sig.Returns)
	}
	ret := sig.Returns[0]
	if ret.CanonicalType != "*http.Request" {
		t.Errorf("expected canonical return type '*http.Request', got %q", ret.CanonicalType)
	}
	if !ret.IsSourceType {
		t.Error("*http.Request return should be flagged as a source type")
	}
	if ret.SourceCategory != taint.SrcUserInput {
		t.Errorf("expected SrcUserInput for returned *http.Request, got %q", ret.SourceCategory)
	}

	// Legacy TaintedReturns map must be populated for the returned index.
	cats, ok := sig.TaintedReturns[ret.Index]
	if !ok {
		t.Fatalf("legacy TaintedReturns[%d] not populated for source-typed return", ret.Index)
	}
	seen := false
	for _, c := range cats {
		if c == taint.SrcUserInput {
			seen = true
			break
		}
	}
	if !seen {
		t.Errorf("expected SrcUserInput in TaintedReturns[%d], got %v", ret.Index, cats)
	}

	// A function that returns a source is not pure.
	if sig.IsPure {
		t.Error("function returning *http.Request should not be pure")
	}
}

// =========================================================================
// Supplementary tests exercising specific catalog & canonicalization edges.
// =========================================================================

// Versioned import paths (e.g. "github.com/labstack/echo/v4") must resolve
// to the parent segment's default alias ("echo") so lookups succeed for
// *echo.Context etc.
func TestTypedSummary_VersionedImportAlias(t *testing.T) {
	content := `package app

import "github.com/labstack/echo/v4"

func handler(c echo.Context) {
	_ = c
}
`
	typed := buildTypedForFile(t, content, "/app/echo.go")

	node := &FuncNode{
		Name:      "handler",
		FilePath:  "/app/echo.go",
		StartLine: 5,
		EndLine:   7,
		Language:  rules.LangGo,
	}

	sig := ComputeTaintSigTyped(node, content, rules.LangGo, nil, nil, typed)

	cParam, ok := findParam(sig, "c")
	if !ok {
		t.Fatalf("expected param 'c', got %+v", sig.Params)
	}
	if cParam.CanonicalType != "echo.Context" {
		t.Errorf("expected canonical 'echo.Context' (stripping /v4), got %q", cParam.CanonicalType)
	}
	if !cParam.IsSourceType {
		t.Error("echo.Context should be flagged as source-type (KnownGoSourceTypes entry)")
	}
}

// applyTypedConfidenceBump should bump ConfidenceScore by +0.1 (cap 1.0) and
// append a "typed_confirmed" tag when the caller passes an argument whose
// canonical type matches a callee's source-typed parameter.
func TestTypedSummary_ConfidenceBump_OnSourceTypeMatch(t *testing.T) {
	callerSrc := `package app

import "net/http"

func outer(req *http.Request) {
	inner(req)
}
`
	callerTyped := buildTypedForFile(t, callerSrc, "/app/outer.go")

	callerNode := &FuncNode{
		Name:      "outer",
		FilePath:  "/app/outer.go",
		StartLine: 5,
		EndLine:   7,
		Language:  rules.LangGo,
	}
	calleeNode := &FuncNode{
		Name:     "inner",
		FilePath: "/app/inner.go",
		TaintSig: TaintSignature{
			Params: []ParamTaint{
				{
					Index:          0,
					Name:           "r",
					Type:           "*http.Request",
					CanonicalType:  "*http.Request",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
			SinkCalls: []SinkRef{
				{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Query"},
			},
			TypesVersion: TypesSchemaVersion,
		},
	}

	finding := rules.Finding{
		RuleID:          "INTERPROC-SRC-A",
		ConfidenceScore: 0.7,
	}

	calls := []typedCallSite{
		{
			lineIdx: 0,
			args:    []string{"req"},
		},
	}

	bumped := applyTypedConfidenceBump(&finding, callerNode, calleeNode, callerTyped, calls)
	if !bumped {
		t.Fatal("expected typed confidence bump on *http.Request source-type match")
	}
	if finding.ConfidenceScore < 0.79 || finding.ConfidenceScore > 0.81 {
		t.Errorf("expected ConfidenceScore ≈ 0.8 after +0.1 bump, got %f", finding.ConfidenceScore)
	}
	hasTag := false
	for _, tg := range finding.Tags {
		if tg == "typed_confirmed" {
			hasTag = true
			break
		}
	}
	if !hasTag {
		t.Errorf("expected 'typed_confirmed' tag, got %v", finding.Tags)
	}
}

// Cap at 1.0: a finding already at 0.95 should not exceed 1.0 after the bump.
func TestTypedSummary_ConfidenceBump_CapsAtOne(t *testing.T) {
	finding := rules.Finding{ConfidenceScore: 0.95}
	if !bumpTypedConfidence(&finding) {
		t.Fatal("expected bump to apply")
	}
	if finding.ConfidenceScore != 1.0 {
		t.Errorf("expected ConfidenceScore to cap at 1.0, got %f", finding.ConfidenceScore)
	}
	// Second call: already at 1.0, so score shouldn't change.
	prev := finding.ConfidenceScore
	bumpTypedConfidence(&finding)
	if finding.ConfidenceScore != prev {
		t.Errorf("expected cap to hold on subsequent calls, got %f", finding.ConfidenceScore)
	}
	// Tag should remain single.
	count := 0
	for _, tg := range finding.Tags {
		if tg == "typed_confirmed" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one 'typed_confirmed' tag, got %d (%v)", count, finding.Tags)
	}
}

// TestTypedSummary_ClosureNodeHasTypedParams covers the HTTP handler factory
// pattern after PR-S: the closure FuncNode emitted by the call graph builder
// must have its own typed Params (w: http.ResponseWriter, r: *http.Request)
// populated by populateTypedParams, with SourceParams pointing at the request
// param. Before PR-S, the closure didn't exist as a node and only the outer
// function's params (just `ctrl`) were visible to interproc.
func TestTypedSummary_ClosureNodeHasTypedParams(t *testing.T) {
	content := `package handler

import "net/http"

func HandleDiff(ctrl *Controller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = ctrl
	}
}
`
	parsed := astflow.ParseGo(content, "/app/handler.go")
	if parsed == nil || parsed.File == nil {
		t.Fatal("ParseGo returned nil")
	}
	typed := BuildGoTypeInfoWithFset(parsed.File, parsed.Fset)
	if typed == nil {
		t.Fatal("BuildGoTypeInfoWithFset returned nil")
	}

	// The closure must be indexed under the canonical
	// "<Outer>.closure@<line>:<col>" name produced by the builder.
	wantPrefix := "HandleDiff.closure@"
	var closureKey string
	for k := range typed.FuncLits {
		if strings.HasPrefix(k, wantPrefix) {
			closureKey = k
			break
		}
	}
	if closureKey == "" {
		keys := make([]string, 0, len(typed.FuncLits))
		for k := range typed.FuncLits {
			keys = append(keys, k)
		}
		t.Fatalf("expected FuncLits key with prefix %q, got: %s", wantPrefix, strings.Join(keys, ", "))
	}

	// Build the FuncNode the call graph builder would emit and run
	// populateTypedParams the same way the scanner does.
	node := &FuncNode{Name: closureKey, Language: rules.LangGo}
	sig := TaintSignature{}
	populateTypedParams(node, typed, &sig)

	if len(sig.Params) != 2 {
		t.Fatalf("closure Params count = %d, want 2 (w, r)", len(sig.Params))
	}
	w := sig.Params[0]
	r := sig.Params[1]
	if w.Name != "w" {
		t.Errorf("closure param[0].Name = %q, want %q", w.Name, "w")
	}
	if w.CanonicalType != "http.ResponseWriter" {
		t.Errorf("closure param[0].CanonicalType = %q, want %q", w.CanonicalType, "http.ResponseWriter")
	}
	if w.IsSourceType {
		t.Error("closure param[0] (w http.ResponseWriter) should NOT be a source type")
	}
	if r.Name != "r" {
		t.Errorf("closure param[1].Name = %q, want %q", r.Name, "r")
	}
	if r.CanonicalType != "*http.Request" {
		t.Errorf("closure param[1].CanonicalType = %q, want %q", r.CanonicalType, "*http.Request")
	}
	if !r.IsSourceType {
		t.Error("closure param[1] (r *http.Request) should be a source type")
	}
	if cat, ok := sig.SourceParams[1]; !ok {
		t.Error("closure SourceParams should include index 1 (the *http.Request param)")
	} else if cat != taint.SrcUserInput {
		t.Errorf("closure SourceParams[1] = %v, want SrcUserInput", cat)
	}
	if _, ok := sig.SourceParams[0]; ok {
		t.Error("closure SourceParams must NOT include index 0 (http.ResponseWriter is outbound)")
	}
}

// BuildGoTypeInfo should index methods under the "Recv.Method" key so that
// FuncNode lookups for method declarations resolve correctly.
func TestTypedSummary_MethodReceiverIndexing(t *testing.T) {
	content := `package app

type Server struct{}

func (s *Server) Handle(path string) string {
	return path
}
`
	typed := buildTypedForFile(t, content, "/app/server.go")

	if _, ok := typed.FuncDecls["Server.Handle"]; !ok {
		keys := make([]string, 0, len(typed.FuncDecls))
		for k := range typed.FuncDecls {
			keys = append(keys, k)
		}
		t.Errorf("expected FuncDecls key 'Server.Handle', got: %s", strings.Join(keys, ", "))
	}
}
