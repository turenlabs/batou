package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-rules/rules"
)

// HarnessCase is the unit of per-language extractor testing. Each case
// declares a source fixture and the Params/Returns the extractor should
// produce for a specific function. The test runner asserts equality.
//
// Per-language PRs from the auto-loop should add their cases under a name
// that identifies the scenario (e.g. "flask_request_source" for Python),
// then call RunHarness with their language and cases.
type HarnessCase struct {
	// Name is the subtest name.
	Name string

	// FilePath is used for parsing context (import resolution, etc.).
	FilePath string

	// Content is the source to parse. Must contain the function named by
	// Func so ExtractFunctions can locate it.
	Content string

	// Func identifies the function whose signature we assert. For Go,
	// this is the canonical "Func" or "Recv.Method" name produced by
	// buildGoTypeInfo.
	Func string

	// WantParams is the expected Params slice. Asserted by checking each
	// field individually so a loop-generated case can pin exactly the
	// subset that matters (e.g. index+canonical+IsSourceType, leaving
	// Name empty to skip that field).
	WantParams []ParamTaint

	// WantReturns is the expected Returns slice.
	WantReturns []ReturnTaint
}

// RunHarness runs a slice of HarnessCase against the registered extractor
// for lang. This is the primary harness per-language PRs should call;
// sample usage in TestGoExtractor_Harness below.
func RunHarness(t *testing.T, lang rules.Language, cases []HarnessCase) {
	t.Helper()
	ex := GetExtractor(lang)
	if ex == nil {
		t.Fatalf("no TypeExtractor registered for language %q", lang)
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Helper()
			ctx := &ExtractContext{
				FilePath: tc.FilePath,
				Content:  []byte(tc.Content),
				Language: lang,
				GoFile:   maybeParseGo(lang, tc.Content, tc.FilePath),
			}
			sigs := ex.ExtractFunctions(ctx)
			got := findSignature(sigs, tc.Func)
			if got == nil {
				t.Fatalf("no signature found for func %q; extractor returned %d sigs",
					tc.Func, len(sigs))
			}
			assertParams(t, got.Params, tc.WantParams)
			assertReturns(t, got.Returns, tc.WantReturns)
		})
	}
}

// maybeParseGo parses Go content so the ExtractContext's GoFile field is
// populated for the Go extractor. Returns nil for other languages — per-
// language extractors are responsible for using TSTree or parsing Content
// themselves.
func maybeParseGo(lang rules.Language, content, filePath string) interface{} {
	if lang != rules.LangGo {
		return nil
	}
	return astflow.ParseGo(content, filePath)
}

func findSignature(sigs []FuncSignature, name string) *FuncSignature {
	for i := range sigs {
		if sigs[i].Name == name {
			return &sigs[i]
		}
	}
	return nil
}

// assertParams compares got to want positionally. Empty string fields in
// want are wildcards (not asserted) so tests can pin only the fields they
// care about.
func assertParams(t *testing.T, got, want []ParamTaint) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	if len(got) != len(want) {
		t.Fatalf("Params length: got %d, want %d (got=%+v)", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if w.Index != 0 && g.Index != w.Index {
			t.Errorf("Params[%d].Index = %d, want %d", i, g.Index, w.Index)
		}
		if w.Name != "" && g.Name != w.Name {
			t.Errorf("Params[%d].Name = %q, want %q", i, g.Name, w.Name)
		}
		if w.Type != "" && g.Type != w.Type {
			t.Errorf("Params[%d].Type = %q, want %q", i, g.Type, w.Type)
		}
		if w.CanonicalType != "" && g.CanonicalType != w.CanonicalType {
			t.Errorf("Params[%d].CanonicalType = %q, want %q", i, g.CanonicalType, w.CanonicalType)
		}
		if w.IsSourceType && !g.IsSourceType {
			t.Errorf("Params[%d].IsSourceType = false, want true", i)
		}
		if w.IsSinkType && !g.IsSinkType {
			t.Errorf("Params[%d].IsSinkType = false, want true", i)
		}
		if w.SourceCategory != "" && g.SourceCategory != w.SourceCategory {
			t.Errorf("Params[%d].SourceCategory = %q, want %q", i, g.SourceCategory, w.SourceCategory)
		}
		if w.SinkCategory != "" && g.SinkCategory != w.SinkCategory {
			t.Errorf("Params[%d].SinkCategory = %q, want %q", i, g.SinkCategory, w.SinkCategory)
		}
	}
}

func assertReturns(t *testing.T, got, want []ReturnTaint) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	if len(got) != len(want) {
		t.Fatalf("Returns length: got %d, want %d (got=%+v)", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if w.Name != "" && g.Name != w.Name {
			t.Errorf("Returns[%d].Name = %q, want %q", i, g.Name, w.Name)
		}
		if w.Type != "" && g.Type != w.Type {
			t.Errorf("Returns[%d].Type = %q, want %q", i, g.Type, w.Type)
		}
		if w.CanonicalType != "" && g.CanonicalType != w.CanonicalType {
			t.Errorf("Returns[%d].CanonicalType = %q, want %q", i, g.CanonicalType, w.CanonicalType)
		}
		if w.IsSourceType && !g.IsSourceType {
			t.Errorf("Returns[%d].IsSourceType = false, want true", i)
		}
		if w.SourceCategory != "" && g.SourceCategory != w.SourceCategory {
			t.Errorf("Returns[%d].SourceCategory = %q, want %q", i, g.SourceCategory, w.SourceCategory)
		}
	}
}

// -----------------------------------------------------------------------
// Go reference test: demonstrates what per-language harness usage looks
// like. Per-language PRs should copy this pattern.
// -----------------------------------------------------------------------

func TestGoExtractor_Harness(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "http_request_source_param",
			FilePath: "/app/handler.go",
			Content: `package handler

import "net/http"

func Serve(w http.ResponseWriter, r *http.Request) {}
`,
			Func: "Serve",
			WantParams: []ParamTaint{
				{Name: "w", CanonicalType: "http.ResponseWriter"},
				{Name: "r", CanonicalType: "*http.Request", IsSourceType: true, SourceCategory: taint.SrcUserInput},
			},
		},
		{
			Name:     "aliased_import",
			FilePath: "/app/h.go",
			Content: `package h

import h "net/http"

func Handle(req *h.Request) {}
`,
			Func: "Handle",
			WantParams: []ParamTaint{
				{Name: "req", CanonicalType: "*http.Request", IsSourceType: true},
			},
		},
		{
			Name:     "no_params",
			FilePath: "/app/pure.go",
			Content: `package pure

func Hello() string { return "hi" }
`,
			Func: "Hello",
			WantReturns: []ReturnTaint{
				{Type: "string", CanonicalType: "string"},
			},
		},
	}
	RunHarness(t, rules.LangGo, cases)
}

// TestExtractorRegistry_GoRegistered verifies the Go extractor is
// registered at init time.
func TestExtractorRegistry_GoRegistered(t *testing.T) {
	if !IsExtractorSupported(rules.LangGo) {
		t.Fatal("Go extractor not registered")
	}
	if ex := GetExtractor(rules.LangGo); ex == nil {
		t.Fatal("GetExtractor returned nil for Go")
	}
}

// TestExtractorRegistry_UnregisteredLanguages confirms non-Go languages
// have no extractor yet — per-language PRs from the loop will flip these
// one at a time.
func TestExtractorRegistry_UnregisteredLanguages(t *testing.T) {
	// Java was registered in this session via E1-T3 — removed from the list.
	// Python was registered via crossfile/pr-ccpy — removed from the list.
	// JavaScript/TypeScript were registered via crossfile/pr-ccjs — removed.
	// Ruby was registered via crossfile/pr-ccruby — removed from the list.
	// PHP was registered via crossfile/pr-ccphp — removed from the list.
	// Remove other entries as each per-language PR lands.
	unregistered := []rules.Language{
		rules.LangC, rules.LangCPP, rules.LangCSharp,
		rules.LangKotlin, rules.LangSwift, rules.LangRust,
		rules.LangLua, rules.LangGroovy, rules.LangPerl,
	}
	for _, lang := range unregistered {
		if IsExtractorSupported(lang) {
			t.Errorf("unexpected extractor registered for %q (remove from this list as languages land)", lang)
		}
	}
}
