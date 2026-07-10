package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// mockExtractor stands in for a per-language extractor that a loop PR
// would register. Returns a fixed signature for a single named function.
type mockExtractor struct {
	lang rules.Language
	sigs []FuncSignature
}

func (m *mockExtractor) Language() rules.Language { return m.lang }

func (m *mockExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	return m.sigs
}

func (m *mockExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	return ""
}

// withMockExtractor registers a mock for lang and arranges a cleanup
// that restores the previous extractor (or removes the mock entirely if
// none was registered before), so tests can exercise non-Go paths
// without leaking state. The restore step matters once real per-
// language extractors land — without it, this helper would tear down
// the Python/Java/etc. extractors registered at package init time and
// subsequent tests in the same run would fail with "no extractor
// registered".
func withMockExtractor(t *testing.T, lang rules.Language, sigs []FuncSignature) {
	t.Helper()
	extractorMu.Lock()
	prev, hadPrev := extractors[lang]
	extractorMu.Unlock()

	RegisterExtractor(&mockExtractor{lang: lang, sigs: sigs})
	t.Cleanup(func() {
		extractorMu.Lock()
		if hadPrev {
			extractors[lang] = prev
		} else {
			delete(extractors, lang)
		}
		extractorMu.Unlock()
	})
}

// TestComputeTaintSigTyped_NonGoViaRegistry verifies that when a non-Go
// language has a registered TypeExtractor, its Params/Returns flow into
// the resulting TaintSignature — the core wire-up E1-T2 delivers.
func TestComputeTaintSigTyped_NonGoViaRegistry(t *testing.T) {
	withMockExtractor(t, rules.LangPython, []FuncSignature{
		{
			Name: "handle_request",
			Params: []ParamTaint{
				{
					Index:          0,
					Name:           "request",
					Type:           "flask.Request",
					CanonicalType:  "flask.Request",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
			Returns: []ReturnTaint{
				{Index: 0, Type: "str", CanonicalType: "str"},
			},
		},
	})

	node := &FuncNode{
		Name:      "handle_request",
		FilePath:  "/app/views.py",
		Language:  rules.LangPython,
		StartLine: 10,
		EndLine:   20,
	}
	content := "def handle_request(request):\n    return request.args.get('q')\n"

	sig := ComputeTaintSigTyped(node, content, rules.LangPython, nil, nil, nil)

	if len(sig.Params) != 1 {
		t.Fatalf("expected 1 typed Param, got %d", len(sig.Params))
	}
	p := sig.Params[0]
	if p.Name != "request" {
		t.Errorf("Params[0].Name = %q, want %q", p.Name, "request")
	}
	if p.CanonicalType != "flask.Request" {
		t.Errorf("Params[0].CanonicalType = %q, want %q", p.CanonicalType, "flask.Request")
	}
	if !p.IsSourceType {
		t.Error("Params[0].IsSourceType = false, want true")
	}
	// SourceParams mirror should be populated too (same side-effect as Go path).
	if cat, ok := sig.SourceParams[0]; !ok || cat != taint.SrcUserInput {
		t.Errorf("SourceParams[0] = %q (ok=%v), want %q", cat, ok, taint.SrcUserInput)
	}
	if sig.TypesVersion != TypesSchemaVersion {
		t.Errorf("TypesVersion = %d, want %d", sig.TypesVersion, TypesSchemaVersion)
	}
}

// TestComputeTaintSigTyped_NonGoNoExtractor_NoChange verifies that absent a
// registered extractor, non-Go languages get the legacy untyped signature
// (no Params/Returns) — identical to behavior before this PR. Kotlin is
// used here because it has no extractor registered yet (Python / JS / Java
// / Ruby / PHP all have one via the cross-language PR series).
func TestComputeTaintSigTyped_NonGoNoExtractor_NoChange(t *testing.T) {
	node := &FuncNode{
		Name:     "noop",
		FilePath: "/app/views.kt",
		Language: rules.LangKotlin,
	}
	sig := ComputeTaintSigTyped(node, "fun noop() {}\n", rules.LangKotlin, nil, nil, nil)
	if len(sig.Params) != 0 {
		t.Errorf("expected no typed Params for unregistered language, got %d", len(sig.Params))
	}
	if sig.TypesVersion != 0 {
		t.Errorf("TypesVersion should be 0 without extractor, got %d", sig.TypesVersion)
	}
}

// TestComputeTaintSigTyped_GoPathUnchanged confirms that when typed is nil
// and Go has no registered extractor (Go is the one language handled by
// the legacy path), the non-Go registry branch does not accidentally fire
// for Go.
func TestComputeTaintSigTyped_GoPathUnchanged(t *testing.T) {
	// Register a mock Go extractor with a signature that would be
	// observable if the registry branch ran for Go. The `lang != rules.LangGo`
	// guard should prevent it.
	withMockExtractor(t, rules.LangGo, []FuncSignature{
		{
			Name: "should_not_appear",
			Params: []ParamTaint{
				{Index: 0, Name: "injected", CanonicalType: "mock.Type"},
			},
		},
	})

	node := &FuncNode{
		Name:     "should_not_appear",
		FilePath: "/app/h.go",
		Language: rules.LangGo,
	}
	sig := ComputeTaintSigTyped(node, "package h\nfunc should_not_appear(){}\n", rules.LangGo, nil, nil, nil)

	if len(sig.Params) != 0 {
		t.Errorf("registry branch fired for Go (expected legacy path only), got %d params", len(sig.Params))
	}
}

// TestComputeTaintSigTyped_NonGoWrongFuncName_NoChange verifies the helper
// tolerates signatures for other functions without leaking their data.
func TestComputeTaintSigTyped_NonGoWrongFuncName_NoChange(t *testing.T) {
	withMockExtractor(t, rules.LangPython, []FuncSignature{
		{
			Name: "some_other_function",
			Params: []ParamTaint{
				{Index: 0, Name: "x", CanonicalType: "str"},
			},
		},
	})

	node := &FuncNode{
		Name:     "not_in_sigs",
		FilePath: "/app/v.py",
		Language: rules.LangPython,
	}
	sig := ComputeTaintSigTyped(node, "def not_in_sigs(): pass\n", rules.LangPython, nil, nil, nil)
	if len(sig.Params) != 0 {
		t.Errorf("expected no Params when func name doesn't match any extracted sig, got %d", len(sig.Params))
	}
}
