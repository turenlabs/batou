package graph

import (
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ExtractContext bundles the parsed forms of a source file that a
// TypeExtractor might need. Different languages consume different fields;
// unused fields are nil.
//
// The TSTree field carries the tree-sitter tree for 14 languages (Python,
// JS/TS, Java, PHP, Ruby, C, C++, C#, Kotlin, Swift, Rust, Lua, Groovy,
// Perl). GoFile carries Go's *astflow.GoParseResult (as interface{} to
// avoid import cycles; Go extractor does the type assertion).
type ExtractContext struct {
	FilePath string
	Content  []byte
	Language rules.Language
	TSTree   interface{} // *ast.Tree from batou-core/ast
	GoFile   interface{} // *astflow.GoParseResult
}

// TypeExtractor is the cross-language interface for extracting typed
// function signatures. Each supported language registers one implementation
// via RegisterExtractor in an init() function, mirroring the taint-catalog
// pattern used in batou-core/taint/languages.
type TypeExtractor interface {
	// Language reports which rules.Language this extractor handles.
	Language() rules.Language

	// ExtractFunctions walks the parsed tree in ctx and returns a
	// FuncSignature for every function/method declaration, with Params
	// and Returns populated (CanonicalType, IsSourceType, IsSinkType,
	// SourceCategory, SinkCategory). Returns an empty slice if the file
	// has no extractable declarations or parsing failed.
	ExtractFunctions(ctx *ExtractContext) []FuncSignature

	// ResolveVarType returns the canonical type of varName at line in the
	// file represented by ctx. Returns "" for dynamic languages or when
	// the type cannot be inferred from source. Used during interprocedural
	// analysis to match caller argument types to callee Param types.
	ResolveVarType(ctx *ExtractContext, varName string, line int) string
}

// FuncSignature is the per-function output of an extractor. It mirrors the
// fields on graph.TaintSignature that are typed — the extractor populates
// these once per file write, and the scanner stores them on the FuncNode.
type FuncSignature struct {
	Name      string
	Package   string
	StartLine int
	EndLine   int
	Params    []ParamTaint
	Returns   []ReturnTaint
	// IsClosure is true when this signature describes a closure — i.e. a
	// lambda or a nested function declaration whose canonical name carries
	// the language-specific line:col anchor (Go's ".closure@L:C", Python's
	// ".lambda@L:C" / ".<name>@L:C"). Downstream consumers use this flag
	// to apply closure-specific propagation rules (e.g. no exported call
	// site, edges only via synthetic parent-emits-closure links).
	IsClosure bool
}

// TypeCatalog is a per-language data bundle mapping canonical type strings
// to source/sink categories. Each TypeExtractor composes one in its init()
// — this is the part of per-language work that is pure data entry, suited
// to the auto-loop pattern.
type TypeCatalog struct {
	// SourceParam maps a canonical type (e.g. "*net/http.Request") to the
	// SourceCategory it represents when seen as a function parameter.
	SourceParam map[string]taint.SourceCategory

	// SinkParam maps a canonical type to the SinkCategory when the
	// parameter itself is a dangerous sink (rare — e.g. *sql.DB).
	SinkParam map[string]taint.SinkCategory

	// SourceReturn maps a canonical type to the SourceCategory when the
	// function returns a value of that type (e.g. a handler returning
	// a *http.Request-like object).
	SourceReturn map[string]taint.SourceCategory
}

// LookupSource reports whether canonical is a known source type. Returns
// the category and true on match, zero-value and false otherwise.
func (t *TypeCatalog) LookupSource(canonical string) (taint.SourceCategory, bool) {
	if t == nil || t.SourceParam == nil {
		return "", false
	}
	cat, ok := t.SourceParam[canonical]
	return cat, ok
}

// LookupSink reports whether canonical is a known sink type.
func (t *TypeCatalog) LookupSink(canonical string) (taint.SinkCategory, bool) {
	if t == nil || t.SinkParam == nil {
		return "", false
	}
	cat, ok := t.SinkParam[canonical]
	return cat, ok
}

// LookupSourceReturn reports whether canonical is a known source return type.
func (t *TypeCatalog) LookupSourceReturn(canonical string) (taint.SourceCategory, bool) {
	if t == nil || t.SourceReturn == nil {
		return "", false
	}
	cat, ok := t.SourceReturn[canonical]
	return cat, ok
}

// --- Registry ---

var (
	extractorMu sync.RWMutex
	extractors  = map[rules.Language]TypeExtractor{}
)

// RegisterExtractor adds a TypeExtractor to the registry. Called from
// per-language init() functions. Duplicate registration for the same
// language replaces the previous entry.
func RegisterExtractor(e TypeExtractor) {
	extractorMu.Lock()
	defer extractorMu.Unlock()
	extractors[e.Language()] = e
}

// GetExtractor returns the TypeExtractor for lang, or nil if none is
// registered.
func GetExtractor(lang rules.Language) TypeExtractor {
	extractorMu.RLock()
	defer extractorMu.RUnlock()
	return extractors[lang]
}

// IsExtractorSupported reports whether an extractor is registered for lang.
func IsExtractorSupported(lang rules.Language) bool {
	extractorMu.RLock()
	defer extractorMu.RUnlock()
	_, ok := extractors[lang]
	return ok
}
