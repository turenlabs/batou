// Cross-function taint propagation for Batou.
//
// When Claude modifies function B, Batou doesn't just analyze B in isolation.
// It walks the call graph to find all callers of B, checks if taint from
// B's parameters flows through callers to dangerous sinks, and reports
// interprocedural taint paths that would be invisible to single-function analysis.
//
// The algorithm:
//  1. Compute taint signatures for changed functions
//  2. Compare with previous signatures to detect meaningful changes
//  3. Walk CalledBy edges transitively to find impacted callers
//  4. Analyze each caller for cross-function taint flows
//  5. Return findings with clear interprocedural explanations
package graph

import (
	"fmt"
	"go/ast"
	"go/token"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// GoTypeInfo carries parsed Go type context used to build typed function
// summaries. Scanner constructs one from the cached *ast.File and passes it
// to PropagateInterprocTyped; non-Go or missing-parse scans pass nil.
type GoTypeInfo struct {
	File    *ast.File
	TypeEnv *astflow.TypeEnv
	// FuncDecls maps FuncNode.Name ("Func" or "Recv.Method") to the
	// corresponding *ast.FuncDecl in File.
	FuncDecls map[string]*ast.FuncDecl
	// FuncLits maps closure FuncNode.Name (the canonical
	// "<EnclosingName>.closure@<line>:<col>" form produced by the call
	// graph builder, see builder.go::FormatClosureName) to the
	// corresponding *ast.FuncLit in File. Populated alongside FuncDecls
	// so populateTypedParams can derive typed Params/Returns for closure
	// nodes the same way it does for top-level functions.
	FuncLits map[string]*ast.FuncLit
	// Fset is the file's token.FileSet, used to recover line:col of a
	// FuncLit when building its canonical closure name.
	Fset *token.FileSet
}

// TypesSchemaVersion identifies the current typed-summary schema. Each node
// records its own version so mixed graphs can age out legacy entries.
const TypesSchemaVersion = 1

// defaultMaxCallerFileSize is the largest caller source file the hook lane
// will read from disk for cross-file interprocedural analysis. Files larger
// than this are skipped: the regex/analysis walk that consumes the content
// costs O(size) regardless of how the bytes are read, so the cap bounds added
// write-time LATENCY, not just memory.
//
// Raised from the original 2 MB to 4 MB. The choice is measurement-driven
// (Apple M-series; a synthetic worst-case caller that is one giant function
// scanned end-to-end — the upper bound on per-file cost):
//
//	size   read     full one-hop walk (read + analyze)
//	1 MB   ~0.4 ms  ~36 ms
//	2 MB   ~0.5 ms  ~64 ms   (legacy cap)
//	4 MB   ~0.8 ms  ~126 ms  (new cap)
//	8 MB   ~1.3 ms  ~254 ms
//	12 MB  ~2.4 ms  ~378 ms
//
// The walk cost is ~31 ms/MB and linear. 2 MB silently dropped large
// generated/vendored callers on monolithic codebases, losing their cross-file
// state. 4 MB doubles the recoverable range while keeping the worst-case
// single-oversized-caller walk (~126 ms) inside a small write-time slice; 8 MB+
// was rejected because a hook can fan out to up to 64 inbound callers and even
// one multi-hundred-ms caller is too much for the per-write budget. The read
// itself is bounded by io.LimitReader so a file that grows past the cap between
// Stat and read can never allocate more than the cap (TOCTOU-safe). Override
// the cap with BATOU_HOOK_CALLER_MAX_MB (whole megabytes); the whole lane still
// sits under the BATOU_HOOK_CROSSFILE kill switch.
const defaultMaxCallerFileSize = 4 * 1024 * 1024

// maxCallerFileSize returns the caller-file size cap, honoring the
// BATOU_HOOK_CALLER_MAX_MB environment override (whole megabytes). Rollback to
// the legacy 2 MB behavior is config-only: BATOU_HOOK_CALLER_MAX_MB=2.
func maxCallerFileSize() int64 {
	if v := os.Getenv("BATOU_HOOK_CALLER_MAX_MB"); v != "" {
		if mb, err := strconv.ParseInt(v, 10, 64); err == nil && mb > 0 {
			return mb * 1024 * 1024
		}
	}
	return defaultMaxCallerFileSize
}

// maxTraversalDepth limits how far we walk up the call graph.
const maxTraversalDepth = 5

// cweForSinkCategory maps sink categories to their CWE IDs.
var cweForSinkCategory = map[taint.SinkCategory]string{
	taint.SnkSQLQuery:    "CWE-89",
	taint.SnkNoSQL:       "CWE-943",
	taint.SnkCSV:         "CWE-1236",
	taint.SnkUpload:      "CWE-434",
	taint.SnkCommand:     "CWE-78",
	taint.SnkFileWrite:   "CWE-22",
	taint.SnkHTMLOutput:  "CWE-79",
	taint.SnkEval:        "CWE-94",
	taint.SnkRedirect:    "CWE-601",
	taint.SnkLDAP:        "CWE-90",
	taint.SnkXPath:       "CWE-643",
	taint.SnkHeader:      "CWE-113",
	taint.SnkTemplate:    "CWE-1336",
	taint.SnkDeserialize: "CWE-502",
	taint.SnkLog:         "CWE-117",
	taint.SnkCrypto:      "CWE-327",
	taint.SnkURLFetch:    "CWE-918",
	taint.SnkRegexDoS:    "CWE-1333",
	taint.SnkPrototype:   "CWE-1321",
}

// owaspForSinkCategory maps sink categories to OWASP top 10.
var owaspForSinkCategory = map[taint.SinkCategory]string{
	taint.SnkSQLQuery:    "A03:2021-Injection",
	taint.SnkNoSQL:       "A03:2021-Injection",
	taint.SnkCSV:         "A03:2021-Injection",
	taint.SnkUpload:      "A04:2021-Insecure Design",
	taint.SnkCommand:     "A03:2021-Injection",
	taint.SnkFileWrite:   "A01:2021-Broken Access Control",
	taint.SnkHTMLOutput:  "A03:2021-Injection",
	taint.SnkEval:        "A03:2021-Injection",
	taint.SnkRedirect:    "A01:2021-Broken Access Control",
	taint.SnkLDAP:        "A03:2021-Injection",
	taint.SnkXPath:       "A03:2021-Injection",
	taint.SnkHeader:      "A03:2021-Injection",
	taint.SnkTemplate:    "A03:2021-Injection",
	taint.SnkDeserialize: "A08:2021-Software and Data Integrity Failures",
	taint.SnkLog:         "A09:2021-Security Logging and Monitoring Failures",
	taint.SnkCrypto:      "A02:2021-Cryptographic Failures",
	taint.SnkURLFetch:    "A10:2021-Server-Side Request Forgery",
	taint.SnkRegexDoS:    "A04:2021-Insecure Design",
	taint.SnkPrototype:   "A08:2021-Software and Data Integrity Failures",
}

// severityForSinkCategory maps sink categories to finding severity.
var severityForSinkCategory = map[taint.SinkCategory]rules.Severity{
	taint.SnkSQLQuery:    rules.Critical,
	taint.SnkNoSQL:       rules.High,
	taint.SnkCommand:     rules.Critical,
	taint.SnkEval:        rules.Critical,
	taint.SnkDeserialize: rules.Critical,
	taint.SnkFileWrite:   rules.High,
	taint.SnkHTMLOutput:  rules.High,
	taint.SnkRedirect:    rules.High,
	taint.SnkLDAP:        rules.High,
	taint.SnkXPath:       rules.High,
	taint.SnkHeader:      rules.High,
	taint.SnkTemplate:    rules.High,
	taint.SnkURLFetch:    rules.High,
	taint.SnkLog:         rules.Medium,
	taint.SnkCSV:         rules.Medium,
	taint.SnkUpload:      rules.High,
	taint.SnkCrypto:      rules.High,
	taint.SnkRegexDoS:    rules.Medium,
	taint.SnkPrototype:   rules.High,
}

// Patterns for identifying taint source parameter types.
//
// http.ResponseWriter is intentionally NOT in this list. The ResponseWriter
// is the OUTBOUND side of an HTTP handler — anything an attacker controls
// flows through *http.Request, not through the writer. Treating w as a
// source caused the interprocedural HTML_OUTPUT analysis to fire on every
// `w.Write([]byte("static string"))` inside an error handler or static
// response path. The *http.Request parameter is still detected, so route
// handlers continue to be picked up as entry points.
var sourceParamPatterns = map[*regexp.Regexp]taint.SourceCategory{
	regexp.MustCompile(`\*?http\.Request`): taint.SrcUserInput,
	regexp.MustCompile(`\*?gin\.Context`):  taint.SrcUserInput,
	regexp.MustCompile(`\*?echo\.Context`): taint.SrcUserInput,
	regexp.MustCompile(`\*?fiber\.Ctx`):    taint.SrcUserInput,
	regexp.MustCompile(`\*?sql\.Row`):      taint.SrcDatabase,
	regexp.MustCompile(`\*?sql\.Rows`):     taint.SrcDatabase,
	regexp.MustCompile(`\*?gorm\.DB`):      taint.SrcDatabase,
	regexp.MustCompile(`io\.Reader`):       taint.SrcNetwork,
	regexp.MustCompile(`io\.ReadCloser`):   taint.SrcNetwork,
	regexp.MustCompile(`net\.Conn`):        taint.SrcNetwork,
}

// directSourcePatterns matches common taint source expressions in argument expressions.
// Compiled once at package level to avoid re-compiling on every call to isArgTaintedInCaller.
var directSourcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bRequest\b`),
	regexp.MustCompile(`\.FormValue\s*\(`),
	regexp.MustCompile(`\.Query\(\)\.(Get|Encode)`),
	regexp.MustCompile(`\.PostForm\b`),
	regexp.MustCompile(`\.URL\.Query\b`),
	regexp.MustCompile(`\.Body\b`),
	regexp.MustCompile(`\.Header\.(Get|Values)\s*\(`),
	regexp.MustCompile(`\.Param\s*\(`),
	regexp.MustCompile(`\.QueryParam\s*\(`),
	regexp.MustCompile(`\bc\.Query\s*\(`),
	regexp.MustCompile(`\bc\.PostForm\s*\(`),
	regexp.MustCompile(`os\.Args\b`),
	regexp.MustCompile(`os\.Getenv\s*\(`),
}

// Patterns for identifying sink calls.
var sinkCallPatterns = []struct {
	pattern  *regexp.Regexp
	category taint.SinkCategory
	method   string
	// dangerousArgs is the 0-indexed list of argument positions
	// that actually carry user-controlled data into the sink. nil
	// (no positional info) means "any arg" — legacy behaviour.
	dangerousArgs []int
}{
	// dangerousArgs lists the 0-indexed positions that carry user-
	// controlled data INTO the sink. nil / empty means "any arg"
	// (legacy ArgFromParam == -1 behaviour). Setting it correctly is
	// critical to avoid FPs like "the *http.Request flowing into
	// http.Redirect" — http.Redirect's first arg is the writer, the
	// second is the request (read for Method only), and only the third
	// (the URL string) is actually a redirect-target value.
	{regexp.MustCompile(`\bdb\.\s*(Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(`), taint.SnkSQLQuery, "sql.Query", []int{0}},
	{regexp.MustCompile(`\bsql\.\s*(Query|QueryRow|Exec)\s*\(`), taint.SnkSQLQuery, "sql.Query", []int{0}},
	// exec.Command(name, args...) is variadic — every position can
	// carry a tainted shell-injection vector (the binary, or any flag/
	// value handed to it). Use nil = "any arg".
	{regexp.MustCompile(`\bexec\.\s*(Command|CommandContext)\s*\(`), taint.SnkCommand, "exec.Command", nil},
	{regexp.MustCompile(`\bos\.\s*(Create|Open|OpenFile|WriteFile|Remove|Rename|Mkdir)\s*\(`), taint.SnkFileWrite, "os.File", []int{0}},
	// fmt.Fprint(w, ...): the writer is arg 0, dangerous args start at 1.
	// fmt.Fprintf(w, format, args...): same — but format string is arg 1.
	{regexp.MustCompile(`\bfmt\.\s*(Fprintf|Fprint|Fprintln)\s*\(\s*w\b`), taint.SnkHTMLOutput, "fmt.Fprint(w)", []int{1}},
	// w.Write([]byte(x)): the byte slice is arg 0.
	{regexp.MustCompile(`\bw\.Write\s*\(`), taint.SnkHTMLOutput, "ResponseWriter.Write", []int{0}},
	// template.HTML(x) / .JS / .URL: the value being trusted is arg 0.
	{regexp.MustCompile(`\btemplate\.\s*(HTML|JS|URL)\s*\(`), taint.SnkTemplate, "template", []int{0}},
	// http.Redirect(w, r, url, code): only the URL (arg 2) is the
	// redirect target. r is read for Method, not URL. This is the bug
	// that made the cross-file Coder REDIRECT cluster fire on
	// `*http.Request` flows.
	{regexp.MustCompile(`\bhttp\.Redirect\s*\(`), taint.SnkRedirect, "http.Redirect", []int{2}},
	// http.Get/Post/Head(url, ...): URL is arg 0.
	{regexp.MustCompile(`\bhttp\.\s*(Get|Post|Head)\s*\(`), taint.SnkURLFetch, "http.Get", []int{0}},
	{regexp.MustCompile(`\beval\s*\(`), taint.SnkEval, "eval", []int{0}},
	// Note: Go's memory-safe stdlib/common decoders are intentionally NOT
	// interprocedural deserialization sinks. encoding/json, gopkg.in/yaml.v2/v3,
	// encoding/xml, and toml all decode into typed Go structs (or generic
	// maps/slices) — they do NOT instantiate attacker-chosen types the way
	// Java's ObjectInputStream, Python's pickle/yaml.load, Ruby's Marshal.load,
	// or PHP's unserialize do. Feeding an HTTP body to yaml.Unmarshal(&cfg) is
	// normal, safe deserialization, so the interproc lift previously flagged it
	// as CRITICAL on essentially every Go web service (block-lane FP cluster).
	// The genuinely type-instantiating Go decoder is encoding/gob; it is
	// covered by the catalog + astflow/ssaflow lane, which additionally
	// suppresses typed-struct targets (isTypedStructTarget) — a discrimination
	// this coarse single-line regex lane cannot make, so gob is deliberately
	// left out here rather than re-introducing the same false positives.
	// log.Printf(format, args...): format string is arg 0. Other
	// log.Print variants accept positional args from 0 onward.
	{regexp.MustCompile(`\blog\.\s*(Print|Printf|Println|Fatal|Fatalf)\s*\(`), taint.SnkLog, "log.Print", nil},
}

// sanitizerPatterns identifies sanitization calls.
var sanitizerPatterns = []struct {
	pattern   *regexp.Regexp
	category  taint.SinkCategory
	sanitizer string
}{
	{regexp.MustCompile(`\bhtml\.EscapeString\s*\(`), taint.SnkHTMLOutput, "html.EscapeString"},
	{regexp.MustCompile(`\burl\.QueryEscape\s*\(`), taint.SnkRedirect, "url.QueryEscape"},
	{regexp.MustCompile(`\burl\.PathEscape\s*\(`), taint.SnkFileWrite, "url.PathEscape"},
	// PR-HH: filepath.Clean is NOT a path-traversal sanitiser on its own
	// (Clean("../../etc/passwd") still returns "../../etc/passwd"). The
	// complete guards are filepath.IsLocal (Go 1.20+), filepath.Localize
	// (Go 1.23+), and securejoin.SecureJoin. The Clean+HasPrefix combo is
	// recognised by the astflow walker's processGuardPattern; this regex
	// list only sees one line at a time and can't pair them.
	{regexp.MustCompile(`\bfilepath\.IsLocal\s*\(`), taint.SnkFileWrite, "filepath.IsLocal"},
	{regexp.MustCompile(`\bfilepath\.IsLocal\s*\(`), taint.SnkFileRead, "filepath.IsLocal"},
	{regexp.MustCompile(`\bfilepath\.Localize\s*\(`), taint.SnkFileWrite, "filepath.Localize"},
	{regexp.MustCompile(`\bfilepath\.Localize\s*\(`), taint.SnkFileRead, "filepath.Localize"},
	{regexp.MustCompile(`\bsecurejoin\.SecureJoin(?:VFS)?\s*\(`), taint.SnkFileWrite, "securejoin.SecureJoin"},
	{regexp.MustCompile(`\bsecurejoin\.SecureJoin(?:VFS)?\s*\(`), taint.SnkFileRead, "securejoin.SecureJoin"},
	{regexp.MustCompile(`\bstrconv\.\s*(Atoi|ParseInt|ParseFloat|ParseBool)\s*\(`), taint.SnkSQLQuery, "strconv.Parse"},
	{regexp.MustCompile(`\bsqlx?\.\s*Named\s*\(`), taint.SnkSQLQuery, "sql.Named"},
	{regexp.MustCompile(`\bregexp\.\s*(Match|Find|Replace)\w*\s*\(`), taint.SnkSQLQuery, "regexp.Match"},
}

// PropagateInterproc performs interprocedural taint analysis starting
// from the given changed functions. It:
//  1. Computes the taint signature of each changed function
//  2. Compares with the previous signature
//  3. If changed, walks all callers and computes cross-function flows
//  4. Returns findings for any new interprocedural taint paths
//
// When flows (from Layer 3 taint analysis) are provided, ComputeTaintSig
// uses them for precise signature computation instead of regex heuristics.
//
// suppressedLines, when non-nil, contains line numbers with active
// batou:ignore directives. Sinks on those lines are moved to
// SuppressedSinks so callers don't generate phantom findings.
func PropagateInterproc(cg *CallGraph, changedFuncIDs []string, fileContents map[string]string, flows []taint.TaintFlow, suppressedLines map[int]bool) []rules.Finding {
	return PropagateInterprocTyped(cg, changedFuncIDs, fileContents, flows, suppressedLines, nil)
}

// PropagateInterprocTyped is like PropagateInterproc but accepts an optional
// GoTypeInfo for typed-summary computation. Pass nil for the legacy
// regex-only behavior (equivalent to PropagateInterproc).
func PropagateInterprocTyped(cg *CallGraph, changedFuncIDs []string, fileContents map[string]string, flows []taint.TaintFlow, suppressedLines map[int]bool, typed *GoTypeInfo) []rules.Finding {
	var findings []rules.Finding

	// Cache per-file type info for caller-side type matching. Changed file
	// uses the scanner-provided typed info; other files are parsed on demand.
	callerTyped := map[string]*GoTypeInfo{}

	// Cache per-file typed FuncSignature lists for non-Go languages. Per-
	// changed-func ComputeTaintSigTyped calls otherwise re-run the language
	// extractor (which re-parses tree-sitter from scratch — see
	// pythonExtractor.ExtractFunctions) once per function. On Django, each
	// 200-line module has 4-10 functions and the same parse runs 4-10 times.
	// Hoisting the extraction to one call per file path cuts the per-file
	// scan cost noticeably for Python repos.
	sigCache := map[string][]FuncSignature{}

	for _, funcID := range changedFuncIDs {
		node := cg.GetNode(funcID)
		if node == nil {
			continue
		}

		content, ok := fileContents[node.FilePath]
		if !ok {
			continue
		}

		// Compute the new taint signature for this changed function.
		// Pass Layer 3 flows for precise analysis when available.
		newSig := computeTaintSigTypedCached(node, content, node.Language, flows, suppressedLines, typed, sigCache)

		// Compare with the old signature.
		oldSig := node.TaintSig
		if !SignatureChanged(oldSig, newSig) {
			continue
		}

		// Update the node's signature.
		node.TaintSig = newSig
		if typed != nil && node.Language == rules.LangGo {
			callerTyped[node.FilePath] = typed
		}

		// Walk callers transitively up to maxTraversalDepth levels. Sort by a
		// stable key so which caller path is reported (and the resulting
		// taint_path) is deterministic — GetTransitiveCallers' BFS order depends
		// on CalledBy edge insertion order, which varies with graph build order.
		callers := cg.GetTransitiveCallers(funcID, maxTraversalDepth)
		sort.Slice(callers, func(i, j int) bool {
			if callers[i].ID != callers[j].ID {
				return callers[i].ID < callers[j].ID
			}
			return callers[i].StartLine < callers[j].StartLine
		})
		for _, callerNode := range callers {
			callerContent, ok := fileContents[callerNode.FilePath]
			if !ok {
				// Caller is in a different file — read it from disk.
				callerContent, ok = loadCallerFile(cg, callerNode.FilePath, fileContents)
				if !ok {
					continue
				}
			}

			// Build/lookup caller-side type info for typed call-site matching.
			var callerTypes *GoTypeInfo
			if callerNode.Language == rules.LangGo {
				callerTypes = resolveCallerTypeInfo(callerNode.FilePath, callerContent, typed, callerTyped)
			}

			callerFindings := analyzeCallerImpactTyped(cg, callerNode, node, callerContent, callerTypes)
			findings = append(findings, callerFindings...)
		}
	}

	return findings
}

// resolveCallerTypeInfo returns the GoTypeInfo for a caller file, parsing it
// lazily if necessary. If the caller is the same file that was already typed
// (scanner-provided), that info is reused.
func resolveCallerTypeInfo(filePath, content string, scanTyped *GoTypeInfo, cache map[string]*GoTypeInfo) *GoTypeInfo {
	if scanTyped != nil && scanTyped.File != nil {
		// Reuse the scan's typed info for the changed file.
		if cached, ok := cache[filePath]; ok {
			return cached
		}
	}
	if cached, ok := cache[filePath]; ok {
		return cached
	}
	parsed := astflow.ParseGo(content, filePath)
	if parsed == nil {
		cache[filePath] = nil
		return nil
	}
	info := BuildGoTypeInfoWithFset(parsed.File, parsed.Fset)
	cache[filePath] = info
	return info
}

// BuildGoTypeInfo builds a GoTypeInfo from a parsed *ast.File, populating
// the type environment and indexing every function declaration by its
// canonical FuncNode name ("Func" or "Recv.Method"). Exported for scanner use.
func BuildGoTypeInfo(file *ast.File) *GoTypeInfo {
	return buildGoTypeInfo(file)
}

// BuildGoTypeInfoWithFset is like BuildGoTypeInfo but also indexes closure
// literals (*ast.FuncLit) by their canonical
// "<EnclosingName>.closure@<line>:<col>" name so populateTypedParams can
// resolve closure FuncNodes the same way it resolves top-level functions.
// Pass nil fset to skip closure indexing.
func BuildGoTypeInfoWithFset(file *ast.File, fset *token.FileSet) *GoTypeInfo {
	info := buildGoTypeInfo(file)
	if info != nil {
		info.Fset = fset
		info.FuncLits = indexFuncLits(file, fset)
	}
	return info
}

// buildGoTypeInfo is the internal builder, kept for call sites inside the
// package that prefer the unexported spelling.
func buildGoTypeInfo(file *ast.File) *GoTypeInfo {
	info := &GoTypeInfo{
		File:      file,
		TypeEnv:   astflow.BuildTypeEnv(file),
		FuncDecls: make(map[string]*ast.FuncDecl),
		FuncLits:  make(map[string]*ast.FuncLit),
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			if recv := exprTypeNameFromAST(fn.Recv.List[0].Type); recv != "" {
				name = recv + "." + fn.Name.Name
			}
		}
		info.FuncDecls[name] = fn
	}
	return info
}

// indexFuncLits walks file's declarations and returns a map from canonical
// closure name ("<EnclosingName>.closure@<line>:<col>") to the *ast.FuncLit.
// Mirrors the stack-based walk in builder.go::walkFuncBody so the names match
// byte-for-byte. Returns an empty map when fset is nil.
func indexFuncLits(file *ast.File, fset *token.FileSet) map[string]*ast.FuncLit {
	out := make(map[string]*ast.FuncLit)
	if file == nil || fset == nil {
		return out
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Name == nil {
			continue
		}
		outerName := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			if recv := exprTypeNameFromAST(fd.Recv.List[0].Type); recv != "" {
				outerName = recv + "." + fd.Name.Name
			}
		}
		// Stack of name-prefixes mirroring walkFuncBody.
		stack := []string{outerName}
		cur := func() string { return stack[len(stack)-1] }
		push := func(s string) { stack = append(stack, s) }
		pop := func() { stack = stack[:len(stack)-1] }

		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if n == nil {
				pop()
				return false
			}
			if fl, ok := n.(*ast.FuncLit); ok {
				pos := fset.Position(fl.Pos())
				closureName := FormatClosureName(cur(), pos.Line, pos.Column)
				out[closureName] = fl
				push(closureName)
				return true
			}
			push(cur())
			return true
		})
	}
	return out
}

// exprTypeNameFromAST extracts a type name from a receiver expression,
// mirroring builder.exprTypeName but local to this file to avoid circularity.
func exprTypeNameFromAST(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeNameFromAST(t.X)
	case *ast.IndexExpr:
		return exprTypeNameFromAST(t.X)
	}
	return ""
}

// ComputeTaintSig analyzes a function body and produces its TaintSignature.
// This summarizes: which params carry taint, which returns carry taint,
// what sinks exist, what sanitizers are applied.
//
// When flows (from Layer 3 taint analysis) are non-empty, the signature is
// populated from precise dataflow results instead of regex heuristics.
// Flows are filtered to those within this function's line range. The regex
// fallback is used when flows is nil or empty.
//
// suppressedLines contains lines with active batou:ignore directives.
// Sinks on those lines are moved to SuppressedSinks instead of SinkCalls.
func ComputeTaintSig(node *FuncNode, content string, lang rules.Language, flows []taint.TaintFlow, suppressedLines map[int]bool) TaintSignature {
	return ComputeTaintSigTyped(node, content, lang, flows, suppressedLines, nil)
}

// ComputeTaintSigTyped is like ComputeTaintSig but additionally populates
// the typed Params/Returns fields when typed metadata is available for the
// function's language:
//
//   - Go: when a GoTypeInfo is provided, the established Go path runs
//     (unchanged since typed summaries were introduced).
//   - Other languages: when a TypeExtractor is registered for the language
//     (see RegisterExtractor), it produces FuncSignatures which populate
//     Params/Returns/SourceParams/TaintedReturns. No extractor → no typed
//     fields, and sig is identical to ComputeTaintSig's output.
//
// The legacy SourceParams map is still populated for backward compatibility
// in both paths.
func ComputeTaintSigTyped(node *FuncNode, content string, lang rules.Language, flows []taint.TaintFlow, suppressedLines map[int]bool, typed *GoTypeInfo) TaintSignature {
	return computeTaintSigTypedCached(node, content, lang, flows, suppressedLines, typed, nil)
}

// computeTaintSigTypedCached is ComputeTaintSigTyped with an optional
// per-file FuncSignature cache. When the caller iterates over multiple
// changed functions in the same file (PropagateInterprocTyped's
// dominant loop), the cache avoids re-running the registered language
// extractor — which would re-parse the file with tree-sitter — once per
// function in that file. Pass nil for the uncached single-shot
// behaviour (no behavioural difference; pure perf optimisation).
func computeTaintSigTypedCached(node *FuncNode, content string, lang rules.Language, flows []taint.TaintFlow, suppressedLines map[int]bool, typed *GoTypeInfo, sigCache map[string][]FuncSignature) TaintSignature {
	sig := computeTaintSigInner(node, content, lang, flows, suppressedLines)
	if lang == rules.LangGo && typed != nil {
		populateTypedParams(node, typed, &sig)
		return sig
	}
	if lang != rules.LangGo && IsExtractorSupported(lang) {
		sigs, ok := lookupCachedSigs(sigCache, node.FilePath)
		if !ok {
			ctx := &ExtractContext{
				FilePath: node.FilePath,
				Content:  []byte(content),
				Language: lang,
			}
			sigs = GetExtractor(lang).ExtractFunctions(ctx)
			if sigCache != nil {
				sigCache[node.FilePath] = sigs
			}
		}
		populateTypedParamsFromSigs(node, sigs, &sig)
	}
	// MyBatis mapper-annotation sink (Java only). A @Mapper interface
	// method whose @Select/@Update/... SQL contains `${...}` is a CWE-89
	// SQL-injection sink; `#{...}` parameterised binding is safe. The
	// method node's body text includes the leading annotation (tree-sitter
	// puts the @Select inside the method_declaration), so we scan it here
	// after typed params are populated (so the dollar-token → param-index
	// pairing in maybeAppendMyBatisSink can use sig.Params). Done last so
	// suppressed lines from computeTaintSigInner are already filtered; the
	// mapper sink is then subject to the same SinkCalls participation as
	// any other sink in SignatureChanged / the caller walk.
	if lang == rules.LangJava {
		if body := extractFuncBody(content, node.StartLine, node.EndLine); body != "" {
			maybeAppendMyBatisSink(node, body, &sig)
		}
	}
	return sig
}

// lookupCachedSigs returns the cached FuncSignature list for filePath
// when cache is non-nil and the entry exists. ok signals whether the
// returned slice came from the cache (vs. needing extraction).
func lookupCachedSigs(cache map[string][]FuncSignature, filePath string) ([]FuncSignature, bool) {
	if cache == nil {
		return nil, false
	}
	sigs, ok := cache[filePath]
	return sigs, ok
}

// populateTypedParamsFromSigs copies Params/Returns from a pre-extracted
// FuncSignature onto a TaintSignature, mirroring the side-effects of
// populateTypedParams (SourceParams, TaintedReturns, TypesVersion, IsPure
// recomputation) so registry-produced typed data behaves the same way as
// the Go-native path.
func populateTypedParamsFromSigs(node *FuncNode, sigs []FuncSignature, sig *TaintSignature) {
	var match *FuncSignature
	for i := range sigs {
		if sigs[i].Name == node.Name {
			match = &sigs[i]
			break
		}
	}
	if match == nil {
		return
	}
	if sig.SourceParams == nil {
		sig.SourceParams = make(map[int]taint.SourceCategory)
	}
	sig.Params = append(sig.Params[:0], match.Params...)
	sig.Returns = append(sig.Returns[:0], match.Returns...)
	for _, p := range match.Params {
		if p.IsSourceType {
			sig.SourceParams[p.Index] = p.SourceCategory
		}
	}
	for _, r := range match.Returns {
		if r.IsSourceType {
			if sig.TaintedReturns == nil {
				sig.TaintedReturns = make(map[int][]taint.SourceCategory)
			}
			sig.TaintedReturns[r.Index] = appendUniqueCat(sig.TaintedReturns[r.Index], r.SourceCategory)
		}
	}
	sig.TypesVersion = TypesSchemaVersion
	sig.IsPure = len(sig.SourceParams) == 0 &&
		len(sig.SinkCalls) == 0 &&
		len(sig.TaintedReturns) == 0 &&
		len(sig.TaintedParams) == 0
}

// computeTaintSigInner is the pre-typed implementation, kept under its
// original logic so that legacy callers are byte-for-byte identical.
func computeTaintSigInner(node *FuncNode, content string, lang rules.Language, flows []taint.TaintFlow, suppressedLines map[int]bool) TaintSignature {
	sig := TaintSignature{
		TaintedParams:  make(map[int][]taint.SourceCategory),
		TaintedReturns: make(map[int][]taint.SourceCategory),
		SourceParams:   make(map[int]taint.SourceCategory),
	}

	// Extract the function body from the full file content.
	body := extractFuncBody(content, node.StartLine, node.EndLine)
	if body == "" {
		sig.IsPure = true
		return sig
	}

	// Filter flows to those within this function's line range.
	funcFlows := filterFlowsForFunc(flows, node.StartLine, node.EndLine)

	// When Layer 3 taint flows are available, use them for precise
	// signature computation instead of regex heuristics.
	if len(funcFlows) > 0 {
		flowSig := computeSigFromFlows(node, funcFlows, body)
		return filterSuppressedSinks(flowSig, suppressedLines)
	}

	// --- Regex fallback (no Layer 3 flows available) ---

	lines := strings.Split(body, "\n")

	// Step 1: Identify source parameters from the function signature.
	// Look at the first line (function declaration) for parameter types.
	if len(lines) > 0 {
		funcDecl := lines[0]
		identifySourceParams(funcDecl, &sig)
	}

	// Step 2: Find sink calls in the function body.
	for lineIdx, line := range lines {
		lineNum := node.StartLine + lineIdx

		for _, sp := range sinkCallPatterns {
			if sp.pattern.MatchString(line) {
				// SQL sinks that pass `?` / `$N` placeholders are
				// using parameterized queries — values are bound,
				// not concatenated, so this isn't a SQL-injection
				// surface even if a caller's tainted arg flows into
				// the call as e.g. a context.Context plumbing arg.
				// Checks the call line AND its continuation lines so a
				// multi-line query whose placeholder sits below the
				// call line is recognized too.
				if sp.category == taint.SnkSQLQuery && sqlCallIsParameterized(lines, lineIdx) {
					continue
				}

				sinkRef := SinkRef{
					SinkCategory: sp.category,
					MethodName:   sp.method,
					Line:         lineNum,
					ArgFromParam: -1, // refined below
				}

				// findParamFlowToSinkFiltered traces which of the
				// enclosing function's parameters flows into the
				// sink call. dangerousArgs (when non-nil) restricts
				// the trace to specific positions of the sink call
				// itself — http.Redirect(w, r, url, code) only
				// counts position 2 (url) as receiving taint, even
				// though `r` is technically forwarded into the call.
				sinkRef.ArgFromParam = findParamFlowToSinkFiltered(lines, lineIdx, &sig, sp.dangerousArgs)

				sig.SinkCalls = append(sig.SinkCalls, sinkRef)
			}
		}
	}

	// Step 3: Find sanitized paths.
	for lineIdx, line := range lines {
		lineNum := node.StartLine + lineIdx
		for _, sp := range sanitizerPatterns {
			if sp.pattern.MatchString(line) {
				// Record sanitized paths for each source param + matching sink.
				for paramIdx := range sig.SourceParams {
					for _, sink := range sig.SinkCalls {
						if sink.SinkCategory == sp.category && sink.Line > lineNum {
							sig.SanitizedPaths = append(sig.SanitizedPaths, SanitizedPath{
								ParamIndex:    paramIdx,
								SinkCategory:  sp.category,
								SanitizerName: sp.sanitizer,
								SanitizerLine: lineNum,
							})
						}
					}
				}
			}
		}
	}

	// Step 4: Determine tainted params and returns.
	// If a source param exists and reaches a sink, the param is tainted.
	for paramIdx, srcCat := range sig.SourceParams {
		for _, sink := range sig.SinkCalls {
			if sink.ArgFromParam == paramIdx || sink.ArgFromParam == -1 {
				if !isPathSanitized(sig.SanitizedPaths, paramIdx, sink.SinkCategory) {
					sig.TaintedParams[paramIdx] = appendUniqueCat(
						sig.TaintedParams[paramIdx], srcCat,
					)
				}
			}
		}
	}

	// If there are source params but no sinks, taint may propagate through returns.
	if len(sig.SourceParams) > 0 && len(sig.SinkCalls) == 0 {
		// Check if the function returns values derived from params.
		// CH5: a bare `return "const"` / `return nil` / `return 0` that
		// does not reference any param-derived token does NOT carry the
		// param's taint, so the return must not be marked tainted on the
		// mere coexistence of a source param and a `return` statement.
		// Require the return expression to lexically reference a source
		// param (or a local assigned from a param-derived expression).
		// Be conservative: only a clear literal/constant return with no
		// param reference is suppressed.
		for lineIdx := len(lines) - 1; lineIdx >= 0; lineIdx-- {
			line := strings.TrimSpace(lines[lineIdx])
			if strings.HasPrefix(line, "return ") {
				if returnExprCarriesParam(lines, line, &sig) {
					for _, srcCat := range sig.SourceParams {
						sig.TaintedReturns[0] = appendUniqueCat(
							sig.TaintedReturns[0], srcCat,
						)
					}
				}
				break
			}
		}
	}

	// Per-field return taint (CH3): record precise per-field tainted return
	// paths for partial-struct returns so a caller reading a clean sibling
	// field is not over-tainted (see scanGoBodyForTaintedReturnPaths).
	populateGoTaintedReturnPaths(&sig, body)

	// Move suppressed sinks to SuppressedSinks so callers skip them.
	sig = filterSuppressedSinks(sig, suppressedLines)

	// A function is pure if it has no source params, no sinks, and no tainted returns.
	sig.IsPure = len(sig.SourceParams) == 0 &&
		len(sig.SinkCalls) == 0 &&
		len(sig.TaintedReturns) == 0 &&
		len(sig.TaintedReturnPaths) == 0 &&
		len(sig.TaintedParams) == 0

	return sig
}

// returnExprCarriesParam reports whether the return expression on returnLine
// lexically references data derived from one of the function's source params.
//
// CH5: the regex-fallback return-taint heuristic previously marked a function's
// return tainted whenever a `return` statement coexisted with a source param,
// firing even on a bare `return "const"` / `return nil` / `return 0` that does
// not carry the param. This helper tightens that: the return is only treated as
// carrying taint when its expression
//
//	(a) references a source param name as a whole-word token, OR
//	(b) references a local variable that was assigned (anywhere above the
//	    return in the body) from an expression that itself references a
//	    source param — covering `tmp := transform(p); return tmp`.
//
// It is deliberately conservative on the recall side: any return expression
// that mentions a param-derived token is kept tainted. Only a return whose
// expression references NO param and NO param-derived local — i.e. a clear
// literal/constant — is suppressed. When param names cannot be recovered from
// the declaration, it returns true (preserve the legacy taint-through-return
// behaviour rather than risk dropping recall).
func returnExprCarriesParam(lines []string, returnLine string, sig *TaintSignature) bool {
	// Strip the leading "return " keyword to get the returned expression.
	expr := strings.TrimSpace(strings.TrimPrefix(returnLine, "return"))
	if expr == "" {
		// `return` with no value can't carry data.
		return false
	}

	// Collect source-param names.
	paramNames := make([]string, 0, len(sig.SourceParams))
	for paramIdx := range sig.SourceParams {
		if name := findParamName(lines, paramIdx); name != "" {
			paramNames = append(paramNames, name)
		}
	}
	if len(paramNames) == 0 {
		// Couldn't recover any param name — preserve the legacy behaviour
		// (mark tainted) rather than risk dropping a real flow.
		return true
	}

	// (a) Direct: the return expression references a source param token.
	for _, name := range paramNames {
		if containsToken(expr, name) {
			return true
		}
	}

	// (b) Indirect: the return expression references a local that was
	// assigned from a param-derived expression. Walk assignments above the
	// return; whenever a local's RHS references a param (or an already
	// param-derived local), mark that local derived. Then check whether the
	// return expression references any derived local.
	derived := make(map[string]bool)
	for _, line := range lines {
		lhs, rhs, ok := splitAssignment(line)
		if !ok {
			continue
		}
		rhsCarries := false
		for _, name := range paramNames {
			if containsToken(rhs, name) {
				rhsCarries = true
				break
			}
		}
		if !rhsCarries {
			for d := range derived {
				if containsToken(rhs, d) {
					rhsCarries = true
					break
				}
			}
		}
		if rhsCarries {
			for _, name := range lhs {
				if name != "" {
					derived[name] = true
				}
			}
		}
	}
	for d := range derived {
		if containsToken(expr, d) {
			return true
		}
	}

	return false
}

// splitAssignment parses a single source line into its assigned local names
// (LHS) and the right-hand-side expression. It recognises the common
// assignment forms across the languages routed through the regex fallback:
//
//	x := rhs        x = rhs        x, y := rhs        var x = rhs
//	const x = rhs   let x = rhs    $x = rhs
//
// It deliberately ignores comparisons (==, !=, <=, >=) and the augmented
// forms are treated as assignments to the LHS (so `x += p` marks x derived).
// Returns ok=false when the line is not an assignment.
func splitAssignment(line string) (lhs []string, rhs string, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "return") {
		return nil, "", false
	}

	// Prefer ':=' (Go/short-var); fall back to a single '='.
	var idx, opLen int
	if p := strings.Index(s, ":="); p >= 0 {
		idx, opLen = p, 2
	} else {
		// Find the first '=' that is a real assignment, not a comparison
		// or part of '<=', '>=', '!=', '=='.
		for i := 0; i < len(s); i++ {
			if s[i] != '=' {
				continue
			}
			prev := byte(' ')
			if i > 0 {
				prev = s[i-1]
			}
			next := byte(' ')
			if i+1 < len(s) {
				next = s[i+1]
			}
			if prev == '=' || prev == '!' || prev == '<' || prev == '>' || next == '=' {
				continue
			}
			// Treat augmented assignments (+=, -=, etc.) as assignments
			// to the LHS variable.
			if prev == '+' || prev == '-' || prev == '*' || prev == '/' || prev == '|' || prev == '&' {
				idx, opLen = i, 1
				// LHS excludes the operator char.
				lhsRaw := strings.TrimSpace(s[:i-1])
				return assignmentLHSNames(lhsRaw), strings.TrimSpace(s[idx+opLen:]), len(lhsRaw) > 0
			}
			idx, opLen = i, 1
			break
		}
		if opLen == 0 {
			return nil, "", false
		}
	}

	lhsRaw := strings.TrimSpace(s[:idx])
	rhs = strings.TrimSpace(s[idx+opLen:])
	names := assignmentLHSNames(lhsRaw)
	if len(names) == 0 || rhs == "" {
		return nil, "", false
	}
	return names, rhs, true
}

// assignmentLHSNames extracts the bare identifier names from an assignment
// LHS, stripping leading declaration keywords (var/const/let/my) and any
// type annotation, and splitting comma-separated multi-assignment targets.
func assignmentLHSNames(lhsRaw string) []string {
	lhsRaw = strings.TrimSpace(lhsRaw)
	// Strip a leading declaration keyword.
	for _, kw := range []string{"var ", "const ", "let ", "my ", "final ", "val "} {
		if strings.HasPrefix(lhsRaw, kw) {
			lhsRaw = strings.TrimSpace(lhsRaw[len(kw):])
			break
		}
	}
	var out []string
	for _, part := range strings.Split(lhsRaw, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "$") // PHP/Perl sigil
		// Take just the identifier (drop any trailing type annotation
		// like `x int` or `x: string`).
		fields := strings.FieldsFunc(part, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ':'
		})
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if isPlainIdentifier(name) {
			out = append(out, name)
		}
	}
	return out
}

// isPlainIdentifier reports whether s is a simple identifier (letters, digits,
// underscore, not starting with a digit) — used to reject blank `_`, indexed
// targets like `a[i]`, and field stores like `o.x` from the derived-local set.
func isPlainIdentifier(s string) bool {
	if s == "" || s == "_" {
		return false
	}
	for i, r := range s {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// filterFlowsForFunc returns the subset of flows whose source or sink line
// falls within the function's line range.
func filterFlowsForFunc(flows []taint.TaintFlow, startLine, endLine int) []taint.TaintFlow {
	if len(flows) == 0 {
		return nil
	}
	var out []taint.TaintFlow
	for _, f := range flows {
		if (f.SourceLine >= startLine && f.SourceLine <= endLine) ||
			(f.SinkLine >= startLine && f.SinkLine <= endLine) {
			out = append(out, f)
		}
	}
	return out
}

// computeSigFromFlows builds a TaintSignature from precise Layer 3 taint
// flows, mapping sources to SourceParams, sinks to SinkCalls, and detecting
// sanitizers from flow steps.
func computeSigFromFlows(node *FuncNode, flows []taint.TaintFlow, body string) TaintSignature {
	sig := TaintSignature{
		TaintedParams:  make(map[int][]taint.SourceCategory),
		TaintedReturns: make(map[int][]taint.SourceCategory),
		SourceParams:   make(map[int]taint.SourceCategory),
	}

	// Also run regex-based source param identification so we can map
	// flow sources to parameter indices.
	lines := strings.Split(body, "\n")
	if len(lines) > 0 {
		identifySourceParams(lines[0], &sig)
	}

	// Track which sink categories have sanitizers from the flows.
	sanitizedCategories := make(map[taint.SinkCategory]bool)

	for _, flow := range flows {
		// Same parameterized-SQL filter as the regex path: skip
		// recording SQL sinks whose call uses ? / $N placeholders —
		// checking the call line AND its continuation lines so a
		// multi-line query (placeholder on a later line) is covered.
		if flow.Sink.Category == taint.SnkSQLQuery && flow.SinkLine > 0 {
			lineIdx := flow.SinkLine - node.StartLine
			if sqlCallIsParameterized(lines, lineIdx) {
				continue
			}
		}
		// Map flow sink to a SinkRef.
		sinkRef := SinkRef{
			SinkCategory: flow.Sink.Category,
			MethodName:   flow.Sink.MethodName,
			Line:         flow.SinkLine,
			ArgFromParam: -1,
		}

		// Try to match the flow source to a parameter index.
		// Check if any source param category matches the flow source category.
		for paramIdx, srcCat := range sig.SourceParams {
			if srcCat == flow.Source.Category {
				sinkRef.ArgFromParam = paramIdx
				break
			}
		}

		// Check flow steps for sanitizer presence.
		hasSanitizer := false
		for _, step := range flow.Steps {
			if strings.Contains(step.Description, "sanitiz") ||
				strings.Contains(step.Description, "escape") ||
				strings.Contains(step.Description, "encode") ||
				strings.Contains(step.Description, "clean") ||
				strings.Contains(step.Description, "validate") {
				hasSanitizer = true
				sanitizedCategories[flow.Sink.Category] = true
				break
			}
		}

		sig.SinkCalls = append(sig.SinkCalls, sinkRef)

		// If no sanitizer, mark the param as tainted for this sink.
		if !hasSanitizer && sinkRef.ArgFromParam >= 0 {
			srcCat := sig.SourceParams[sinkRef.ArgFromParam]
			sig.TaintedParams[sinkRef.ArgFromParam] = appendUniqueCat(
				sig.TaintedParams[sinkRef.ArgFromParam], srcCat,
			)
		}

		// Record sanitized paths.
		if hasSanitizer && sinkRef.ArgFromParam >= 0 {
			sig.SanitizedPaths = append(sig.SanitizedPaths, SanitizedPath{
				ParamIndex:   sinkRef.ArgFromParam,
				SinkCategory: flow.Sink.Category,
			})
		}
	}

	// Return-taint heuristic — parity with the regex path (Step 4 above,
	// ~line 714). The flow path otherwise NEVER populates TaintedReturns, yet
	// it is PREFERRED over the regex path when Layer-3 flows exist, so a precise
	// param->return passthrough callee (`func f(x){ return x }`) produced an
	// empty signature and the caller's return-taint path (Path B,
	// checkCallerUsesTaintedReturn, gated on len(TaintedReturns)>0) silently
	// died exactly when analysis was most precise — strictly worse than the
	// regex fallback. When params are sources but no sink consumed them and the
	// body returns param-derived data, mark the return tainted.
	if len(sig.SourceParams) > 0 && len(sig.SinkCalls) == 0 {
		for lineIdx := len(lines) - 1; lineIdx >= 0; lineIdx-- {
			if strings.HasPrefix(strings.TrimSpace(lines[lineIdx]), "return ") {
				for _, srcCat := range sig.SourceParams {
					sig.TaintedReturns[0] = appendUniqueCat(sig.TaintedReturns[0], srcCat)
				}
				break
			}
		}
	}

	// Per-field return taint (CH3): when the body returns a struct/composite
	// literal with only SOME fields carrying sources, record the precise
	// per-field tainted return paths so a caller reading a CLEAN sibling
	// field is not over-tainted. Independent of the whole-return heuristic
	// above (a partial-struct return need not have a source PARAM).
	populateGoTaintedReturnPaths(&sig, body)

	sig.IsPure = len(sig.SourceParams) == 0 &&
		len(sig.SinkCalls) == 0 &&
		len(sig.TaintedReturns) == 0 &&
		len(sig.TaintedReturnPaths) == 0 &&
		len(sig.TaintedParams) == 0

	return sig
}

// populateGoTaintedReturnPaths runs the Go per-field return-path producer
// on a function body and merges the result into sig.TaintedReturnPaths.
// No-op when the body has no decomposable tainted-field return.
func populateGoTaintedReturnPaths(sig *TaintSignature, body string) {
	paths := scanGoBodyForTaintedReturnPaths(body)
	if len(paths) == 0 {
		return
	}
	if sig.TaintedReturnPaths == nil {
		sig.TaintedReturnPaths = make(map[string][]taint.SourceCategory, len(paths))
	}
	for k, v := range paths {
		sig.TaintedReturnPaths[k] = appendUniqueCatList(sig.TaintedReturnPaths[k], v)
	}
}

// AnalyzeCallerImpact checks if a caller is impacted by a callee's taint
// signature change. Returns findings if tainted data from the caller
// flows through the callee to a sink.
func AnalyzeCallerImpact(cg *CallGraph, callerNode *FuncNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactWithSanMemo(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactWithSanMemo is AnalyzeCallerImpact with an optional
// walk-scoped sanitizer-facts memo for the catalog-backed caller-side
// sanitizer gate. The generic path serves Go and Java callees: for Go
// callers the gate is inert (tsflow has no Go config → nil facts →
// fail-open), while Java callers get the same catalog gate the
// per-language walkers use. Pass nil for uncached single-shot behaviour
// (the gate still memoizes per invocation).
func analyzeCallerImpactWithSanMemo(cg *CallGraph, callerNode *FuncNode, calleeNode *FuncNode, callerContent string, sanMemo *sanitizerFactsMemo) []rules.Finding {
	var findings []rules.Finding

	// Fast-path: callees with no sinks AND no tainted-return signature
	// cannot produce findings via either Path A (passes-taint-to-callee)
	// or Path B (uses-tainted-return). Skip the body extraction +
	// regex.Compile cost, which dominates per-file PropagateInterproc
	// runtime on large repos (e.g. Django: thousands of changed Python
	// funcs × 5-deep transitive callers × per-pair regex compile).
	// A field-sensitive-only return (TaintedReturnPaths, CH3) is also a
	// valid Path B driver, so it must NOT be fast-pathed away.
	if len(calleeNode.TaintSig.SinkCalls) == 0 &&
		len(calleeNode.TaintSig.TaintedReturns) == 0 &&
		len(calleeNode.TaintSig.TaintedReturnPaths) == 0 {
		return nil
	}

	callerBody := extractFuncBody(callerContent, callerNode.StartLine, callerNode.EndLine)
	if callerBody == "" {
		return nil
	}

	calleeSig := calleeNode.TaintSig
	lines := strings.Split(callerBody, "\n")

	// Find lines where the caller calls the callee.
	calleeBaseName := extractBaseName(calleeNode.Name)
	callPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(calleeBaseName) + `\s*\(`)

	// Catalog-backed caller-side sanitizer gate (purely suppressive;
	// consulted lazily so non-candidate pairs never pay a parse). Inert
	// for Go callers (tsflow has no Go config).
	sanGate := newCallerSanitizerGate(sanMemo, callerNode, callerContent)

	for lineIdx, line := range lines {
		if !callPattern.MatchString(line) {
			continue
		}

		callLine := callerNode.StartLine + lineIdx

		// --- Path A: Caller passes tainted data TO the callee ---
		// Check if caller passes tainted arguments to callee's sink-connected params.
		findings = append(findings,
			checkCallerPassesTaintToCallee(callerNode, calleeNode, &calleeSig, line, callLine, lines, lineIdx, sanGate)...,
		)

		// --- Path B: Caller uses callee's tainted return value ---
		// Check if callee returns tainted data and caller passes it to a sink.
		findings = append(findings,
			checkCallerUsesTaintedReturn(callerNode, calleeNode, &calleeSig, line, callLine, lines, lineIdx, sanGate)...,
		)
	}

	return findings
}

// FindImpactedCallers returns all functions that may be affected by
// changes to the given functions, walking up the call graph transitively.
func FindImpactedCallers(cg *CallGraph, changedFuncIDs []string) []ImpactedCaller {
	visited := make(map[string]bool)
	var impacted []ImpactedCaller

	for _, funcID := range changedFuncIDs {
		visited[funcID] = true
	}

	for _, funcID := range changedFuncIDs {
		node := cg.GetNode(funcID)
		if node == nil {
			continue
		}

		// BFS up the call graph.
		queue := []string{funcID}
		depth := 0

		for len(queue) > 0 && depth < maxTraversalDepth {
			var nextQueue []string
			for _, id := range queue {
				n := cg.GetNode(id)
				if n == nil {
					continue
				}
				for _, callerID := range n.CalledBy {
					if visited[callerID] {
						continue
					}
					visited[callerID] = true

					callerNode := cg.GetNode(callerID)
					if callerNode == nil {
						continue
					}

					// Determine severity based on the changed function's sinks.
					sev := bestSeverityFromSinks(node.TaintSig.SinkCalls)

					reason := fmt.Sprintf(
						"calls %s which has modified taint signature", node.Name,
					)
					// Partial cross-file path: the caller (source side, where
					// the multi-hop chain begins) → the changed function's
					// sink (sink side). Intermediate hops aren't tracked here
					// because BFS over CalledBy edges doesn't record call-site
					// lines, so we emit source + sink with the file each is in.
					var taintPath []rules.TaintStep
					if len(node.TaintSig.SinkCalls) > 0 {
						sc := node.TaintSig.SinkCalls[0]
						reason = fmt.Sprintf(
							"calls %s which now has %s sink (%s)",
							node.Name, sc.MethodName, sc.SinkCategory,
						)
						// When the sink was lifted up the callgraph by
						// PropagateSignaturesAcrossCallgraph, the SinkRef's
						// Line points at the "(via X)" hop in node, not the
						// leaf — surface the leaf via OriginFile/OriginLine.
						sinkFile := node.FilePath
						sinkLine := sc.Line
						if sc.OriginFile != "" {
							sinkFile = sc.OriginFile
							sinkLine = sc.OriginLine
						}
						taintPath = []rules.TaintStep{
							{
								File:  callerNode.FilePath,
								Line:  callerNode.StartLine,
								Kind:  rules.TaintStepSource,
								Label: fmt.Sprintf("%s (transitively reaches %s)", callerNode.Name, node.Name),
							},
							{
								File:  sinkFile,
								Line:  sinkLine,
								Kind:  rules.TaintStepSink,
								Label: fmt.Sprintf("%s (in %s)", sc.MethodName, node.Name),
							},
						}
					}

					impacted = append(impacted, ImpactedCaller{
						CallerID:   callerID,
						CallerNode: callerNode,
						Reason:     reason,
						Severity:   sev,
						TaintPath:  taintPath,
					})

					nextQueue = append(nextQueue, callerID)
				}
			}
			queue = nextQueue
			depth++
		}
		if len(queue) > 0 && frontierHasUnvisitedCallers(cg, queue, visited) {
			// Diagnostics only: the impact BFS stopped at maxTraversalDepth
			// with unexplored callers — deeper impacted callers truncated.
			capHits.depth.Add(1)
		}
	}

	// Sort by severity (highest first).
	sort.Slice(impacted, func(i, j int) bool {
		return impacted[i].Severity > impacted[j].Severity
	})

	return impacted
}

// --- Internal helpers ---

// loadCallerFile reads a caller's source file from disk for cross-file
// interprocedural analysis. Results are cached in fileContents so each
// file is read at most once per PropagateInterproc invocation.
// Returns the content and true on success, or ("", false) if the file
// cannot be read (missing, too large, or unreadable).
func loadCallerFile(cg *CallGraph, filePath string, fileContents map[string]string) (string, bool) {
	// Check cache first (another caller in the same file may have loaded it).
	// Content already in the map is trusted fresh — it was either just written
	// (the hook's edited file) or loaded+validated earlier this walk.
	if content, ok := fileContents[filePath]; ok {
		return content, true
	}

	cap := maxCallerFileSize()

	info, err := os.Stat(filePath)
	if err != nil || info.IsDir() {
		return "", false
	}
	if info.Size() > cap {
		capHits.oversize.Add(1) // diagnostics only: caller file declined for exceeding the size cap
		return "", false
	}

	f, err := os.Open(filePath)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	// Bounded read: cap the allocation at the size limit even if the file
	// grew past `cap` between Stat and read (TOCTOU). Read one byte past the
	// cap so an over-cap file is detected and skipped rather than silently
	// truncated. Peak memory for this load therefore never exceeds the cap,
	// independent of how large the file actually is on disk.
	data, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return "", false
	}
	if int64(len(data)) > cap {
		// File grew past the cap after the Stat check — skip it rather than
		// feed a truncated body to the cross-file walker.
		capHits.oversize.Add(1) // diagnostics only
		return "", false
	}

	content := string(data)

	// Staleness gate: a persisted graph carries each function's StartLine/
	// EndLine from when it was last scanned. In hook mode the graph is adopted
	// from a prior `batou scan`, so if THIS file changed out-of-band since then
	// (e.g. a git pull moved lines), those spans now point at the wrong lines —
	// slicing the current content by them yields wrong-line findings and false
	// negatives. When the graph has a scan-time whole-file baseline hash for
	// this path and the current content no longer matches it, the file's nodes
	// are stale: skip the walk rather than analyze the wrong body. Only
	// demonstrably-changed files are skipped; a graph with no baseline for the
	// file (or a matching hash) proceeds exactly as before.
	if cg != nil && fileChangedSinceGraphBaseline(cg, filePath, content) {
		capHits.stale.Add(1) // diagnostics only: file skipped as changed since the graph baseline
		return "", false
	}

	fileContents[filePath] = content
	return content, true
}

// fileChangedSinceGraphBaseline reports whether filePath's current content
// differs from the whole-file hash recorded when the graph was built. Returns
// false (proceed) when there is no baseline for the file, so files the graph
// never recorded are never spuriously skipped.
//
// The baseline hash (FileTaintCache.ContentHash) is computed by the scanner
// over CRLF-normalized content (scanner.go normalizes "\r\n"->"\n" before
// hashing). loadCallerFile reads raw disk bytes, so we must apply the SAME
// normalization here — otherwise every file with CRLF line endings would hash
// differently and be spuriously treated as stale, dropping its cross-file
// walk on Windows-style repos.
func fileChangedSinceGraphBaseline(cg *CallGraph, filePath, content string) bool {
	cg.Mu.Lock()
	entry := cg.FileTaintCaches[filePath]
	cg.Mu.Unlock()
	if entry == nil {
		return false
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	return entry.ContentHash != FileContentHash(normalized)
}

// reJSONContentType matches Content-Type headers set to non-HTML types
// like application/json, text/plain, application/ndjson, etc. When a
// ResponseWriter sets one of these, w.Write() is NOT an XSS vector.
var reJSONContentType = regexp.MustCompile(
	`(?i)\.Header\(\)\.\s*Set\(\s*"Content-Type"\s*,\s*"(application/(json|ndjson|octet-stream|protobuf)|text/plain)`)

// hasNonHTMLContentType checks if the function body (as lines) sets a
// Content-Type header to a non-HTML type anywhere before or near the
// given line index. This suppresses false-positive XSS (CWE-79)
// findings on w.Write() in JSON API handlers.
func hasNonHTMLContentType(lines []string, sinkLineIdx int) bool {
	// Scan the entire function for Content-Type headers. JSON APIs
	// typically set the header once near the top of the handler.
	for i := 0; i < len(lines); i++ {
		if reJSONContentType.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// extractFuncBody extracts lines startLine..endLine (1-indexed, inclusive) from content.
func extractFuncBody(content string, startLine, endLine int) string {
	if startLine <= 0 || endLine <= 0 || endLine < startLine {
		return ""
	}

	lines := strings.Split(content, "\n")
	if startLine > len(lines) {
		return ""
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}

	return strings.Join(lines[startLine-1:endLine], "\n")
}

// identifySourceParams parses a function declaration line and identifies
// which parameters are taint sources based on their types.
func identifySourceParams(funcDecl string, sig *TaintSignature) {
	// Extract the parameter list from the function declaration.
	parenStart := strings.Index(funcDecl, "(")
	if parenStart < 0 {
		return
	}

	// Find the matching closing paren (handle nested parens for method receivers).
	depth := 0
	paramStart := -1
	paramEnd := -1
	parenCount := 0

	for i := parenStart; i < len(funcDecl); i++ {
		switch funcDecl[i] {
		case '(':
			depth++
			parenCount++
			if parenCount == 2 {
				paramStart = i
			}
			if parenCount == 1 && paramStart == -1 {
				paramStart = i
			}
		case ')':
			depth--
			if depth == 0 {
				paramEnd = i
				goto done
			}
		}
	}
done:
	if paramStart < 0 || paramEnd < 0 {
		return
	}

	paramStr := funcDecl[paramStart+1 : paramEnd]
	params := strings.Split(paramStr, ",")

	for idx, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}

		// context.Context parameters are plumbing — they carry
		// cancellation / deadline metadata, never user-controlled
		// data. Skip them so cross-file flows like
		// `handler(ctx, …) → svc(ctx, …) → db.Exec(ctx, "…")` don't
		// surface "ctx flows into a SQL sink" as a finding.
		if isContextParamType(param) {
			continue
		}

		for re, srcCat := range sourceParamPatterns {
			if re.MatchString(param) {
				sig.SourceParams[idx] = srcCat
				break
			}
		}
	}
}

// findParamFlowToSink attempts to determine which source parameter
// flows to a sink call on the given line by tracing variable assignments
// backward through the function body.
// findParamFlowToSinkFiltered is findParamFlowToSink restricted to the
// dangerous arg positions of the sink call. dangerousArgs is the list
// of 0-indexed positions in the SINK CALL ITSELF that actually carry
// user-controllable data (e.g. http.Redirect's URL is at position 2;
// `r` at position 1 is plumbing). When dangerousArgs is nil we fall
// back to the legacy "any arg position" behaviour.
//
// Returns the enclosing function's parameter index that flows into one
// of the dangerous positions of the sink, or -1 if no flow is found.
func findParamFlowToSinkFiltered(lines []string, sinkLineIdx int, sig *TaintSignature, dangerousArgs []int) int {
	if len(dangerousArgs) == 0 {
		return findParamFlowToSink(lines, sinkLineIdx, sig)
	}
	if len(sig.SourceParams) == 0 || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return -1
	}

	sinkLine := lines[sinkLineIdx]
	parenIdx := strings.Index(sinkLine, "(")
	if parenIdx < 0 {
		return -1
	}
	args := extractArgList(sinkLine[parenIdx:])
	if len(args) == 0 {
		return -1
	}

	wanted := make(map[int]bool, len(dangerousArgs))
	for _, i := range dangerousArgs {
		wanted[i] = true
	}

	for paramIdx := range sig.SourceParams {
		paramName := findParamName(lines, paramIdx)
		if paramName == "" {
			continue
		}
		for callArgIdx, arg := range args {
			if !wanted[callArgIdx] {
				continue
			}
			arg = strings.TrimSpace(arg)
			// Direct: the dangerous position is the param itself.
			if arg == paramName {
				return paramIdx
			}
			// Derived: the dangerous arg expression mentions the
			// param as a token (e.g. `url.QueryEscape(p)`) — even
			// though escaped, the lexical reference is enough to
			// say "this param reaches the position". Use token
			// matching so 1-char params like `r` don't match every
			// arg that happens to contain the letter `r`.
			if containsToken(arg, paramName) {
				return paramIdx
			}
		}
	}
	return -1
}

func findParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
	if len(sig.SourceParams) == 0 {
		return -1
	}

	sinkLine := lines[sinkLineIdx]

	// Extract argument expressions from the sink call.
	parenIdx := strings.Index(sinkLine, "(")
	if parenIdx < 0 {
		return -1
	}

	argsStr := sinkLine[parenIdx:]
	// Simplified: look backward for variable assignments that trace to params.
	// For each source param, check if any variable derived from it appears in
	// the sink args. We match identifiers as TOKENS (\b...\b) — never bare
	// substrings — so 1-char param names like `r` don't match every line that
	// happens to contain the letter "r" (e.g. "Printf", "forwarding").
	for paramIdx := range sig.SourceParams {
		// Search backward for assignments from this param.
		// This is a lightweight heuristic — full tracking is done by taint.Analyze.
		paramName := findParamName(lines, paramIdx)
		if paramName == "" {
			continue
		}
		if containsToken(argsStr, paramName) {
			return paramIdx
		}

		// Also check if any variable assigned from this param appears in the sink.
		for i := 0; i < sinkLineIdx; i++ {
			trimmed := strings.TrimSpace(lines[i])
			if !containsToken(trimmed, paramName) {
				continue
			}
			// This line references the param. Extract the LHS variable.
			if eqIdx := strings.Index(trimmed, ":="); eqIdx > 0 {
				lhs := strings.TrimSpace(trimmed[:eqIdx])
				if containsToken(argsStr, lhs) {
					return paramIdx
				}
			} else if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 {
				before := trimmed[eqIdx-1]
				if before != '!' && before != '<' && before != '>' && before != '=' {
					lhs := strings.TrimSpace(trimmed[:eqIdx])
					if containsToken(argsStr, lhs) {
						return paramIdx
					}
				}
			}
		}
	}

	return -1
}

// findParamName extracts the Nth parameter name from the function declaration
// (assumed to be the first line).
func findParamName(lines []string, paramIdx int) string {
	if len(lines) == 0 {
		return ""
	}

	funcDecl := lines[0]
	parenStart := strings.Index(funcDecl, "(")
	if parenStart < 0 {
		return ""
	}

	// For methods, skip the receiver by finding the second '('.
	rest := funcDecl[parenStart+1:]
	closeIdx := strings.Index(rest, ")")
	if closeIdx < 0 {
		return ""
	}

	// Check if there's another param list (method receiver was first).
	afterClose := rest[closeIdx+1:]
	nextParen := strings.Index(afterClose, "(")
	if nextParen >= 0 {
		// This was the receiver; use the next param list.
		rest = afterClose[nextParen+1:]
		closeIdx = strings.Index(rest, ")")
		if closeIdx < 0 {
			return ""
		}
	}

	paramStr := rest[:closeIdx]
	params := strings.Split(paramStr, ",")

	if paramIdx >= len(params) {
		return ""
	}

	param := strings.TrimSpace(params[paramIdx])
	if param == "" {
		return ""
	}

	// Extract just the name (before the type).
	parts := strings.Fields(param)
	if len(parts) == 0 {
		return ""
	}

	return parts[0]
}

// sqlPlaceholderRe matches positional/numbered SQL bind placeholders —
// `?` (MySQL/Go database-sql/JDBC) and `$1..$9` (PostgreSQL) — anchored
// so a literal `?`/`$` inside non-binding text doesn't match. A bound
// placeholder is preceded by `=`, `,`, `(`, or whitespace and (for `?`)
// followed by a clause/string separator — a comma, close paren, whitespace,
// quote, backtick, or end-of-line. This deliberately covers the common
// spaced form `WHERE id = ?` (which the prior substring-marker list missed,
// because the `?` there is followed by a quote/backtick, not `,`/`)`/`\n`)
// while still rejecting an interpolating `%s` (NOT a bound placeholder in
// Go/Java string formatting — that remains a SQL-injection surface).
var sqlPlaceholderRe = regexp.MustCompile(
	`[=,(\s]\?(?:[,)\s'` + "`" + `"]|$)` + // ? bind placeholder, separator-bounded
		`|[=,(\s]\$[1-9]`, // $1..$9 PostgreSQL positional placeholder
)

// maxSQLCallContinuationLines bounds how many continuation lines past the
// sink-call line sqlCallIsParameterized inspects for a placeholder. A SQL
// query string + its bind args almost always close within a handful of
// lines; the bound keeps a runaway/unterminated call from scanning the
// whole function body.
const maxSQLCallContinuationLines = 16

// sqlCallIsParameterized reports whether the SQL-sink call that STARTS at
// lines[idx] uses placeholders (? or $N) to bind its values — the signature
// of a properly parameterized query. Such calls bind values rather than
// interpolating them, so a tainted arg flowing into the call (e.g. across a
// function/file boundary) isn't a real SQL-injection surface.
//
// It MUST stay consistent with the single-file recognition in
// taint.isParameterizedQuery (taint/tracker.go) for the `?`/`$N` forms, so a
// parameterized query is suppressed identically whether the sink is reached
// in-function (single-file) or lifted across a boundary (interproc/cross-file).
// It intentionally does NOT treat `%s` as a bound placeholder: in Go/Java
// `fmt.Sprintf("...%s", v)` is string interpolation, a genuine injection
// surface (see sqlPlaceholderRe).
//
// Unlike the single-file path (which sees the call's parsed argument
// expressions), the interproc signature path only has body lines — so it
// checks the call line AND its continuation lines up to the call's closing
// parenthesis. This matters for multi-line SQL: a query whose placeholder
// lives on a later line, e.g.
//
//	row := a.db.QueryRow(`
//	    SELECT ... FROM t
//	    WHERE id = ?`, id)
//
// The sink pattern matches on the `a.db.QueryRow(` line (idx), but the `?`
// placeholder is several lines down. Checking only lines[idx] misses it,
// leaving the parameterized sink in the signature so the cross-file/interproc
// walk lifts it into a spurious CWE-89 — the exact false positive this guards
// against. The single-file taint path doesn't have this problem because it
// sees the call's parsed argument expressions; the interproc signature path
// only has body lines, so we reconstruct the call span here.
//
// Recall guard: a query that BOTH binds a placeholder AND concatenates a
// fragment into the SQL text (e.g. `"... WHERE " + col + " = ?"`) is NOT
// safe — the concatenated fragment is a genuine injection surface. Such a
// mixed call is reported as parameterized by the single-file check (any
// placeholder present → true), but on the cross-file path we deliberately do
// NOT suppress it, so the genuine concat injection still surfaces. This makes
// the interproc check strictly recall-safe relative to the old behavior.
func sqlCallIsParameterized(lines []string, idx int) bool {
	if idx < 0 || idx >= len(lines) {
		return false
	}
	// Gather the call span: lines[idx] through the line where the call's
	// parentheses balance (or the continuation bound), so both the
	// placeholder check and the concat guard see the whole call.
	depth := strings.Count(lines[idx], "(") - strings.Count(lines[idx], ")")
	end := idx
	limit := idx + maxSQLCallContinuationLines
	if limit >= len(lines) {
		limit = len(lines) - 1
	}
	for j := idx + 1; j <= limit; j++ {
		end = j
		if depth <= 0 {
			break
		}
		depth += strings.Count(lines[j], "(") - strings.Count(lines[j], ")")
	}

	hasPlaceholder := false
	for j := idx; j <= end; j++ {
		if sqlPlaceholderRe.MatchString(lines[j]) {
			hasPlaceholder = true
			break
		}
	}
	if !hasPlaceholder {
		return false
	}
	// A placeholder is present. If the call ALSO interpolates a fragment via
	// string concatenation, treat it as NOT-parameterized (still a SQLi
	// surface) so the cross-file finding is not over-suppressed.
	for j := idx; j <= end; j++ {
		if sqlConcatFragmentRe.MatchString(lines[j]) {
			return false
		}
	}
	return true
}

// sqlConcatFragmentRe detects a string-concatenation operator joining a
// fragment into a SQL string — a `+` immediately adjacent to a quote or
// backtick: `"..." +` (closing-quote then +) or `+ "..."` (+ then opening
// quote). This is the reliable signature of building a query by splicing a
// variable between string literals (`"... WHERE " + col + " = ?"`). It is
// deliberately anchored on the quote/backtick so arithmetic inside a bind
// arg (`a+b`) or a `+` elsewhere does NOT match — matching there would
// wrongly un-suppress a genuinely parameterized query. Used as a recall
// guard in sqlCallIsParameterized: a query that concatenates a fragment is
// not safe even if it also binds a placeholder.
var sqlConcatFragmentRe = regexp.MustCompile(
	"[\"'`]\\s*\\+" + // "..." +   (closing quote/backtick then concat)
		"|\\+\\s*[\"'`]", // + "..."  (concat then opening quote/backtick)
)

// isContextParamType reports whether a Go parameter's type is
// context.Context (or a pointer to it). Such parameters are plumbing —
// they carry cancellation / deadline metadata, not user-controlled
// data — and shouldn't be classified as taint sources even when a
// caller passes them into a sink-bearing function. Removing them from
// the source-arg pool cuts a large class of interproc false positives
// like "ctx flows into db.Exec".
func isContextParamType(typeName string) bool {
	typeName = strings.TrimSpace(typeName)
	typeName = strings.TrimPrefix(typeName, "*")
	return typeName == "context.Context" || typeName == "Context"
}

// isSanitizerByName reports whether the callee's function name suggests
// it IS the sanitizer for the given sink category. A function named
// EscapeControlHTML, SanitizeHTML, FilterAttr, etc. that itself writes
// into the corresponding sink (template / html / header / log / etc.)
// is implementing the sanitization step — flagging it would be flagging
// the cure.
//
// Match prefixes (case-insensitive) per sink category:
//
//	SnkHTMLOutput / SnkTemplate: Escape, Sanitize, Filter, Encode, Clean
//	SnkLog / SnkHeader:          Escape, Sanitize, Strip, Clean
//	SnkCommand:                  Escape, Quote, Shell
//	SnkSQLQuery:                 Quote, Escape
//	SnkRedirect / SnkURLFetch:   ValidateURL, NormalizeURL, EscapeURL
//	SnkXPath / SnkLDAP:          Escape, Sanitize
//
// The name match is a heuristic; sanitizers that don't follow a verb-prefix
// naming convention will still fire (recover by catalog sanitizer entries).
func isSanitizerByName(fnName string, sinkCat taint.SinkCategory) bool {
	if fnName == "" {
		return false
	}
	lower := strings.ToLower(fnName)

	// Generic sanitizer-verb prefixes that apply to most string sinks.
	generic := []string{
		"escape", "sanitize", "filter", "encode", "clean",
		"normalize", "quote", "strip",
	}
	for _, p := range generic {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	// Method-name suffix variant: ToSanitized, MarkSafeHTML, ForcePlain, …
	suffixes := []string{"sanitize", "sanitized", "escape", "escaped", "safe", "tosafehtml"}
	for _, s := range suffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// isSanitizerByCalleeName is the sink-category-agnostic variant of
// isSanitizerByName, used on the source-propagation path (Path B) where
// we don't have a specific sink category at the point of suppression —
// just the function name. Any function whose name starts with a
// sanitizer verb is treated as producing safe output.
func isSanitizerByCalleeName(fnName string) bool {
	return isSanitizerByName(fnName, "")
}

// isPathSanitized checks if a param→sink path has a sanitizer.
func isPathSanitized(paths []SanitizedPath, paramIdx int, sinkCat taint.SinkCategory) bool {
	for _, p := range paths {
		if p.ParamIndex == paramIdx && p.SinkCategory == sinkCat {
			return true
		}
	}
	return false
}

// appendUniqueCat appends a SourceCategory to a slice if not already present.
func appendUniqueCat(cats []taint.SourceCategory, cat taint.SourceCategory) []taint.SourceCategory {
	for _, c := range cats {
		if c == cat {
			return cats
		}
	}
	return append(cats, cat)
}

// extractBaseName returns the function name without package or receiver prefix.
// E.g. "pkg.Receiver.Method" → "Method", "FuncName" → "FuncName".
func extractBaseName(name string) string {
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// bestSeverityFromSinks returns the highest severity among a set of sink refs.
func bestSeverityFromSinks(sinks []SinkRef) rules.Severity {
	best := rules.High // Interprocedural findings are at least High.
	for _, sink := range sinks {
		if sev, ok := severityForSinkCategory[sink.SinkCategory]; ok && sev > best {
			best = sev
		}
	}
	return best
}

// checkCallerPassesTaintToCallee checks Path A: caller passes tainted data
// as arguments to the callee, and the callee has sinks for those params.
func checkCallerPassesTaintToCallee(
	callerNode *FuncNode,
	calleeNode *FuncNode,
	calleeSig *TaintSignature,
	callLine string,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
	sanGate *callerSanitizerGate,
) []rules.Finding {
	var findings []rules.Finding

	if len(calleeSig.SinkCalls) == 0 {
		return nil
	}

	// Extract the arguments the caller passes to the callee.
	calleeBaseName := extractBaseName(calleeNode.Name)
	callIdx := strings.Index(callLine, calleeBaseName)
	if callIdx < 0 {
		return nil
	}

	argsStart := strings.Index(callLine[callIdx:], "(")
	if argsStart < 0 {
		return nil
	}

	argStr := callLine[callIdx+argsStart:]
	args := extractArgList(argStr)

	// Check each argument: is it tainted in the caller's context?
	for argIdx, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		// Check if this argument position connects to a sink in the callee.
		// ArgFromParam == argIdx is a precise positional match. ArgFromParam
		// == -1 is a wildcard fallback used only when the callee has no
		// SourceParams (e.g. ExecuteCmd(cmd string), the canonical
		// cross-function command-injection case where findParamFlowToSink
		// was a no-op and we fall back to "any caller arg may flow"). When
		// the callee HAS SourceParams, a -1 ArgFromParam means
		// findParamFlowToSink ran and found NO connection from any
		// SourceParam to this sink — treat as not reached, to avoid
		// flagging every unrelated log.Printf in a handler that happens to
		// take an *http.Request.
		//
		// PR-FF: prefer a precise positional match over the -1 wildcard.
		// We do two passes: first looking for sink.ArgFromParam == argIdx,
		// then falling back to -1 (only when callee has no sources). This
		// guarantees that when caller(a, b) calls callee with sinks at both
		// arg positions, each tainted caller arg pairs with its OWN sink
		// and we don't accidentally fire a -1 sink that "happens to match"
		// the same arg.
		calleeHasSources := len(calleeSig.SourceParams) > 0
		var matchedSink *SinkRef
		// First pass: precise positional match (sink.ArgFromParam == argIdx).
		for i := range calleeSig.SinkCalls {
			sink := &calleeSig.SinkCalls[i]
			if sink.ArgFromParam != argIdx {
				continue
			}
			if isPathSanitized(calleeSig.SanitizedPaths, argIdx, sink.SinkCategory) {
				continue
			}
			matchedSink = sink
			break
		}
		// Second pass: -1 wildcard fallback. Only used when no precise match
		// was found AND the callee has no SourceParams (PR-P scope: keep the
		// ExecuteCmd(cmd string) command-injection case working).
		if matchedSink == nil && !calleeHasSources {
			for i := range calleeSig.SinkCalls {
				sink := &calleeSig.SinkCalls[i]
				if sink.ArgFromParam != -1 {
					continue
				}
				if isPathSanitized(calleeSig.SanitizedPaths, argIdx, sink.SinkCategory) {
					continue
				}
				matchedSink = sink
				break
			}
		}
		if matchedSink == nil {
			continue
		}

		// Check if the argument is tainted in the caller's context.
		// Pass the caller's TaintSig so the check can trust its
		// already-computed SourceParams (e.g. when the caller has a
		// *http.Request parameter, passing that parameter is tainted
		// by definition — no need to find a body-level regex match).
		if !isArgTaintedInCallerWithSig(arg, callerLines, callLineIdx, &callerNode.TaintSig) {
			continue
		}

		// Suppress XSS (HTML_OUTPUT) findings when the caller or callee
		// sets a non-HTML Content-Type (e.g., application/json).
		if matchedSink.SinkCategory == taint.SnkHTMLOutput && hasNonHTMLContentType(callerLines, callLineIdx) {
			continue
		}

		// Suppress when the callee IS the sanitizer. A function whose name
		// is Escape* / Sanitize* / Filter* / Encode* / Clean* / Quote*
		// and that hands its input to a template/HTML/log sink internally
		// is the sanitization step, not the vulnerability. The classic
		// false positive: EscapeControlHTML(html template.HTML) wraps its
		// input as template.HTML on return — the wrap fires the TEMPLATE
		// sink even though the function's whole job is to sanitize.
		if isSanitizerByName(calleeNode.Name, matchedSink.SinkCategory) {
			continue
		}

		// Catalog-backed caller-side sanitizer gate: the arg's base
		// variable was assigned from a catalog sanitizer neutralising
		// this sink category on an earlier line, with no plain rebind
		// since (last-assignment-wins). Purely suppressive; fails open
		// on parse failure, complex arg expressions, and Go callers
		// (tsflow has no Go config).
		if sanGate.argSanitized(arg, callLineNum, matchedSink.SinkCategory) {
			continue
		}

		sev := severityForSinkCategory[matchedSink.SinkCategory]
		if sev < rules.High {
			sev = rules.High
		}

		cwe := cweForSinkCategory[matchedSink.SinkCategory]
		owasp := owaspForSinkCategory[matchedSink.SinkCategory]

		// Cross-file data-flow path: tainted arg in the caller's file →
		// the call site in the caller's file → the sink inside the callee's
		// file. We have a precise line for the caller's call site; the
		// sink's line comes from the callee's signature; the source line is
		// the call site (the arg expression lives there).
		sinkLabel := matchedSink.MethodName
		if sinkLabel == "" {
			sinkLabel = string(matchedSink.SinkCategory)
		}
		// PR-FF: include the matched callee parameter index in the
		// propagation step so triagers see which positional param of the
		// callee receives the tainted arg. When the match was the -1
		// wildcard fallback (callee has no SourceParams), we don't know a
		// specific param index and fall back to the generic phrasing.
		var propLabel string
		if matchedSink.ArgFromParam >= 0 {
			propLabel = fmt.Sprintf(
				"caller's %s flows to %s as param %d",
				arg, calleeBaseName, matchedSink.ArgFromParam,
			)
		} else {
			propLabel = fmt.Sprintf("passed to %s(...)", calleeBaseName)
		}
		taintPath := []rules.TaintStep{
			{
				File:  callerNode.FilePath,
				Line:  callLineNum,
				Kind:  rules.TaintStepSource,
				Label: fmt.Sprintf("tainted argument %q (arg %d)", arg, argIdx),
			},
			{
				File:  callerNode.FilePath,
				Line:  callLineNum,
				Kind:  rules.TaintStepPropagation,
				Label: propLabel,
			},
		}
		// If the matched sink was lifted up the call graph by PR-H's
		// signature propagation, the sink's true home is OriginFile/
		// OriginLine — matchedSink.Line is just the "(via X)" hop in the
		// inheriting callee. Append the propagation hop + the leaf-sink
		// step so the taint path preserves the chain end-to-end. The
		// OriginFile may legitimately equal calleeNode.FilePath when the
		// leaf and the via-hop happen to live in the same file (G calls
		// H, both in pkg/x.go); honour the lift either way.
		if matchedSink.OriginFile != "" {
			taintPath = append(taintPath,
				rules.TaintStep{
					File:  calleeNode.FilePath,
					Line:  matchedSink.Line,
					Kind:  rules.TaintStepPropagation,
					Label: fmt.Sprintf("forwarded by %s (inherited sink)", calleeNode.Name),
				},
				rules.TaintStep{
					File:  matchedSink.OriginFile,
					Line:  matchedSink.OriginLine,
					Kind:  rules.TaintStepSink,
					Label: fmt.Sprintf("%s (leaf sink lifted via %s)", sinkLabel, calleeNode.Name),
				},
			)
		} else {
			taintPath = append(taintPath, rules.TaintStep{
				File:  calleeNode.FilePath,
				Line:  matchedSink.Line,
				Kind:  rules.TaintStepSink,
				Label: fmt.Sprintf("%s (in %s)", sinkLabel, calleeNode.Name),
			})
		}

		finding := rules.Finding{
			RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(matchedSink.SinkCategory))),
			Severity:      sev,
			SeverityLabel: sev.String(),
			Title: fmt.Sprintf(
				"Interprocedural taint: user input flows through %s() to %s",
				calleeNode.Name, matchedSink.MethodName,
			),
			Description: fmt.Sprintf(
				"Tainted data from %s() (%s:%d) is passed as argument %d to %s(), "+
					"which forwards it to %s without sanitization. "+
					"This creates a cross-function %s vulnerability.",
				callerNode.Name, callerNode.FilePath, callLineNum,
				argIdx, calleeNode.Name,
				matchedSink.MethodName, matchedSink.SinkCategory,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: callLineNum,
			MatchedText: fmt.Sprintf(
				"%s (arg %d) -> %s() -> %s %s",
				arg, argIdx, calleeNode.Name,
				matchedSink.MethodName, formatSinkLocation(*matchedSink, calleeNode.FilePath),
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize '%s' before passing it to %s(), or add sanitization inside %s() before the %s call.",
				arg, calleeNode.Name, calleeNode.Name, matchedSink.MethodName,
			),
			CWEID:           cwe,
			OWASPCategory:   owasp,
			Confidence:      "high",
			ConfidenceScore: 0.8,
			// Interprocedural Path A: the caller-side source is unknown at this
			// layer (we just know the argument is tainted upstream). Mark it
			// generically as "external" so triagers can still bucket it.
			SourceCategory: string(taint.SrcExternal),
			SinkCategory:   string(matchedSink.SinkCategory),
			Tags:           []string{"interprocedural", "taint-analysis", "cross-function", string(matchedSink.SinkCategory)},
		}

		findings = append(findings, finding)
	}

	return findings
}

// checkCallerUsesTaintedReturn checks Path B: callee returns tainted data,
// and the caller passes it to a sink without sanitization.
func checkCallerUsesTaintedReturn(
	callerNode *FuncNode,
	calleeNode *FuncNode,
	calleeSig *TaintSignature,
	callLine string,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
	sanGate *callerSanitizerGate,
) []rules.Finding {
	var findings []rules.Finding

	// A callee qualifies for Path B when it has EITHER whole-return taint
	// (legacy, index-keyed) OR field-sensitive tainted return paths (CH3).
	// The latter alone — a `return T{tainted, clean}` partial-struct return
	// — is a valid driver; the field gate below restricts the caller's sink
	// to the EXACT tainted field path so a clean-sibling read stays silent.
	if len(calleeSig.TaintedReturns) == 0 && len(calleeSig.TaintedReturnPaths) == 0 {
		return nil
	}

	// If the callee's name looks like a sanitizer (Escape*, Sanitize*,
	// Filter*, etc.) its return value is sanitized OUTPUT, not tainted.
	// Apply the same name-based suppression we use on Path A.
	if isSanitizerByCalleeName(calleeNode.Name) {
		return nil
	}
	// If the CALLER's name is a sanitizer, the surrounding function IS
	// the sanitization step (e.g. EscapeControlHTML calls
	// EscapeControlReader inside). Don't flag the wrap-on-return as a
	// vulnerability — the function exists to produce safe output.
	if isSanitizerByCalleeName(callerNode.Name) {
		return nil
	}

	// Find what variable receives the callee's return value.
	trimmed := strings.TrimSpace(callLine)
	var returnVar string

	if idx := strings.Index(trimmed, ":="); idx > 0 {
		lhs := strings.TrimSpace(trimmed[:idx])
		// Handle multi-return: take the first variable.
		if commaIdx := strings.Index(lhs, ","); commaIdx > 0 {
			returnVar = strings.TrimSpace(lhs[:commaIdx])
		} else {
			returnVar = lhs
		}
	} else if idx := strings.Index(trimmed, "="); idx > 0 {
		before := trimmed[idx-1]
		if before != '!' && before != '<' && before != '>' && before != '=' {
			if idx+1 >= len(trimmed) || trimmed[idx+1] != '=' {
				lhs := strings.TrimSpace(trimmed[:idx])
				if commaIdx := strings.Index(lhs, ","); commaIdx > 0 {
					returnVar = strings.TrimSpace(lhs[:commaIdx])
				} else {
					returnVar = lhs
				}
			}
		}
	}

	if returnVar == "" {
		return nil
	}

	// Field-sensitive return mode (CH3): the callee taints only specific
	// return-value fields (`return T{Name: src, Page: "static"}`). The
	// caller's sink must read one of those EXACT field paths off the return
	// variable — `db.Query(res.Name)` fires, `http.ServeFile(.., res.Page)`
	// stays silent. Whole-return callees (TaintedReturnPaths empty) skip the
	// gate and keep the legacy whole-variable behaviour.
	fieldSensitiveReturn := len(calleeSig.TaintedReturnPaths) > 0

	// Search forward from the call site: does the return variable reach a sink?
	for i := callLineIdx + 1; i < len(callerLines); i++ {
		line := callerLines[i]

		for _, sp := range sinkCallPatterns {
			if !sp.pattern.MatchString(line) {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}

			// Field-sensitive return gate (CH3): when the callee taints only
			// specific return fields, the sink line must read a field path
			// off returnVar that matches a tainted return path. We extract
			// the access path the sink reads off returnVar
			// (`db.Query(res.Name)` → "Name"), compose it with return index 0
			// ("0.Name"), bound it, and require a tainted-prefix hit. A bare
			// `sink(res)` whole-object read only fires when the callee ALSO
			// has whole-return taint — preserving legacy behaviour for
			// non-struct returns.
			if fieldSensitiveReturn {
				retFieldPath := jsSinkFieldPathForParam(line, returnVar)
				if retFieldPath == "" {
					// Whole-object read of returnVar: only fire if the callee
					// has whole-return taint too. A partial-struct callee
					// taints no whole value, so we stay silent.
					if len(calleeSig.TaintedReturns) == 0 {
						continue
					}
				} else {
					composed := boundReturnPath("0", retFieldPath)
					if !returnPathTainted(composed, calleeSig.TaintedReturnPaths) {
						continue
					}
				}
			}

			// Suppress XSS (HTML_OUTPUT) findings when the function
			// sets a non-HTML Content-Type (e.g., application/json).
			// Writing to ResponseWriter with JSON Content-Type is not XSS.
			if sp.category == taint.SnkHTMLOutput && hasNonHTMLContentType(callerLines, i) {
				continue
			}

			// Check if the return variable was sanitized between the call and the sink.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				for _, san := range sanitizerPatterns {
					if san.pattern.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
						if san.category == sp.category {
							sanitized = true
							break
						}
					}
				}
				if sanitized {
					break
				}
			}
			if sanitized {
				continue
			}
			// Catalog-backed sanitizer gate: returnVar was rebound from a
			// catalog sanitizer neutralising this category before the sink
			// line (last-assignment-wins; the tainted call assignment
			// itself is a plain fact that revokes any earlier sanitize).
			// Inert for Go callers (tsflow has no Go config).
			if sanGate.argSanitized(returnVar, callerNode.StartLine+i, sp.category) {
				continue
			}

			sinkLineNum := callerNode.StartLine + i
			sev := severityForSinkCategory[sp.category]
			if sev < rules.High {
				sev = rules.High
			}

			cwe := cweForSinkCategory[sp.category]
			owasp := owaspForSinkCategory[sp.category]

			// Determine the source category from the tainted return.
			// srcCatLabel is the human-readable text used in the data-flow
			// label ("tainted" when the callee has no specific category);
			// srcCatJSON is the machine label exposed on Finding.SourceCategory
			// — must be a real taint.SourceCategory value, so "external" is
			// the fallback when no specific category is available.
			srcCatLabel := "tainted"
			srcCatJSON := string(taint.SrcExternal)
			for _, cats := range calleeSig.TaintedReturns {
				if len(cats) > 0 {
					srcCatLabel = string(cats[0])
					srcCatJSON = string(cats[0])
					break
				}
			}
			// Field-sensitive-only callee: the category lives on the tainted
			// return PATH, not the index-keyed whole-return map.
			if srcCatJSON == string(taint.SrcExternal) {
				for _, cats := range calleeSig.TaintedReturnPaths {
					if len(cats) > 0 {
						srcCatLabel = string(cats[0])
						srcCatJSON = string(cats[0])
						break
					}
				}
			}

			// Cross-file data-flow path: the callee returns tainted data
			// (its file) → caller's call site receives it into returnVar
			// (caller's file) → caller's sink (caller's file). We don't
			// have a precise return line inside the callee, so the source
			// step points at the callee's declaration line and the label
			// makes that explicit.
			calleeBaseName := extractBaseName(calleeNode.Name)
			taintPath := []rules.TaintStep{
				{
					File:  calleeNode.FilePath,
					Line:  calleeNode.StartLine,
					Kind:  rules.TaintStepSource,
					Label: fmt.Sprintf("%s() returns %s data", calleeNode.Name, srcCatLabel),
				},
				{
					File:  callerNode.FilePath,
					Line:  callLineNum,
					Kind:  rules.TaintStepPropagation,
					Label: fmt.Sprintf("result of %s(...) assigned to %s", calleeBaseName, returnVar),
				},
				{
					File:  callerNode.FilePath,
					Line:  sinkLineNum,
					Kind:  rules.TaintStepSink,
					Label: sp.method,
				},
			}

			finding := rules.Finding{
				RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(sp.category))),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title: fmt.Sprintf(
					"Interprocedural taint: %s data from %s() reaches %s",
					srcCatLabel, calleeNode.Name, sp.method,
				),
				Description: fmt.Sprintf(
					"Return value of %s() (called at %s:%d) carries %s taint. "+
						"The caller %s() stores it in '%s' and passes it to %s at line %d "+
						"without sanitization, creating a cross-function %s vulnerability.",
					calleeNode.Name, callerNode.FilePath, callLineNum,
					srcCatLabel,
					callerNode.Name, returnVar, sp.method, sinkLineNum,
					sp.category,
				),
				FilePath:   callerNode.FilePath,
				LineNumber: sinkLineNum,
				MatchedText: fmt.Sprintf(
					"%s() -> %s -> %s (line %d)",
					calleeNode.Name, returnVar, sp.method, sinkLineNum,
				),
				TaintPath: taintPath,
				Suggestion: fmt.Sprintf(
					"Sanitize '%s' (returned by %s()) before passing it to %s.",
					returnVar, calleeNode.Name, sp.method,
				),
				CWEID:           cwe,
				OWASPCategory:   owasp,
				Confidence:      "high",
				ConfidenceScore: 0.8,
				// Interprocedural Path B: callee returns tainted data; the
				// source category is the first tainted return cat. When no
				// specific category is available the fallback is "external".
				SourceCategory: srcCatJSON,
				SinkCategory:   string(sp.category),
				Tags:           []string{"interprocedural", "taint-analysis", "cross-function", "return-taint", string(sp.category)},
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// isArgTaintedInCaller checks if an argument expression is tainted in the
// caller's context by looking backward for taint sources.
func isArgTaintedInCaller(argExpr string, callerLines []string, callLineIdx int) bool {
	return isArgTaintedInCallerWithSig(argExpr, callerLines, callLineIdx, nil)
}

// isArgTaintedInCallerWithSig is isArgTaintedInCaller with the caller's
// already-computed TaintSig in hand. Trusting SourceParams skips a lot
// of the body-level regex work: when a caller declares `func H(req
// *http.Request)` and passes `req` to a downstream sink, we know `req`
// is tainted without re-finding a directSourcePattern match in the
// body. callerSig may be nil — the function falls back to the original
// regex-only behaviour in that case.
func isArgTaintedInCallerWithSig(argExpr string, callerLines []string, callLineIdx int, callerSig *TaintSignature) bool {
	argTrim := strings.TrimSpace(argExpr)

	// Cheap shortcut: the caller's TaintSig already knows which of its
	// parameters are source-typed. If the argument is one of those
	// parameters (or a field/method access ON one of them), it's
	// tainted. This is what fires cross-file path A on functions like
	// `func handle(req *http.Request) { ... store(req) }` where the
	// per-file interproc pass marked `req` as SrcUserInput in
	// callerSig.SourceParams.
	if callerSig != nil && len(callerSig.SourceParams) > 0 && len(callerSig.Params) > 0 {
		// Root the expression: strip ".field" / "[idx]" suffixes so
		// `req.Body` resolves back to `req`.
		root := argTrim
		if dotIdx := strings.Index(root, "."); dotIdx > 0 {
			root = root[:dotIdx]
		}
		if bracketIdx := strings.Index(root, "["); bracketIdx > 0 {
			root = root[:bracketIdx]
		}
		root = strings.TrimSpace(root)
		for paramIdx, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[paramIdx]; isSource {
				return true
			}
		}
	}

	// Direct source patterns in the argument itself.
	for re := range sourceParamPatterns {
		if re.MatchString(argExpr) {
			return true
		}
	}

	// Common taint source patterns directly in the argument.
	for _, re := range directSourcePatterns {
		if re.MatchString(argExpr) {
			return true
		}
	}

	// Trace the variable backward: look for assignments from taint sources.
	argVar := argTrim
	if dotIdx := strings.Index(argVar, "."); dotIdx > 0 {
		argVar = argVar[:dotIdx]
	}
	if bracketIdx := strings.Index(argVar, "["); bracketIdx > 0 {
		argVar = argVar[:bracketIdx]
	}

	for i := callLineIdx - 1; i >= 0; i-- {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)

		// Skip the function's own declaration line — it usually shows
		// up as callerLines[0] (extractFuncBody includes the decl line
		// for source attribution). The decl mentions parameter and
		// return types like `*http.Request` / `*httplib.Request`,
		// which spuriously match `\bRequest\b` and other source
		// patterns. SourceParam classification (identifySourceParams)
		// already handled real sources declared in the decl.
		if isFuncDeclLine(trimmed) {
			continue
		}

		// Check if this line assigns to our variable. Match argVar
		// as a token so a short name like `w` doesn't match every
		// line containing the letter "w".
		if !containsToken(trimmed, argVar) {
			continue
		}

		// Check if the RHS contains a taint source.
		for _, re := range directSourcePatterns {
			if re.MatchString(trimmed) {
				return true
			}
		}
	}

	return false
}

// containsToken reports whether s contains name as a whole word, i.e.
// `\bname\b` at a Go-identifier boundary. Used to match identifier names
// (param names, variables) against arbitrary source lines without
// substring-matching short names like `r` or `w` into unrelated tokens
// (e.g. "Printf", "forwarding", "url"). Returns false on empty inputs.
//
// The check stays cheap: short-circuit on `strings.Contains` first, then
// reuse a cached regex (one per name) so the regex backtracker isn't
// invoked for lines that don't contain the substring at all.
func containsToken(s, name string) bool {
	if name == "" || s == "" {
		return false
	}
	if !strings.Contains(s, name) {
		return false
	}
	return tokenRegexFor(name).MatchString(s)
}

// tokenAfter reports whether a whole-word occurrence of name in s begins
// at a byte offset >= minPos (word-boundary semantics matching
// containsToken). Used to confirm a same-line sink consumes a returned
// variable that ALSO appears as the assignment LHS before the call —
// `const n = getName(req); cp.exec(n);` — where only the post-call `n`
// usage indicates the sink reads the return value.
func tokenAfter(s, name string, minPos int) bool {
	if name == "" || s == "" || minPos < 0 {
		return false
	}
	if !strings.Contains(s, name) {
		return false
	}
	re := tokenRegexFor(name)
	for _, loc := range re.FindAllStringIndex(s, -1) {
		if loc[0] >= minPos {
			return true
		}
	}
	return false
}

// tokenRegexCache memoizes `\bname\b` regexes across calls. Identifier
// names are short and few — a sync.Map is overkill, a plain map under a
// RWMutex is fine for the call frequencies seen here.
var (
	tokenRegexCacheMu sync.RWMutex
	tokenRegexCache   = map[string]*regexp.Regexp{}
)

func tokenRegexFor(name string) *regexp.Regexp {
	tokenRegexCacheMu.RLock()
	re, ok := tokenRegexCache[name]
	tokenRegexCacheMu.RUnlock()
	if ok {
		return re
	}
	compiled := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	tokenRegexCacheMu.Lock()
	if cached, ok := tokenRegexCache[name]; ok {
		tokenRegexCacheMu.Unlock()
		return cached
	}
	tokenRegexCache[name] = compiled
	tokenRegexCacheMu.Unlock()
	return compiled
}

// isFuncDeclLine reports whether the line contains a function declaration
// header — top-level (`func Name(`), method (`func (recv T) Name(`), or
// closure (`x := func(`, `return func(`, `go func(`, etc.). Used to skip
// such lines during backward source tracing so parameter and return types
// like `*httplib.Request` / `*http.Request` don't spuriously match
// directSourcePatterns like `\bRequest\b`.
func isFuncDeclLine(trimmed string) bool {
	return funcDeclLineRe.MatchString(trimmed)
}

// funcDeclLineRe matches `func` as a keyword followed by an optional
// receiver/name and an opening paren. `\bfunc\b` anchors on a word
// boundary so identifiers ending in "func" don't match. The trailing
// `[^()]*\(` permits a receiver list before the parameter list.
var funcDeclLineRe = regexp.MustCompile(`\bfunc\b[^()]*\(`)

// filterSuppressedSinks moves sinks on suppressed lines from SinkCalls
// to SuppressedSinks. This prevents callers from generating interprocedural
// findings for sinks that the developer has explicitly marked as safe.
func filterSuppressedSinks(sig TaintSignature, suppressedLines map[int]bool) TaintSignature {
	if len(suppressedLines) == 0 || len(sig.SinkCalls) == 0 {
		return sig
	}
	var kept []SinkRef
	for _, sink := range sig.SinkCalls {
		if suppressedLines[sink.Line] {
			sig.SuppressedSinks = append(sig.SuppressedSinks, sink)
		} else {
			kept = append(kept, sink)
		}
	}
	sig.SinkCalls = kept
	return sig
}

// extractArgList extracts a list of argument expressions from a string
// that starts at an opening parenthesis.
func extractArgList(s string) []string {
	if len(s) == 0 || s[0] != '(' {
		return nil
	}

	// Find the matching close paren.
	depth := 0
	end := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				goto found
			}
		}
	}
found:
	if end < 0 {
		end = len(s)
	}

	inner := s[1:end]
	if strings.TrimSpace(inner) == "" {
		return nil
	}

	// Split by commas, respecting nested parens.
	var args []string
	depth = 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	args = append(args, strings.TrimSpace(inner[start:]))

	return args
}

// populateTypedParams walks the ast.FuncDecl matching node.Name and fills
// sig.Params / sig.Returns with canonical-type information from the
// KnownGoSourceTypes / KnownGoSinkTypes catalogs. For any parameter whose
// type is a known source, SourceParams is also populated so downstream
// regex-driven logic still works.
//
// For closure FuncNodes (Name matching "<Outer>.closure@line:col"), the
// FuncType is resolved via typed.FuncLits instead of typed.FuncDecls.
func populateTypedParams(node *FuncNode, typed *GoTypeInfo, sig *TaintSignature) {
	if typed == nil || typed.TypeEnv == nil {
		return
	}
	ft := lookupFuncType(typed, node.Name)
	if ft == nil {
		return
	}
	env := typed.TypeEnv

	if sig.SourceParams == nil {
		sig.SourceParams = make(map[int]taint.SourceCategory)
	}

	// Params: walk parameter declarations, expanding grouped names.
	sig.Params = sig.Params[:0]
	idx := 0
	if ft.Params != nil {
		for _, field := range ft.Params.List {
			rawType := astflow.ExprToTypeString(field.Type)
			canonical := env.CanonicalizeType(rawType)
			names := fieldNames(field)
			if len(names) == 0 {
				// Anonymous param still counts positionally.
				names = []string{""}
			}
			for _, name := range names {
				pt := ParamTaint{
					Index:         idx,
					Name:          name,
					Type:          rawType,
					CanonicalType: canonical,
				}
				if cat, ok := languages.LookupGoSourceType(canonical); ok {
					pt.IsSourceType = true
					pt.SourceCategory = cat
					sig.SourceParams[idx] = cat
				}
				if info, ok := languages.LookupGoSinkType(canonical); ok {
					pt.IsSinkType = true
					pt.SinkCategory = info.Category
				}
				sig.Params = append(sig.Params, pt)
				idx++
			}
		}
	}

	// Returns.
	sig.Returns = sig.Returns[:0]
	if ft.Results != nil {
		rIdx := 0
		for _, field := range ft.Results.List {
			rawType := astflow.ExprToTypeString(field.Type)
			canonical := env.CanonicalizeType(rawType)
			names := fieldNames(field)
			if len(names) == 0 {
				names = []string{""}
			}
			for _, name := range names {
				rt := ReturnTaint{
					Index:         rIdx,
					Name:          name,
					Type:          rawType,
					CanonicalType: canonical,
				}
				if cat, ok := languages.LookupGoSourceType(canonical); ok {
					rt.IsSourceType = true
					rt.SourceCategory = cat
					// A source-typed return means the function yields tainted data.
					if sig.TaintedReturns == nil {
						sig.TaintedReturns = make(map[int][]taint.SourceCategory)
					}
					sig.TaintedReturns[rIdx] = appendUniqueCat(sig.TaintedReturns[rIdx], cat)
				}
				sig.Returns = append(sig.Returns, rt)
				rIdx++
			}
		}
	}

	sig.TypesVersion = TypesSchemaVersion

	// Adding typed source/return information may flip an otherwise-pure
	// function to impure; recompute IsPure so callers re-evaluate.
	sig.IsPure = len(sig.SourceParams) == 0 &&
		len(sig.SinkCalls) == 0 &&
		len(sig.TaintedReturns) == 0 &&
		len(sig.TaintedParams) == 0
}

// lookupFuncType resolves a FuncNode name to the corresponding *ast.FuncType
// in typed. Top-level / method names hit FuncDecls; closure names matching
// "<Outer>.closure@line:col" hit FuncLits. Returns nil when no match exists.
func lookupFuncType(typed *GoTypeInfo, name string) *ast.FuncType {
	if typed == nil {
		return nil
	}
	if isClosureName(name) {
		if typed.FuncLits != nil {
			if fl := typed.FuncLits[name]; fl != nil {
				return fl.Type
			}
		}
		return nil
	}
	if typed.FuncDecls != nil {
		if fn := typed.FuncDecls[name]; fn != nil {
			return fn.Type
		}
	}
	return nil
}

// fieldNames returns the names declared on an ast.Field, skipping blank `_`.
func fieldNames(field *ast.Field) []string {
	if field == nil {
		return nil
	}
	out := make([]string, 0, len(field.Names))
	for _, n := range field.Names {
		if n == nil || n.Name == "_" {
			continue
		}
		out = append(out, n.Name)
	}
	return out
}

// analyzeCallerImpactTyped wraps AnalyzeCallerImpact, additionally using
// the caller's GoTypeInfo (if present) to bump confidence when a call-site
// argument's type matches a typed-source parameter of the callee, or when
// the callee returns a typed-source value.
func analyzeCallerImpactTyped(cg *CallGraph, callerNode *FuncNode, calleeNode *FuncNode, callerContent string, callerTypes *GoTypeInfo) []rules.Finding {
	findings := AnalyzeCallerImpact(cg, callerNode, calleeNode, callerContent)
	if len(findings) == 0 {
		return findings
	}
	if callerTypes == nil {
		return findings
	}

	callerBody := extractFuncBody(callerContent, callerNode.StartLine, callerNode.EndLine)
	if callerBody == "" {
		return findings
	}
	lines := strings.Split(callerBody, "\n")
	calleeBaseName := extractBaseName(calleeNode.Name)
	callPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(calleeBaseName) + `\s*\(`)

	// Collect caller->callee call sites and the arguments passed at each.
	var calls []typedCallSite
	for i, line := range lines {
		if !callPattern.MatchString(line) {
			continue
		}
		callIdx := strings.Index(line, calleeBaseName)
		if callIdx < 0 {
			continue
		}
		argsStart := strings.Index(line[callIdx:], "(")
		if argsStart < 0 {
			continue
		}
		calls = append(calls, typedCallSite{
			lineIdx: i,
			args:    extractArgList(line[callIdx+argsStart:]),
		})
	}

	for i := range findings {
		f := &findings[i]
		applyTypedConfidenceBump(f, callerNode, calleeNode, callerTypes, calls)
	}
	return findings
}

// applyTypedConfidenceBump inspects the finding's associated call site and,
// when a caller argument or callee return is confirmed by a known type,
// bumps ConfidenceScore by +0.1 (capped at 1.0) and tags the finding with
// "typed_confirmed". Returns true if a bump was applied.
// typedCallSite records a caller→callee call site for typed analysis.
type typedCallSite struct {
	lineIdx int
	args    []string
}

func applyTypedConfidenceBump(
	f *rules.Finding,
	callerNode *FuncNode,
	calleeNode *FuncNode,
	callerTypes *GoTypeInfo,
	calls []typedCallSite,
) bool {
	if callerTypes == nil || callerTypes.TypeEnv == nil {
		return false
	}

	// --- Path A: typed callee source param (Params[i].IsSourceType) ---
	// The caller passes an argument of a known-source type at position i.
	for _, pt := range calleeNode.TaintSig.Params {
		if !pt.IsSourceType {
			continue
		}
		for _, call := range calls {
			if pt.Index >= len(call.args) {
				continue
			}
			argExpr := strings.TrimSpace(call.args[pt.Index])
			argRoot := rootIdent(argExpr)
			if argRoot == "" {
				continue
			}
			argType := callerTypes.TypeEnv.VarType(argRoot)
			if argType == "" {
				continue
			}
			if callerTypes.TypeEnv.CanonicalizeType(argType) == pt.CanonicalType {
				return bumpTypedConfidence(f)
			}
		}
	}

	// --- Path B: typed callee sink param (*sql.DB etc.) ---
	for _, pt := range calleeNode.TaintSig.Params {
		if !pt.IsSinkType {
			continue
		}
		for _, call := range calls {
			if pt.Index >= len(call.args) {
				continue
			}
			argExpr := strings.TrimSpace(call.args[pt.Index])
			argRoot := rootIdent(argExpr)
			if argRoot == "" {
				continue
			}
			argType := callerTypes.TypeEnv.VarType(argRoot)
			if argType == "" {
				continue
			}
			if callerTypes.TypeEnv.CanonicalizeType(argType) == pt.CanonicalType {
				return bumpTypedConfidence(f)
			}
		}
	}

	// --- Path C: typed source return ---
	for _, rt := range calleeNode.TaintSig.Returns {
		if rt.IsSourceType {
			return bumpTypedConfidence(f)
		}
	}

	return false
}

func bumpTypedConfidence(f *rules.Finding) bool {
	newScore := f.ConfidenceScore + 0.1
	if newScore > 1.0 {
		newScore = 1.0
	}
	if newScore > f.ConfidenceScore {
		f.ConfidenceScore = newScore
	}
	hasTag := false
	for _, t := range f.Tags {
		if t == "typed_confirmed" {
			hasTag = true
			break
		}
	}
	if !hasTag {
		f.Tags = append(f.Tags, "typed_confirmed")
	}
	return true
}

// rootIdent returns the leading identifier of an expression, stripping
// trailing `.Field`, `[idx]`, or `()` suffixes. Returns "" when the
// expression isn't rooted at a simple identifier.
func rootIdent(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	end := 0
	for end < len(expr) {
		c := expr[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
			(end > 0 && c >= '0' && c <= '9') {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return ""
	}
	return expr[:end]
}
