// Per-language adapter: Go.
//
// Implements the LanguageResolver interface for Go source code:
//   - ProjectRoot walks up from scanDir to find go.mod and extracts the
//     module path declared inside it.
//   - ExtractScope parses a file's `import (...)` block (with go/parser
//     in ImportsOnly mode) into the alias→import-path map plus the
//     declared package name.
//   - ResolveCall takes a raw call expression like "auth.LoginByName"
//     and resolves it against the file's scope plus the project's
//     PackageIndex:
//     1. Split into (alias, methodName).
//     2. Look up alias in scope.Imports to get the import path.
//     3. If the import path starts with modulePath/ it's in-project;
//     look up the package's nodes via PackageIndex.
//     4. Find a node whose name == methodName (the resolved target).
//     5. If the import path is NOT in-project, treat it as an extern
//     and emit "<importPath>.<methodName>" so downstream consumers
//     can answer "what external surface does this function touch?".
package graph

import (
	"bufio"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// goResolver implements LanguageResolver for Go.
type goResolver struct{}

func init() {
	RegisterResolver(&goResolver{})
}

// Language reports that this resolver handles Go.
func (g *goResolver) Language() rules.Language { return rules.LangGo }

// ProjectRoot walks up from scanDir looking for a go.mod file and
// returns its path plus the declared module path. The walk stops at the
// filesystem root or at a directory where we lose stat permission.
//
// Module path is the value following `module` on the first non-comment,
// non-blank line of go.mod (Go's actual parser is stricter; we accept
// the relaxed shape here because we only need the path string).
func (g *goResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
	dir := scanDir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", false
	}
	for {
		candidate := filepath.Join(abs, "go.mod")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			modPath := readGoModModulePath(candidate)
			return candidate, modPath, true
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", "", false
		}
		abs = parent
	}
}

// readGoModModulePath returns the module path declared in a go.mod file
// (the first `module <path>` directive). Returns "" if the file can't
// be read or no module directive is found within the first 64 lines.
func readGoModModulePath(modPath string) string {
	f, err := os.Open(modPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	const maxLines = 64
	for i := 0; i < maxLines && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.HasPrefix(line, "module") {
			continue
		}
		// Accept either `module path` or `module "path"`.
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		rest = strings.TrimPrefix(rest, "(")
		rest = strings.TrimSpace(rest)
		rest = strings.Trim(rest, `"`)
		// Strip any trailing comment.
		if idx := strings.Index(rest, "//"); idx >= 0 {
			rest = strings.TrimSpace(rest[:idx])
		}
		if rest != "" {
			return rest
		}
	}
	return ""
}

// ExtractScope parses the Go file's package declaration and import
// block into a FileScope. Uses go/parser in ImportsOnly mode so we
// don't pay for body parsing — this is cheap enough to run on every
// file during the cross-file pass.
func (g *goResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	fs := FileScope{FilePath: filePath, Imports: map[string]string{}}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filePath, content, parser.ImportsOnly)
	if err != nil {
		// Return what we have — a partial scope is more useful than an
		// empty one when source contains a parse error somewhere below
		// the imports.
		return fs, err
	}
	if parsed.Name != nil {
		fs.Package = parsed.Name.Name
	}

	for _, imp := range parsed.Imports {
		if imp.Path == nil {
			continue
		}
		raw := strings.Trim(imp.Path.Value, `"`)
		if raw == "" {
			continue
		}
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		switch alias {
		case "_":
			// Blank import: side-effect-only, no alias to resolve.
			continue
		case ".":
			// Dot import: names are unqualified in the current scope.
			fs.StarImports = append(fs.StarImports, raw)
			continue
		case "":
			// No explicit alias — use the last path component. This
			// matches the language-level binding the compiler does.
			alias = path.Base(raw)
		}
		fs.Imports[alias] = raw
	}
	return fs, nil
}

// ResolveCall resolves a single Go call expression. callee is one of:
//
//	"Func"        — bare identifier, package-local function call
//	"pkg.Func"    — selector call; pkg is either an import alias OR a
//	                local variable / receiver. We try the import
//	                interpretation first; if it doesn't match, we fall
//	                back to "unresolved" and let the caller decide.
//
// Same-file resolution already runs during initial extraction (see
// builder.go), but a bare same-package call can target a function defined
// in a SIBLING file (Go makes every top-level func in a package visible
// across all its files without an import). The same-file pass can't see
// that callee, so we resolve bare identifiers against the caller's own
// package via the PackageIndex here — see resolveBareSamePackage.
func (g *goResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")
	if dot <= 0 || dot == len(callee)-1 {
		// Bare identifier (no dot, or dot at edge). Try to resolve it to a
		// top-level function declared in a different file of the caller's
		// own package; the same-file pass already handled same-file callees.
		if dot < 0 {
			if id, ok := g.resolveBareSamePackage(callee, scope, idx); ok {
				return ResolveResult{TargetID: id, Confidence: 0.85}
			}
		}
		return ResolveResult{}
	}
	alias := callee[:dot]
	methodName := callee[dot+1:]

	importPath, ok := scope.Imports[alias]
	if !ok {
		// Not an import alias — likely a receiver or local variable
		// method call. Let the caller decide.
		return ResolveResult{}
	}

	// In-project? Match by prefix == modulePath, AND a trailing slash
	// OR exact match (don't let "example.com/foo" steal calls intended
	// for "example.com/foobar").
	if modulePath != "" && (importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/")) {
		// Look up the package in the index. The Go resolver keys the
		// package index by import path directly — see builder/Go
		// indexing.
		candidates := idx.Lookup(importPath)
		// FuncID is "<filePath>:<funcName>"; match the final segment
		// against methodName. For top-level functions the segment is
		// the function name; for methods it's "Receiver.Method".
		//
		// First pass: exact top-level function name. `pkg.Func` names a
		// top-level func, so when one exists it must win over a
		// same-named method ("Recv.Func") that merely suffix-matches —
		// first-hit order would otherwise mis-bind (mirrors the Java /
		// PHP exact-first two-pass).
		for _, candID := range candidates {
			colon := strings.LastIndexByte(candID, ':')
			if colon < 0 {
				continue
			}
			if candID[colon+1:] == methodName {
				return ResolveResult{TargetID: candID, Confidence: 0.9}
			}
		}
		// Second pass: method-suffix fallback ("Receiver.Method").
		for _, candID := range candidates {
			colon := strings.LastIndexByte(candID, ':')
			if colon < 0 {
				continue
			}
			if strings.HasSuffix(candID[colon+1:], "."+methodName) {
				return ResolveResult{TargetID: candID, Confidence: 0.9}
			}
		}
		// In-project import but no matching function — could be a
		// struct method we missed, or a name we don't index. Don't
		// emit an extern (the call is definitely not external).
		return ResolveResult{}
	}

	// External package — record it for "what does this function depend
	// on externally?" queries.
	return ResolveResult{
		Extern:     importPath + "." + methodName,
		Confidence: 0.95,
	}
}

// resolveBareSamePackage resolves a bare call `helper()` to a top-level
// function `func helper(...)` declared in a SIBLING file of the caller's own
// Go package. Go compiles every file in a package together, so a top-level
// func is visible across all the package's files with no import — but the
// same-file extraction pass (buildGoNodes) can only wire the edge when the
// definition is in the SAME file. This closes that cross-file gap.
//
// The Go PackageIndex is keyed by import path, and every file in a package
// shares that one key (see importPathForNode), so we:
//
//  1. find the caller file's own package key (PackageForFile on scope.FilePath),
//  2. look up that package's nodes, and
//  3. return the node whose top-level func name is exactly `name`.
//
// Precision guards that keep this purely additive (cross-file edges only,
// never a wrong one):
//   - We require an EXACT top-level func-name match (fnPart == name). A bare
//     identifier can never be a method call (those carry a receiver and arrive
//     here dotted), so we deliberately do NOT match a "Recv.name" suffix the
//     way the dotted path does — that would mis-bind `helper()` onto an
//     unrelated method named `helper`.
//   - We skip any candidate in the caller's OWN file: that edge is the
//     same-file pass's job, and resolveNodeRawCalls rejects self-edges anyway.
//     This makes the resolver strictly add sibling-file edges.
func (g *goResolver) resolveBareSamePackage(name string, scope FileScope, idx *PackageIndex) (string, bool) {
	if name == "" || idx == nil || scope.FilePath == "" {
		return "", false
	}
	pkg := idx.PackageForFile(scope.FilePath)
	if pkg == "" {
		return "", false
	}
	ownPrefix := scope.FilePath + ":"
	for _, candID := range idx.Lookup(pkg) {
		if strings.HasPrefix(candID, ownPrefix) {
			// Same file — handled by the same-file pass.
			continue
		}
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		// Exact top-level function name only (no "Recv.method" suffix match).
		if candID[colon+1:] == name {
			return candID, true
		}
	}
	return "", false
}
