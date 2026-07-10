// Per-language adapter: Shell (PR-Gshell).
//
// Implements LanguageResolver for cross-file Shell call resolution. Shell
// cross-file linkage is `source FILE` / `. FILE`: sourcing runs the target
// in the CURRENT shell, injecting its functions into the sourcing file's
// namespace, so a function defined in a sourced file becomes callable BY
// BARE NAME in the sourcing file. There is no per-symbol import and no
// method receiver — every function is a bare top-level name.
//
// Shell functions are therefore bare-name (like Swift), BUT — and this is
// the precision the held single-bucket port lacked — a function is only
// reachable cross-file when its defining file is pulled in via the
// `source` graph. The earlier port keyed ALL Shell nodes under one shared
// bucket and resolved a bare call to the FIRST same-named node in ANY file
// of the scan dir; that over-resolves (a `parse()` in lib/a.sh would link
// to a `parse()` call in an unrelated tool/b.sh that never sources it),
// which is the diagnosed false-positive class. This resolver instead:
//
//   - PackageIndex keys each Shell node under its OWN absolute file path
//     (importPathForNode's `case rules.LangShell` arm returns
//     node.FilePath), exactly like the C# / Lua / Rust path-keyed branches.
//   - ExtractScope parses each file's `source FILE` / `. FILE` directives,
//     resolves each (relative paths against the file's own directory), and
//     records the resolved absolute targets in StarImports. scope.Package
//     is the file's absolute path.
//   - resolve.go builds a project-wide source-graph (PackageIndex
//     .shellSources: caller-file → sourced files) from those StarImports.
//   - ResolveCall walks the TRANSITIVE source-closure from the caller's
//     file and resolves the bare call only to a function defined in one of
//     those sourced files. A function in a file the caller never sources is
//     left unresolved — eliminating the over-resolution FP class while the
//     V1 `source ./lib.sh` shape resolves precisely.
//
// This is the source-graph analog of the C# resolver's "same-namespace,
// no using" precision (resolver_csharp.go: resolveSameNamespaceQualified +
// Package== matching): C# scopes by declared namespace, Shell scopes by the
// source-graph. The node-ID suffix matcher mirrors the C# resolver's
// suffix-match approach.
//
// Out of scope for v1 (documented cuts):
//   - Dynamic `source "$var"` of a computed path (the argument isn't a
//     literal, so no edge is recorded — conservative, no FP).
//   - Functions made visible only at runtime (e.g. sourced inside a
//     conditional branch) are still treated as sourced (we don't model
//     control flow); this can only ADD an edge that exists statically, and
//     the sink/sanitizer two-sided gate caps the blast radius.
//
// Everything here is gated to rules.LangShell: the resolver registers only
// for LangShell and the dispatcher (resolve.go) calls GetResolver(lang), so
// no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// shellResolver implements LanguageResolver for Shell.
type shellResolver struct{}

func init() {
	RegisterResolver(&shellResolver{})
}

// Language reports that this resolver handles Shell.
func (r *shellResolver) Language() rules.Language { return rules.LangShell }

// shellManifestFilenames identify a likely shell-project root. Shell has no
// formal manifest, so these are heuristic anchors; resolution does not
// depend on finding one (the source-graph model works from any root —
// PackageIndex keys on absolute file paths).
var shellManifestFilenames = []string{
	".git",
	"Makefile",
	"makefile",
}

// ProjectRoot walks up from scanDir looking for a heuristic project anchor.
// The module path is always empty for Shell — every node keys under its own
// absolute file path, not a path-derived namespace.
func (r *shellResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
	dir := scanDir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", false
	}
	cur := abs
	for {
		for _, manifest := range shellManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, "", true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No anchor found — anchor at scanDir so the framework still has a
	// non-empty manifest path (mirrors the Swift / Lua last-resort).
	return abs, "", true
}

// ExtractScope produces a FileScope for a Shell file: the file's absolute
// path as both FilePath and Package (PackageIndex keys Shell nodes by
// absolute file path), plus the resolved absolute paths of every file the
// script `source`s / `.`s recorded in StarImports. The source-graph built
// from these StarImports is what scopes cross-file resolution.
func (r *shellResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	abs := filePath
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(filePath); err == nil {
			abs = a
		}
	}
	fs := FileScope{
		FilePath: abs,
		Package:  abs,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}

	tree := tsast.Parse(content, rules.LangShell)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	baseDir := filepath.Dir(abs)
	seen := map[string]bool{}
	collectShellSources(tree.Root(), baseDir, &fs, seen)
	return fs, nil
}

// collectShellSources walks the tree recording every `source FILE` / `. FILE`
// directive's resolved absolute target into fs.StarImports. The directive is
// a `command` node whose command-word is `source` or `.` and whose first
// literal argument is the target path. Relative targets resolve against
// baseDir (the sourcing file's own directory). Non-literal targets
// (`source "$var"`) and absolute paths outside the project are recorded as-is
// when they exist on disk; otherwise skipped.
func collectShellSources(n *tsast.Node, baseDir string, fs *FileScope, seen map[string]bool) {
	if n == nil {
		return
	}
	if n.Type() == "command" {
		if word := shellCommandWord(n); word == "source" || word == "." {
			if target := shellFirstArg(n); target != "" {
				if resolved := resolveShellSourcePath(target, baseDir); resolved != "" && !seen[resolved] {
					seen[resolved] = true
					fs.StarImports = append(fs.StarImports, resolved)
				}
			}
		}
	}
	for _, c := range n.NamedChildren() {
		collectShellSources(c, baseDir, fs, seen)
	}
}

// shellFirstArg returns the first positional argument text of a `command`
// node (the `argument`-field child), stripped of surrounding quotes. Returns
// "" when there is no literal argument (e.g. `source "$dir/lib.sh"` whose
// argument is an expansion — we don't resolve dynamic source paths).
func shellFirstArg(call *tsast.Node) string {
	for i := 0; i < call.ChildCount(); i++ {
		c := call.Child(i)
		if c.FieldName() != "argument" {
			continue
		}
		// Only a literal `word` (or a quoted plain string) is a resolvable
		// path. An expansion / command-substitution argument is dynamic.
		switch c.Type() {
		case "word":
			return strings.TrimSpace(c.Text())
		case "string", "raw_string":
			t := strings.TrimSpace(c.Text())
			// A quoted literal with no `$` expansion is still static.
			if strings.ContainsRune(t, '$') {
				return ""
			}
			t = strings.Trim(t, `"'`)
			return strings.TrimSpace(t)
		default:
			return ""
		}
	}
	return ""
}

// resolveShellSourcePath turns a `source` argument into an absolute file
// path. A bare `lib.sh` / `./lib.sh` / `../util/lib.sh` resolves against
// baseDir; an absolute path is used directly. Returns "" when the resolved
// path doesn't exist on disk (an unresolved / out-of-tree source contributes
// no edge — conservative, no FP). A leading `$` (dynamic path) yields "".
func resolveShellSourcePath(arg, baseDir string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" || strings.ContainsRune(arg, '$') {
		return ""
	}
	var candidate string
	if filepath.IsAbs(arg) {
		candidate = filepath.Clean(arg)
	} else {
		candidate = filepath.Clean(filepath.Join(baseDir, arg))
	}
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	return ""
}

// buildShellSourceGraph constructs the project-wide source-graph from every
// Shell FileScope's StarImports (the resolved sourced-file paths captured by
// shellResolver.ExtractScope). Returns nil when no Shell file sources
// anything, so callers cheaply skip the source-graph path on projects with
// no shell `source` edges. Keyed by absolute file path on both sides.
func buildShellSourceGraph(scopes map[string]FileScope) map[string][]string {
	out := map[string][]string{}
	any := false
	for path, scope := range scopes {
		if len(scope.StarImports) == 0 {
			continue
		}
		// Only treat a scope as a Shell scope when its Package == its own
		// path (the convention shellResolver.ExtractScope sets). Other
		// languages also use StarImports (Python/Java), but their Package is
		// a dotted namespace, never the absolute file path, so this keeps the
		// graph Shell-only without a language field on FileScope.
		abs := scope.FilePath
		if abs == "" {
			abs = path
		}
		if scope.Package != abs {
			continue
		}
		out[abs] = append(out[abs], scope.StarImports...)
		any = true
	}
	if !any {
		return nil
	}
	return out
}

// shellSourceClosure returns the set of absolute file paths transitively
// reachable from startFile via the source-graph (the files startFile
// `source`s, the files THOSE source, and so on). startFile itself is
// included (a function defined in the same file is trivially visible, though
// the same-file pass already wired that edge). Bounded by the number of
// indexed files; cycles are handled by the visited set.
func shellSourceClosure(startFile string, sources map[string][]string) map[string]bool {
	closure := map[string]bool{startFile: true}
	if sources == nil {
		return closure
	}
	stack := []string{startFile}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, dst := range sources[cur] {
			if !closure[dst] {
				closure[dst] = true
				stack = append(stack, dst)
			}
		}
	}
	return closure
}

// ResolveCall resolves a Shell call (a bare command word that names a
// defined function) to a FuncNode ID by bare-name lookup, scoped to the
// caller file's transitive source-closure.
//
// callee is the bare command word (`get_name`). Built-in commands and
// external binaries (`eval`, `curl`, `echo`) simply find no matching
// function node and resolve to nothing.
//
// Same-file calls are already wired by the builder; this fires for the
// cross-file case where the called function is defined in a file the caller
// (transitively) sources.
func (r *shellResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" || idx == nil {
		return ResolveResult{}
	}
	// Shell command words carry no receiver; if a dotted form ever shows up
	// (it should not for shell), fall back to the trailing segment.
	want := callee
	if i := strings.LastIndex(callee, "."); i >= 0 {
		want = callee[i+1:]
	}
	if want == "" {
		return ResolveResult{}
	}

	// Scope resolution to the files the caller transitively sources. The
	// caller file is scope.FilePath (set by ExtractScope to the abs path).
	closure := shellSourceClosure(scope.FilePath, idx.shellSources)
	if id, ok := resolveShellNodeID(want, closure, idx); ok {
		return ResolveResult{TargetID: id, Confidence: 0.8}
	}
	return ResolveResult{}
}

// resolveShellNodeID looks up a function whose name equals `want` among the
// nodes declared in any file in `closure` (the caller's transitive source-
// closure). PackageIndex keys Shell nodes by absolute file path, so we scan
// only the closure files' buckets rather than the whole project — precise
// AND cheap. Returns the FIRST match (deterministic given sorted node IDs).
func resolveShellNodeID(want string, closure map[string]bool, idx *PackageIndex) (string, bool) {
	if idx == nil || want == "" || len(closure) == 0 {
		return "", false
	}
	// Iterate closure files in sorted order so the FIRST match is stable
	// across runs when two sourced files define the same function name
	// (Go map iteration is randomised; scan determinism matters — see the
	// per-language parse-lock fix that made `batou scan` deterministic).
	files := make([]string, 0, len(closure))
	for file := range closure {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		cands := idx.Lookup(file)
		for _, candID := range cands {
			colon := strings.LastIndexByte(candID, ':')
			if colon < 0 {
				continue
			}
			fnPart := candID[colon+1:]
			if fnPart == want {
				return candID, true
			}
		}
	}
	return "", false
}
