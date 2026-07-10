// Per-language adapter: C++ (PR-Gcpp).
//
// Implements LanguageResolver for cross-file C++ call resolution. C++ has
// no module system — cross-translation-unit visibility is established by
// the preprocessor's `#include` directive. A function declared in a header
// (`helper.h`) is typically *defined* in a sibling implementation file
// (`helper.cpp`), so when `main.cpp` does `#include "helper.h"`, the
// definition that the cross-file pass needs to reach lives in `helper.cpp`,
// not the header.
//
// Resolution model (path-keyed, like JS / Lua / Java / PHP / Ruby):
//
//   - PackageIndex is keyed on absolute file paths. The importPathForNode
//     case in resolve.go returns each node's own absolute file path, so a
//     `.cpp` file's function nodes land in that file's bucket.
//   - ExtractScope parses every `#include "x.h"` (quoted form only — angle-
//     bracket `<system>` includes are external libraries, never searched on
//     disk) and resolves it to the set of in-project files reachable from
//     that header: the header itself PLUS every sibling implementation file
//     with the same basename (`x.cpp`, `x.cc`, `x.cxx`, `x.c++`, `x.c`).
//     Those absolute paths are recorded in scope.Imports (keyed by the
//     resolved path so duplicates collapse) and additionally accumulated in
//     scope.Aux["includes"] (a `\n`-joined list) so ResolveCall can iterate
//     them.
//   - ResolveCall takes the call's bare suffix (strips any `ns::` / `Class::`
//     scope) and returns the first C++ node in any included file whose name
//     basename matches. Both `getName` and `ns.getName` / `Foo.getName`
//     node names satisfy a `getName` / `ns::getName` call.
//
// Out of scope for v1 (documented cuts):
//   - Include-path search dirs from a build system (CMake target
//     include_directories, -I flags). v1 searches relative to the including
//     file's directory and the project root, which covers the dominant
//     "headers next to sources" and "include/ + src/" layouts.
//   - Transitive includes (header A includes header B). v1 resolves one hop;
//     a call whose definition is two includes away is left unresolved.
//   - Overload resolution / ADL. The bare-suffix match over-resolves on
//     same-named overloads in different files (matching every other port);
//     the sink/sanitizer two-sided gate suppresses spurious pairs.
//
// This resolver registers for BOTH rules.LangC and rules.LangCPP (one
// instance each, sharing every method body); the dispatcher (resolve.go)
// calls GetResolver(lang), so only C-family resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// cppResolver implements LanguageResolver for the C-family (C and C++). The
// same #include-driven, path-keyed resolution model applies to both: a `.c`
// file's `#include "x.h"` reaches the sibling `x.c` implementation exactly
// as a `.cpp` file's reaches `x.cpp`. cppImplExts / cppHeaderExts already
// enumerate the `.c` / `.h` extensions, so one resolver body handles both.
// The `lang` field records which language this registered instance answers
// for (so GetResolver(LangC) and GetResolver(LangCPP) both succeed); the
// tree-sitter grammar used in ExtractScope is selected per-file-path by
// cppGrammarForPath, not by this field.
type cppResolver struct{ lang rules.Language }

func init() {
	// Register one instance per C-family language so GetResolver(LangC) and
	// GetResolver(LangCPP) both resolve to this shared resolver body. The
	// LangCPP instance is byte-identical in behaviour to the pre-C version
	// (it parses .cpp/.hpp with the C++ grammar via cppGrammarForPath); the
	// LangC instance newly enables cross-file taint for .c/.h files.
	RegisterResolver(&cppResolver{lang: rules.LangCPP})
	RegisterResolver(&cppResolver{lang: rules.LangC})
}

// Language reports which C-family language this resolver instance handles.
func (r *cppResolver) Language() rules.Language { return r.lang }

// isCPPFamily reports whether lang is one of the C-family languages handled
// by the shared cpp builder / resolver / walker (C and C++).
func isCPPFamily(lang rules.Language) bool {
	return lang == rules.LangC || lang == rules.LangCPP
}

// cppGrammarForPath picks the tree-sitter grammar used to parse a C-family
// file. Only an unambiguous `.c` extension selects the C grammar; every
// extension the previous LangCPP-only resolver handled (`.cpp`, `.cc`,
// `.cxx`, `.c++`, and the ambiguous header extensions `.h`/`.hpp`/...) keeps
// the C++ grammar, a superset of C's surface syntax that parses C-in-headers
// without loss. This keeps #include extraction byte-identical for every path
// the old code parsed while giving a genuine `.c` translation unit the C
// grammar the builder also stamps onto its nodes.
func cppGrammarForPath(path string) rules.Language {
	if strings.EqualFold(filepath.Ext(path), ".c") {
		return rules.LangC
	}
	return rules.LangCPP
}

// cppManifestFilenames identify a C++ project's root.
var cppManifestFilenames = []string{
	"CMakeLists.txt",
	"compile_commands.json",
	"conanfile.txt",
	"conanfile.py",
	"meson.build",
	"Makefile",
	"BUILD",
	"BUILD.bazel",
}

// cppManifestDirs are directory names that, when present, indicate a
// project root even without a manifest file (the common `include/` +
// `src/` split).
var cppManifestDirs = []string{
	"include",
	"src",
}

// cppImplExts are the implementation-file extensions a header's
// declarations are typically defined in.
var cppImplExts = []string{".cpp", ".cc", ".cxx", ".c++", ".cp", ".c"}

// cppHeaderExts are the header-file extensions an implementation may
// include.
var cppHeaderExts = []string{".h", ".hpp", ".hh", ".hxx", ".h++"}

// ProjectRoot walks up from scanDir looking for a C++ project marker.
// modulePath is always empty for C++ — there is no path-prefix namespace.
func (r *cppResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range cppManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		for _, sub := range cppManifestDirs {
			if info, err := os.Stat(filepath.Join(cur, sub)); err == nil && info.IsDir() {
				return filepath.Join(cur, "__manifest__"), "", true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No marker found — anchor at scanDir so the framework still has a
	// non-empty manifest path (mirrors the Lua / Swift last-resort).
	return abs, "", true
}

// findCPPProjectRoot walks up from a file's directory looking for the same
// markers as ProjectRoot and returns the project root directory, or "".
func findCPPProjectRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range cppManifestFilenames {
			if info, err := os.Stat(filepath.Join(cur, manifest)); err == nil && !info.IsDir() {
				return cur
			}
		}
		for _, sub := range cppManifestDirs {
			if info, err := os.Stat(filepath.Join(cur, sub)); err == nil && info.IsDir() {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return ""
}

// ExtractScope parses a C++ file's `#include "x.h"` directives into a
// FileScope. Each quoted include is resolved to the set of in-project
// files reachable from it (the header plus sibling implementation files);
// those absolute paths populate scope.Imports (path → path) and
// scope.Aux["includes"] (a `\n`-joined ordered list ResolveCall iterates).
//
// scope.Package is the file's own absolute path — PackageIndex keys nodes
// by absolute file path, mirroring the JS / Java / Lua model.
func (r *cppResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	fs := FileScope{
		FilePath: filePath,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}
	abs := filePath
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(filePath); err == nil {
			abs = a
		}
	}
	fs.FilePath = abs
	fs.Package = abs

	projectRoot := findCPPProjectRoot(abs)
	if projectRoot != "" {
		fs.Aux["project_root"] = projectRoot
	}

	// A .cpp file should always be able to reach its OWN sibling header
	// (and vice-versa) even when the corresponding #include line is
	// absent — the definitions in a translation unit and its header are
	// part of the same logical compilation unit. Seed self-siblings first.
	var includes []string
	seen := map[string]bool{}
	addTarget := func(p string) {
		if p == "" || p == abs || seen[p] {
			return
		}
		seen[p] = true
		includes = append(includes, p)
		fs.Imports[p] = p
	}
	for _, sib := range cppSelfSiblings(abs) {
		addTarget(sib)
	}

	tree := tsast.Parse(content, cppGrammarForPath(abs))
	if tree != nil && tree.Root() != nil {
		for _, spec := range collectCPPIncludes(tree.Root()) {
			for _, t := range resolveCPPInclude(spec, abs, projectRoot) {
				addTarget(t)
			}
		}
	}

	if len(includes) > 0 {
		fs.Aux["includes"] = strings.Join(includes, "\n")
	}
	return fs, nil
}

// collectCPPIncludes returns the quoted-include specifiers (`"helper.h"` →
// "helper.h") found at the top level of a translation unit. Angle-bracket
// system includes are skipped — they are external libraries.
func collectCPPIncludes(root *tsast.Node) []string {
	var out []string
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		if n.Type() == "preproc_include" {
			if p := n.ChildByFieldName("path"); p != nil {
				if p.Type() == "string_literal" {
					out = append(out, cppStripIncludeLiteral(p))
				}
				// system_lib_string (`<string>`) is intentionally skipped.
			}
			return
		}
		// Includes only appear at the top level / inside preproc
		// conditionals, so a shallow walk over named children suffices.
		for _, c := range n.NamedChildren() {
			switch c.Type() {
			case "preproc_include", "preproc_if", "preproc_ifdef",
				"preproc_else", "preproc_elif", "translation_unit":
				visit(c)
			}
		}
	}
	visit(root)
	return out
}

// cppStripIncludeLiteral returns the inner path of a `string_literal`
// include path node with the surrounding quotes removed.
func cppStripIncludeLiteral(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Type() == "string_content" {
			return strings.TrimSpace(c.Text())
		}
	}
	s := strings.TrimSpace(n.Text())
	s = strings.Trim(s, `"`)
	return s
}

// cppSelfSiblings returns the in-project sibling files of fileAbs that
// share its basename but use a complementary extension (a .cpp's headers,
// a header's .cpp). These are reachable without an explicit #include
// because they form one logical compilation unit.
func cppSelfSiblings(fileAbs string) []string {
	dir := filepath.Dir(fileAbs)
	base := strings.TrimSuffix(filepath.Base(fileAbs), filepath.Ext(fileAbs))
	if base == "" {
		return nil
	}
	var exts []string
	if cppIsHeaderPath(fileAbs) {
		exts = cppImplExts
	} else {
		exts = cppHeaderExts
	}
	var out []string
	for _, ext := range exts {
		cand := filepath.Join(dir, base+ext)
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			out = append(out, cand)
		}
	}
	// Also probe the parallel include/ ⇄ src/ layout for a header's impl.
	if root := findCPPProjectRoot(fileAbs); root != "" {
		for _, peerDir := range cppParallelDirs(dir, root) {
			for _, ext := range exts {
				cand := filepath.Join(peerDir, base+ext)
				if info, err := os.Stat(cand); err == nil && !info.IsDir() {
					out = append(out, cand)
				}
			}
		}
	}
	return out
}

// cppParallelDirs returns the include/ ⇄ src/ mirror of dir under root, so
// a header in `<root>/include/foo` maps to `<root>/src/foo` and vice versa.
func cppParallelDirs(dir, root string) []string {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil
	}
	segs := strings.Split(filepath.ToSlash(rel), "/")
	if len(segs) == 0 {
		return nil
	}
	var out []string
	swap := map[string]string{"include": "src", "src": "include"}
	for i, s := range segs {
		if peer, ok := swap[s]; ok {
			cp := append([]string(nil), segs...)
			cp[i] = peer
			out = append(out, filepath.Join(root, filepath.FromSlash(strings.Join(cp, "/"))))
		}
	}
	return out
}

// cppIsHeaderPath reports whether path uses a header extension.
func cppIsHeaderPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, h := range cppHeaderExts {
		if ext == h {
			return true
		}
	}
	return false
}

// resolveCPPInclude resolves a quoted include specifier to the set of
// in-project absolute paths reachable from it: the header (when found on
// disk) plus its sibling implementation files. Search roots are the
// including file's directory, the directory the include path is relative
// to, and the project root (and its include/ and src/ subdirs).
func resolveCPPInclude(spec, fileAbs, projectRoot string) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	rel := filepath.FromSlash(spec)

	var roots []string
	if d := filepath.Dir(fileAbs); d != "" {
		roots = append(roots, d)
	}
	if projectRoot != "" {
		roots = append(roots,
			projectRoot,
			filepath.Join(projectRoot, "include"),
			filepath.Join(projectRoot, "src"),
		)
	}

	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		if info, err := os.Stat(p); err != nil || info.IsDir() {
			return
		}
		if a, err := filepath.Abs(p); err == nil {
			p = a
		}
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	for _, root := range roots {
		header := filepath.Join(root, rel)
		add(header)
		// Sibling implementation files (same dir, same basename).
		dir := filepath.Dir(header)
		base := strings.TrimSuffix(filepath.Base(header), filepath.Ext(header))
		if base == "" {
			continue
		}
		for _, ext := range cppImplExts {
			add(filepath.Join(dir, base+ext))
		}
		// include/ → src/ mirror for the impl.
		if projectRoot != "" {
			for _, peerDir := range cppParallelDirs(dir, projectRoot) {
				for _, ext := range cppImplExts {
					add(filepath.Join(peerDir, base+ext))
				}
			}
		}
	}
	return out
}

// ResolveCall resolves a C++ call expression to a FuncNode ID by bare-
// suffix lookup across the file's included translation units.
//
// callee is one of:
//
//	"foo"          — bare name. Resolved against every included file's
//	                 node basenames.
//	"ns::foo"      — namespace-qualified call. The trailing name is used
//	                 for the match (the resolver knows the dotted node
//	                 names, so `ns.foo` and bare `foo` both satisfy it).
//	"Class::foo"   — static / qualified method call. Same handling.
//	"method"       — a `obj.method` call already reduced to "method" by the
//	                 builder/index; matched by suffix.
//
// Same-file calls are already wired by the builder; this fires for the
// cross-file case where the callee lives in an included file.
func (r *cppResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" || idx == nil {
		return ResolveResult{}
	}
	wantSuffix := callee
	if i := strings.LastIndex(callee, "::"); i >= 0 {
		wantSuffix = callee[i+2:]
	} else if i := strings.LastIndex(callee, "."); i >= 0 {
		wantSuffix = callee[i+1:]
	}
	wantSuffix = strings.TrimSpace(wantSuffix)
	if wantSuffix == "" {
		return ResolveResult{}
	}

	targets := cppIncludeTargets(scope)
	for _, target := range targets {
		if id, ok := resolveCPPNodeID(target, wantSuffix, idx); ok {
			return ResolveResult{TargetID: id, Confidence: 0.8}
		}
	}
	return ResolveResult{}
}

// cppIncludeTargets returns the ordered list of in-project file paths the
// file's includes resolved to. Reads scope.Aux["includes"] (the ordered
// list) and falls back to the Imports map keys.
func cppIncludeTargets(scope FileScope) []string {
	if raw := scope.Aux["includes"]; raw != "" {
		return strings.Split(raw, "\n")
	}
	if len(scope.Imports) == 0 {
		return nil
	}
	out := make([]string, 0, len(scope.Imports))
	for _, target := range scope.Imports {
		if filepath.IsAbs(target) {
			out = append(out, target)
		}
	}
	return out
}

// resolveCPPNodeID looks up a function whose name basename equals
// `wantSuffix` inside the file `filePath` via the PackageIndex (keyed by
// absolute file path for C++). A node named "ns.getName", "Foo.getName" or
// bare "getName" all satisfy a `getName` / `ns::getName` call. Returns the
// FIRST match (deliberate — C++ v1 over-resolves on same-named overloads
// in different files, matching the Swift / Lua behaviour; the two-sided
// sink/sanitizer gate suppresses spurious pairs).
func resolveCPPNodeID(filePath, wantSuffix string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || wantSuffix == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		if fnPart == wantSuffix || strings.HasSuffix(fnPart, "."+wantSuffix) {
			return candID, true
		}
	}
	return "", false
}
