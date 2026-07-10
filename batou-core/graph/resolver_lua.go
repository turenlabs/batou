// Per-language adapter: Lua (PR-Glua).
//
// Implements LanguageResolver for cross-file Lua call resolution. Lua has
// no file-path-to-namespace mapping enforced by the language — modules
// are values returned by a chunk and bound to a local via `require`. So,
// like the JS / Ruby resolvers, PackageIndex is keyed on absolute file
// paths and each `require("mod")` records an alias → absolute target-path
// binding. Downstream `alias.method(...)` calls are then resolved against
// the functions declared in that file.
//
// require resolution (the standard `package.path` convention):
//
//   - `require("a.b.c")` → dotted module name; `.` is the path separator.
//     Tried as `<root>/a/b/c.lua` and `<root>/a/b/c/init.lua`, where
//     `<root>` is the importing file's directory and the project root (and
//     a `lua/` / `src/` subdir of the root, common in LuaRocks / OpenResty
//     layouts).
//   - `require("mod")` → flat module name; `<dir>/mod.lua`,
//     `<root>/mod.lua`, `<root>/lua/mod.lua`, `<root>/src/mod.lua`.
//   - `require "mod"` (no parens) is the same call shape in tree-sitter.
//
// alias binding: `local m = require("mod")` binds alias `m`. The variable
// the result is assigned to is what later `m.method()` calls reference, so
// the resolver re-derives that binding from the file's own `local <a> =
// require(<spec>)` statements (the basename of the spec is NOT the alias
// in Lua, unlike Ruby's convention).
//
// Out of scope for this initial implementation (documented cuts):
//   - `package.loaded` / custom loaders and `package.path` rewrites.
//   - Re-export chains (`local x = require("a").sub`).
//   - C modules and LuaRocks tree resolution (`require("cjson")` →
//     extern, never searched on disk).
//
// Everything here is gated to rules.LangLua: the resolver registers only
// for LangLua and the dispatcher (resolve.go) calls GetResolver(lang),
// so no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// luaResolver implements LanguageResolver for Lua.
type luaResolver struct{}

func init() {
	RegisterResolver(&luaResolver{})
}

// Language reports that this resolver handles Lua.
func (r *luaResolver) Language() rules.Language { return rules.LangLua }

// luaManifestFilenames identify a Lua project's module root.
var luaManifestFilenames = []string{
	".luarc.json",
	".luacheckrc",
	"init.lua",
	"main.lua",
}

// luaManifestDirs are directory names that, when present, indicate a
// project root even without a manifest file (LuaRocks `lua/` tree,
// OpenResty `src/` layout).
var luaManifestDirs = []string{
	"lua",
	"src",
}

// luaExternPrefixes lists C-module / well-known library names the
// resolver treats as out-of-source — never searched on disk.
var luaExternPrefixes = []string{
	"cjson",
	"resty", // lua-resty-* libraries (resty.mysql, resty.redis, ...)
	"ngx",
	"socket", // luasocket
	"ssl",
	"lfs", // luafilesystem
	"posix",
	"lpeg",
	"luasql",
	"redis",
	"pgmoon",
	"http", // lua-http / resty.http
	"cqueues",
	"openssl",
	"bit",
	"ffi",
}

// ProjectRoot walks up from scanDir looking for a Lua project marker.
// modulePath is always empty for Lua — there is no path-prefix namespace.
func (r *luaResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range luaManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		for _, sub := range luaManifestDirs {
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
	// non-empty manifest path (mirrors the Ruby / JS last-resort).
	return abs, "", true
}

// findLuaModuleRoot walks up from a file's directory looking for the same
// markers as ProjectRoot and returns the project root directory, or "".
func findLuaModuleRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range luaManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return cur
			}
		}
		for _, sub := range luaManifestDirs {
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

// ExtractScope parses a Lua file's `require` bindings into a FileScope.
//
// Imports map shape: alias → absolute file path of the required `.lua`
// file (when resolvable on disk), or alias → bare specifier for externs.
// The alias is the local variable the require result is assigned to
// (`local m = require("mod")` → alias "m"); when require is used as a
// bare statement (`require("mod")`) the dotted basename is recorded so a
// later `mod.fn()` still resolves.
//
// scope.Package is the file's own absolute path — PackageIndex keys nodes
// by absolute file path, mirroring the JS / Ruby model.
func (r *luaResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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

	moduleRoot := findLuaModuleRoot(abs)
	if moduleRoot != "" {
		fs.Aux["module_root"] = moduleRoot
	}

	tree := tsast.Parse(content, rules.LangLua)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	root := tree.Root()
	// Top-level statements: `local m = require(...)` is a
	// variable_declaration whose value is a require function_call; a bare
	// `require(...)` is a function_call statement on its own.
	for _, stmt := range root.NamedChildren() {
		switch stmt.Type() {
		case "variable_declaration", "variable_assignment":
			collectLuaRequireBinding(stmt, abs, moduleRoot, fs.Imports)
		case "function_call":
			if spec := luaRequireSpec(stmt); spec != "" {
				bindLuaRequire(luaModuleBasename(spec), spec, abs, moduleRoot, fs.Imports)
			}
		}
	}
	return fs, nil
}

// collectLuaRequireBinding inspects a `local <a> = require(<spec>)` (or
// `<a> = require(<spec>)`) node and records the alias→target binding.
func collectLuaRequireBinding(n *tsast.Node, fileAbs, moduleRoot string, imports map[string]string) {
	alias := ""
	var valueCall *tsast.Node
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "variable_declarator":
			// In the tree-sitter-lua grammar the declarator IS the `name`
			// slot of the parent declaration; its first identifier child is
			// the bound variable. The require result is a SIBLING node
			// fielded `value` on the parent (handled by the `function_call`
			// arm below), not a child of the declarator.
			if alias == "" {
				alias = luaDeclaratorName(c)
			}
			if v := c.ChildByFieldName("value"); v != nil && v.Type() == "function_call" {
				valueCall = v
			}
		case "variable_list":
			if alias == "" {
				for _, vc := range c.NamedChildren() {
					if vc.Type() == "identifier" {
						alias = strings.TrimSpace(vc.Text())
						break
					}
				}
			}
		case "expression_list":
			if valueCall == nil {
				for _, ec := range c.NamedChildren() {
					if ec.Type() == "function_call" {
						valueCall = ec
						break
					}
				}
			}
		case "function_call":
			if c.FieldName() == "value" && valueCall == nil {
				valueCall = c
			}
		}
	}
	if valueCall == nil {
		return
	}
	spec := luaRequireSpec(valueCall)
	if spec == "" {
		return
	}
	if alias == "" {
		alias = luaModuleBasename(spec)
	}
	bindLuaRequire(alias, spec, fileAbs, moduleRoot, imports)
}

// luaDeclaratorName returns the bound variable name of a
// `variable_declarator` node: its first identifier child (or the node's
// own text when no identifier child is present).
func luaDeclaratorName(decl *tsast.Node) string {
	for _, c := range decl.NamedChildren() {
		if c.Type() == "identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return strings.TrimSpace(decl.Text())
}

// bindLuaRequire records imports[alias] = <target>, resolving the spec to
// an absolute path when possible and falling back to extern / bare spec.
func bindLuaRequire(alias, spec, fileAbs, moduleRoot string, imports map[string]string) {
	if alias == "" || spec == "" {
		return
	}
	if isLuaExternSpecifier(spec) {
		imports[alias] = spec
		return
	}
	if target := resolveLuaModuleSpecifier(spec, fileAbs, moduleRoot); target != "" {
		imports[alias] = target
		return
	}
	// Unresolved — record the bare spec so ResolveCall routes it to extern.
	imports[alias] = spec
}

// luaRequireSpec returns the string-literal module name from a
// `require(<spec>)` function_call, or "" when the call isn't a require or
// the argument isn't a string literal.
func luaRequireSpec(call *tsast.Node) string {
	if call == nil || call.Type() != "function_call" {
		return ""
	}
	// The callee must be the bare identifier `require`.
	isRequire := false
	for i := 0; i < call.ChildCount(); i++ {
		c := call.Child(i)
		if c.Type() == "identifier" {
			if strings.TrimSpace(c.Text()) == "require" {
				isRequire = true
			}
			break
		}
		// A dotted/colon callee (e.g. `pkg.require`) is not the builtin.
		if c.Type() == "dot_index_expression" {
			break
		}
	}
	if !isRequire {
		return ""
	}
	args := call.ChildByFieldName("args")
	if args == nil {
		// Grammar variants put the literal directly as a child for the
		// paren-less `require "mod"` form.
		for i := 0; i < call.ChildCount(); i++ {
			if call.Child(i).Type() == "string" {
				return luaStripStringLiteral(call.Child(i))
			}
		}
		return ""
	}
	for _, a := range args.NamedChildren() {
		if a.Type() == "string" {
			return luaStripStringLiteral(a)
		}
	}
	return ""
}

// luaStripStringLiteral returns the inner text of a Lua `string` node with
// the surrounding quotes / long-bracket markers removed.
func luaStripStringLiteral(n *tsast.Node) string {
	// Prefer a string_content child when the grammar exposes one.
	for _, c := range n.NamedChildren() {
		if c.Type() == "string_content" {
			return strings.TrimSpace(c.Text())
		}
	}
	s := strings.TrimSpace(n.Text())
	s = strings.Trim(s, `"'`)
	return s
}

// luaModuleBasename returns the last dotted segment of a module spec
// (`a.b.c` → "c"), used as a fallback alias for bare require statements.
func luaModuleBasename(spec string) string {
	s := strings.TrimSpace(spec)
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// resolveLuaModuleSpecifier resolves a dotted module spec to an absolute
// `.lua` path. `.` is the package.path separator, so `a.b.c` → `a/b/c`.
// Tries, in order, under each search root: `<rel>.lua` then
// `<rel>/init.lua`. Search roots are the importing file's directory, the
// module root, and `lua/` / `src/` subdirs of the module root.
func resolveLuaModuleSpecifier(spec, fileAbs, moduleRoot string) string {
	rel := filepath.FromSlash(strings.ReplaceAll(strings.TrimSpace(spec), ".", "/"))
	if rel == "" {
		return ""
	}
	var roots []string
	if d := filepath.Dir(fileAbs); d != "" {
		roots = append(roots, d)
	}
	if moduleRoot != "" {
		roots = append(roots,
			moduleRoot,
			filepath.Join(moduleRoot, "lua"),
			filepath.Join(moduleRoot, "src"),
		)
	}
	for _, root := range roots {
		for _, cand := range []string{
			filepath.Join(root, rel+".lua"),
			filepath.Join(root, rel, "init.lua"),
		} {
			if info, err := os.Stat(cand); err == nil && !info.IsDir() {
				if abs, err := filepath.Abs(cand); err == nil {
					return abs
				}
				return cand
			}
		}
	}
	return ""
}

// isLuaExternSpecifier reports whether spec matches a known C-module /
// library name prefix. Strict match: exact or `<prefix>.<rest>`.
func isLuaExternSpecifier(spec string) bool {
	s := strings.TrimSpace(spec)
	if s == "" {
		return false
	}
	for _, p := range luaExternPrefixes {
		if s == p || strings.HasPrefix(s, p+".") {
			return true
		}
	}
	return false
}

// ResolveCall resolves a Lua call expression to a FuncNode ID, an extern
// symbol, or "no opinion".
//
// callee is one of:
//
//	"foo"        — bare name. The same-file pass already handles local
//	               functions; cross-file we only act when `foo` is itself
//	               a require alias (rare; a module that returns a single
//	               function bound as `local foo = require("foo")`).
//
//	"m.method"   — qualified call. `m` may be a require alias bound by
//	               `local m = require("mod")`; we look up `method` (or
//	               `<table>.method`) in the target file's nodes. When `m`
//	               isn't an import alias it's a local table — out of scope.
func (r *luaResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")

	if dot < 0 {
		if target, ok := scope.Imports[callee]; ok && filepath.IsAbs(target) {
			if id, hit := resolveLuaNodeID(target, "", callee, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.7}
			}
		}
		return ResolveResult{}
	}

	alias := callee[:dot]
	rest := callee[dot+1:]
	if alias == "" || rest == "" {
		return ResolveResult{}
	}

	target, ok := scope.Imports[alias]
	if !ok {
		return ResolveResult{}
	}
	if !filepath.IsAbs(target) {
		// Extern (unresolved C-module / library specifier).
		return ResolveResult{Extern: target + "." + rest, Confidence: 0.8}
	}
	if id, hit := resolveLuaNodeID(target, alias, rest, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}
	// File is in-project but no matching function — "no opinion" so the
	// dispatcher's UnresolvedCalls filter handles it.
	return ResolveResult{}
}

// resolveLuaNodeID looks up a function named `method` (optionally with a
// module-table qualifier) inside the file `filePath` via the PackageIndex
// (keyed by absolute file path for Lua). The importing alias `m` differs
// from the module table name inside the target file (`M`), so we match on
// the method basename: a node named "M.method" or "method" both satisfy a
// `m.method` call.
func resolveLuaNodeID(filePath, alias, method string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || method == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	// `m.get_id` where the import alias `m` masks a deeper path like
	// `sub.get_id` — only the final segment is reliable across the require
	// boundary, so match the trailing method name.
	wantSuffix := method
	if i := strings.LastIndex(method, "."); i >= 0 {
		wantSuffix = method[i+1:]
	}
	// First pass: exact name match (full dotted name or bare basename) —
	// an exact hit must win over a mere ".<basename>" suffix hit so
	// first-hit order can never mis-bind (mirrors the Java / PHP
	// exact-first two-pass).
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		if fnPart == method || fnPart == wantSuffix {
			return candID, true
		}
	}
	// Second pass: any node whose name ends with ".<basename>".
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		if strings.HasSuffix(candID[colon+1:], "."+wantSuffix) {
			return candID, true
		}
	}
	return "", false
}
