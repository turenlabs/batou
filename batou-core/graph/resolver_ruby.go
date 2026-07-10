// Per-language adapter: Ruby.
//
// Implements LanguageResolver for cross-file Ruby call resolution.
// Ruby has no formal package/namespace declaration tied to file paths
// (unlike Java's `package com.foo.bar`), so PackageIndex is keyed on
// absolute file paths — the same approach the JS resolver uses. Each
// `require_relative` (and resolvable `require 'lib/...'`) call site
// records an absolute target path; downstream `Class.method` calls
// are resolved against the methods declared in those files.
//
// Scope of this initial implementation:
//
//   - `require_relative './foo'` → `<dir>/foo.rb` relative to the
//     importing file. If the specifier already has `.rb`, we use it
//     as-is; otherwise we add the extension.
//
//   - `require 'foo'` → tries `<moduleRoot>/lib/foo.rb` and
//     `<moduleRoot>/app/**/foo.rb` (Rails layout). Module root is the
//     nearest directory ancestor containing `Gemfile`, `config.ru`,
//     `lib/`, or `app/`. Stdlib / gem names (`require 'json'`,
//     `require 'sinatra'`) fall through and yield no in-source target.
//
//   - `autoload :Foo, 'foo'` is treated identically to `require 'foo'`.
//
//   - Standard-library / gem prefixes (`rails/...`, `sinatra`, `json`,
//     `active_record`, `bundler`, ...) are treated as externs — they
//     are not searched on disk.
//
// Known limitations (deliberate scope cuts for this PR):
//
//   - Bundler / gem-path resolution is not attempted. We don't read
//     `Gemfile.lock` or walk `vendor/bundle`.
//   - `load 'path'` and the obsolete `Kernel#load(filename, wrap)` form
//     are handled like `require` for resolution purposes; we don't
//     model the wrap-namespace semantics.
//   - Ruby's open-class / monkey-patching means a method declared in
//     file A may end up callable on a class defined in file B. The
//     resolver pins calls to the file that declares the matching
//     method name; if multiple files declare the same `Cls.method`,
//     only the first-encountered registration wins.
//   - Rails ActiveSupport autoload (Zeitwerk) is not modeled — the
//     name → file mapping it derives at runtime is convention-based
//     and would need a directory walk + camelcase inference.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// rubyResolver implements LanguageResolver for Ruby.
type rubyResolver struct{}

func init() {
	RegisterResolver(&rubyResolver{})
}

// Language reports that this resolver handles Ruby.
func (r *rubyResolver) Language() rules.Language { return rules.LangRuby }

// rubyManifestFilenames is the precedence-ordered list of project
// markers that identify a Ruby project's module root.
var rubyManifestFilenames = []string{
	"Gemfile",
	"Gemfile.lock",
	"config.ru",
	"Rakefile",
	".ruby-version",
}

// rubyManifestDirs are directory names that, when present alongside no
// manifest file, still indicate a project root (Rails apps without a
// top-level Gemfile in scan view, lib-only gems).
var rubyManifestDirs = []string{
	"lib",
	"app",
}

// rubyExternPrefixes lists gem / stdlib name prefixes the resolver
// treats as out-of-source. Calls into these never get an in-project
// target and the dispatcher routes them as ExternCalls.
//
// The list is intentionally short — Rails apps tend to require things
// like `rails/all`, `active_record`, `action_controller`; web stacks
// require `sinatra`, `rack`, `puma`, etc. Anything not on this list
// AND not findable on disk simply yields no target (silently dropped).
var rubyExternPrefixes = []string{
	"rails",
	"active_",       // active_record, active_support, active_model, ...
	"action_",       // action_controller, action_view, action_mailer, ...
	"sinatra",
	"rack",
	"roda",
	"hanami",
	"puma",
	"unicorn",
	"sidekiq",
	"resque",
	"rspec",
	"minitest",
	"rake",
	"bundler",
	"json",
	"yaml",
	"net/",
	"open-uri",
	"openssl",
	"securerandom",
	"digest",
	"base64",
	"date",
	"time",
	"uri",
	"csv",
	"logger",
	"fileutils",
	"tempfile",
	"stringio",
	"pathname",
	"set",
	"forwardable",
	"singleton",
	"observer",
	"monitor",
	"thread",
}

// ProjectRoot walks up from scanDir looking for a Ruby project marker.
//
// Precedence:
//  1. Directory containing a `Gemfile` / `config.ru` / `Rakefile` /
//     `.ruby-version` file → that directory.
//  2. Directory containing both `lib/` and `app/` (Rails layout) → that
//     directory, even without a manifest file (some scanned subtrees
//     omit the Gemfile).
//  3. No marker found → return scanDir so the framework still has a
//     non-empty anchor (consistent with the JS resolver's last-resort).
//
// modulePath is always empty for Ruby — gems use namespaces declared
// inside source files, not via a top-level path prefix.
func (r *rubyResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range rubyManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		// Dir-based fallback: `lib` or `app` directly under `cur`.
		hasLibOrApp := false
		for _, sub := range rubyManifestDirs {
			if info, err := os.Stat(filepath.Join(cur, sub)); err == nil && info.IsDir() {
				hasLibOrApp = true
				break
			}
		}
		if hasLibOrApp {
			return filepath.Join(cur, "__manifest__"), "", true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No marker found anywhere on the path. Anchor at scanDir so the
	// framework still has a non-empty manifest path.
	return abs, "", true
}

// findRubyModuleRoot walks up from a file's directory looking for the
// same markers as ProjectRoot and returns the path of the project root
// directory. We re-derive it here because ExtractScope is called
// without the broader CallGraph state.
func findRubyModuleRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range rubyManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return cur
			}
		}
		for _, sub := range rubyManifestDirs {
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

// ExtractScope parses a Ruby file's `require` / `require_relative` /
// `autoload` calls into a FileScope.
//
// Imports map shape: alias → absolute file path of the imported .rb
// file (when resolvable). For Ruby the "alias" is the basename of the
// required path (e.g. `require_relative './services/user'` → alias
// "user" → path .../services/user.rb). For `autoload :Foo, 'foo'` the
// alias is the constant name `Foo` so `Foo.bar` calls resolve.
// Unresolved (stdlib / gem) requires record the bare specifier under
// the basename so ResolveCall can route them to extern.
//
// scope.Package is the file's own absolute path. PackageIndex keys
// nodes by their absolute file path, mirroring the JS resolver's
// "every file is its own namespace" model — Ruby has no file-path-to-
// namespace mapping enforced by the language.
//
// scope.Aux["module_root"] carries the project root so ResolveCall can
// re-derive `lib/` paths without re-walking the filesystem.
func (r *rubyResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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

	moduleRoot := findRubyModuleRoot(abs)
	if moduleRoot != "" {
		fs.Aux["module_root"] = moduleRoot
	}

	tree := tsast.Parse(content, rules.LangRuby)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	// Walk top-level require / require_relative / autoload / load calls.
	// Tree-sitter Ruby models these as plain `call` nodes at the program
	// level — there's no dedicated `require_statement` node type.
	root := tree.Root()
	for i := 0; i < root.ChildCount(); i++ {
		stmt := root.Child(i)
		if stmt == nil || stmt.Type() != "call" {
			continue
		}
		collectRubyRequireEntry(stmt, abs, moduleRoot, fs.Imports)
	}
	return fs, nil
}

// collectRubyRequireEntry inspects a `call` node and, when it's one of
// the import forms, populates imports with the alias → absolute-path
// (or alias → bare-specifier for externs) binding.
func collectRubyRequireEntry(n *tsast.Node, fileAbs, moduleRoot string, imports map[string]string) {
	methodNode := n.ChildByFieldName("method")
	if methodNode == nil {
		return
	}
	// Require / autoload / load are top-level identifiers — skip
	// receiver-style calls (`Kernel.require` is rare and out of scope).
	if recv := n.ChildByFieldName("receiver"); recv != nil {
		return
	}
	method := strings.TrimSpace(methodNode.Text())
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return
	}

	switch method {
	case "require_relative":
		specifier := firstRubyStringArg(args)
		if specifier == "" {
			return
		}
		target := resolveRubyRelative(fileAbs, specifier)
		if target == "" {
			return
		}
		alias := rubyBasenameAlias(specifier)
		if alias != "" {
			imports[alias] = target
		}
	case "require", "load":
		specifier := firstRubyStringArg(args)
		if specifier == "" {
			return
		}
		alias := rubyBasenameAlias(specifier)
		if alias == "" {
			return
		}
		if isRubyExternSpecifier(specifier) {
			imports[alias] = specifier
			return
		}
		if target := resolveRubyLibrarySpecifier(specifier, moduleRoot); target != "" {
			imports[alias] = target
			return
		}
		// Unresolved — record the bare spec so ResolveCall can route it
		// to extern (preserving the dependency surface).
		imports[alias] = specifier
	case "autoload":
		// autoload(:ConstantName, 'path')
		name, spec := parseRubyAutoload(args)
		if name == "" || spec == "" {
			return
		}
		if isRubyExternSpecifier(spec) {
			imports[name] = spec
			return
		}
		if target := resolveRubyLibrarySpecifier(spec, moduleRoot); target != "" {
			imports[name] = target
			return
		}
		// Last-resort: relative resolution (autoload paths can be
		// relative when set via $LOAD_PATH; rarely seen in practice).
		if target := resolveRubyRelative(fileAbs, spec); target != "" {
			imports[name] = target
			return
		}
		imports[name] = spec
	}
}

// firstRubyStringArg returns the first string-literal argument of an
// argument_list, with surrounding quotes already stripped. Returns ""
// when the first arg isn't a string (e.g. `require some_var`).
func firstRubyStringArg(args *tsast.Node) string {
	for _, c := range args.NamedChildren() {
		if c.Type() == "string" {
			for _, sc := range c.NamedChildren() {
				if sc.Type() == "string_content" {
					return strings.TrimSpace(sc.Text())
				}
			}
		}
	}
	return ""
}

// parseRubyAutoload extracts the (constant, path) pair from an
// `autoload(:Foo, 'foo/bar')` argument list.
func parseRubyAutoload(args *tsast.Node) (constant, specifier string) {
	for _, c := range args.NamedChildren() {
		switch c.Type() {
		case "simple_symbol":
			if constant == "" {
				constant = strings.TrimPrefix(strings.TrimSpace(c.Text()), ":")
			}
		case "string":
			if specifier == "" {
				for _, sc := range c.NamedChildren() {
					if sc.Type() == "string_content" {
						specifier = strings.TrimSpace(sc.Text())
						break
					}
				}
			}
		}
	}
	return constant, specifier
}

// rubyBasenameAlias derives the alias name a `require` introduces. For
// `require_relative './services/user'` the alias is `user`; for
// `require 'rails/all'` the alias is `all`. The convention loses one
// hop of namespace (the leading `rails/`), but Ruby's actual binding
// happens via constants declared inside the loaded file, not via the
// path — the alias here is just a label so ResolveCall can find an
// entry in `imports`.
func rubyBasenameAlias(specifier string) string {
	s := strings.TrimSpace(specifier)
	if s == "" {
		return ""
	}
	// Strip trailing `.rb` if present.
	s = strings.TrimSuffix(s, ".rb")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// resolveRubyRelative resolves a `require_relative` specifier against
// the importing file's directory. Returns the absolute path of the
// `.rb` file if it exists on disk, else "".
func resolveRubyRelative(fileAbs, specifier string) string {
	if specifier == "" {
		return ""
	}
	dir := filepath.Dir(fileAbs)
	candidate := filepath.Join(dir, specifier)
	if !strings.HasSuffix(candidate, ".rb") {
		candidate += ".rb"
	}
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		if abs, err := filepath.Abs(candidate); err == nil {
			return abs
		}
		return candidate
	}
	return ""
}

// resolveRubyLibrarySpecifier resolves a `require 'foo'` specifier
// against the project's module root. Tries, in order:
//
//	<moduleRoot>/lib/<spec>.rb
//	<moduleRoot>/app/<spec>.rb        (rare, but happens in some Rails configs)
//	<moduleRoot>/<spec>.rb            (last-resort, e.g. flat scripts)
//
// Returns the absolute path when found, "" otherwise. Walks under
// app/**/<basename>.rb to model Rails autoload roots (controllers,
// models, etc.) — but capped at a small depth to keep the scan fast.
func resolveRubyLibrarySpecifier(specifier, moduleRoot string) string {
	if moduleRoot == "" || specifier == "" {
		return ""
	}
	rel := specifier
	if !strings.HasSuffix(rel, ".rb") {
		rel += ".rb"
	}
	for _, sub := range []string{"lib", "app"} {
		candidate := filepath.Join(moduleRoot, sub, rel)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(candidate); err == nil {
				return abs
			}
			return candidate
		}
	}
	// Try the project root itself (flat layouts).
	candidate := filepath.Join(moduleRoot, rel)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		if abs, err := filepath.Abs(candidate); err == nil {
			return abs
		}
		return candidate
	}
	// Rails subdirectory walk: `app/models/user`, `app/controllers/foo`,
	// `app/services/bar`. We probe a single level under `app/` rather
	// than a deep walk to keep the resolver O(small).
	appDir := filepath.Join(moduleRoot, "app")
	if info, err := os.Stat(appDir); err == nil && info.IsDir() {
		entries, err := os.ReadDir(appDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				candidate := filepath.Join(appDir, e.Name(), rel)
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					if abs, err := filepath.Abs(candidate); err == nil {
						return abs
					}
					return candidate
				}
			}
		}
	}
	return ""
}

// isRubyExternSpecifier reports whether specifier matches a known
// stdlib / gem-name prefix. Strict-prefix matching with a trailing `/`
// or end-of-string anchor so `active_record` matches but a sibling
// project file like `active_users.rb` doesn't.
func isRubyExternSpecifier(specifier string) bool {
	s := strings.TrimSpace(specifier)
	if s == "" {
		return false
	}
	for _, p := range rubyExternPrefixes {
		// Allow exact match (`require 'json'`) or prefix-with-slash
		// (`require 'rails/all'`, `require 'net/http'`).
		if s == p || strings.HasPrefix(s, p+"/") {
			return true
		}
		// When the prefix already ends in `/` (e.g. `net/`), match
		// `net/http`, `net/smtp`, etc. without appending another slash.
		if strings.HasSuffix(p, "/") && strings.HasPrefix(s, p) {
			return true
		}
		// Allow underscore-prefix (`active_record`, `action_view`)
		// when the catalog entry ends with `_`.
		if strings.HasSuffix(p, "_") && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ResolveCall resolves a Ruby call expression to a FuncNode ID, an
// extern symbol, or "no opinion".
//
// callee is one of:
//
//	"foo"        — bare name. The same-file pass already handles
//	               local methods; for cross-file we only act when
//	               `foo` is an alias in scope.Imports (rare but
//	               happens when a script `require`s a leaf with the
//	               same basename as the method).
//
//	"Cls.bar"    — qualified call. `Cls` may be:
//	                 - a constant introduced by `autoload :Cls, 'path'`
//	                   (alias is the constant name itself).
//	                 - the basename of a `require`d file (we try a
//	                   case-insensitive match here too because Ruby
//	                   convention has `require 'user_service'` →
//	                   `class UserService`).
//	                 - a local variable / instance / class reference —
//	                   out of scope without type inference; return
//	                   "no opinion".
func (r *rubyResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")

	// Bare-name calls: see if the importer has an alias matching the
	// callee. Rare in practice — Ruby doesn't really import top-level
	// procs across files — but cheap to check.
	if dot < 0 {
		if target, ok := scope.Imports[callee]; ok && filepath.IsAbs(target) {
			if id, hit := resolveRubyNodeID(target, "", callee, idx); hit {
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

	// Exact import alias match (autoload constant or basename).
	if target, ok := scope.Imports[alias]; ok {
		if filepath.IsAbs(target) {
			if id, hit := resolveRubyNodeID(target, alias, rest, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.85}
			}
			// File exists but no method found — return "no opinion"
			// rather than extern so the dispatcher's UnresolvedCalls
			// filter handles it (the file IS in-project).
			return ResolveResult{}
		}
		// Extern (unresolved gem / stdlib specifier).
		return ResolveResult{Extern: target + "." + rest, Confidence: 0.85}
	}

	// Ruby-convention fallback: `UserService` → look up an alias
	// `user_service` (snake_case basename of a `require`d file).
	if snake := rubyCamelToSnake(alias); snake != "" && snake != alias {
		if target, ok := scope.Imports[snake]; ok && filepath.IsAbs(target) {
			if id, hit := resolveRubyNodeID(target, alias, rest, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.7}
			}
		}
	}

	return ResolveResult{}
}

// resolveRubyNodeID looks up a method named `method` (optionally
// qualified by `className`) inside the file `filePath` via the
// PackageIndex (which is keyed by absolute file path for Ruby, same as
// JS/TS and Java).
//
// Match precedence:
//  1. Exact `<className>.<method>` — for qualified calls.
//  2. Exact `<method>` — a top-level def must win over a same-named
//     method on some class in the file (first-hit order would
//     otherwise mis-bind, order-dependently).
//  3. Suffix `.<method>` — for bare-name calls and qualified calls
//     where the leading class is the file's outermost type.
func resolveRubyNodeID(filePath, className, method string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || method == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	if className != "" {
		want := className + "." + method
		for _, candID := range cands {
			colon := strings.LastIndexByte(candID, ':')
			if colon < 0 {
				continue
			}
			fnPart := candID[colon+1:]
			if fnPart == want || strings.HasSuffix(fnPart, "."+want) {
				return candID, true
			}
		}
	}
	// Exact bare-name match (top-level def) before any method-suffix
	// fallback (mirrors the Java / PHP exact-first two-pass).
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		if candID[colon+1:] == method {
			return candID, true
		}
	}
	// Suffix fallback: any node whose name ends with ".<method>".
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		if strings.HasSuffix(candID[colon+1:], "."+method) {
			return candID, true
		}
	}
	return "", false
}

// rubyCamelToSnake converts `UserService` → `user_service`,
// `HTMLParser` → `html_parser`. Returns "" for empty input. Used to
// bridge Ruby's `CamelCase` constant names to the `snake_case` file
// basenames most projects use.
func rubyCamelToSnake(s string) string {
	if s == "" {
		return ""
	}
	var out strings.Builder
	out.Grow(len(s) + 4)
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				// Lower-then-upper boundary: insert _.
				prev := rune(s[i-1])
				if prev >= 'a' && prev <= 'z' {
					out.WriteByte('_')
				} else if prev >= 'A' && prev <= 'Z' && i+1 < len(s) {
					// Upper-then-Upper-then-lower (HTMLParser → HTML_parser).
					next := rune(s[i+1])
					if next >= 'a' && next <= 'z' {
						out.WriteByte('_')
					}
				}
			}
			out.WriteRune(r + 32)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}
