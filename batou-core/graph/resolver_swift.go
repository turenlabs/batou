// Per-language adapter: Swift (PR-Gswift).
//
// Implements LanguageResolver for cross-file Swift call resolution. Swift
// is the SIMPLEST of all the ports: within one Swift module every
// top-level func and every method on a struct/class/enum/extension is
// visible across ALL files BY BARE NAME — `import X` is MODULE-level
// only, never per-symbol. There is no alias→file binding to track (unlike
// JS / Lua / Ruby / PHP).
//
// So cross-file resolution = bare-symbol lookup across the union of all
// Swift nodes:
//
//   - PackageIndex keys ALL Swift nodes under ONE shared bucket. The
//     importPathForNode case in resolve.go returns the CONSTANT
//     "swift::module" for every Swift node, so every node lands in the
//     same index bucket. v1 treats the whole scan dir as one module
//     (correct for single-target apps).
//   - ExtractScope is trivial: set FilePath + Package = "swift::module".
//     `import` lines are module-level and need no per-symbol bookkeeping.
//   - ResolveCall takes the call's bare suffix (strips any receiver) and
//     returns the first Swift node whose name basename matches. Both
//     `getName` and `Foo.getName` node names satisfy a `getName` call.
//
// Out of scope for v1 (documented cuts):
//   - Multi-SPM-target boundaries (the whole scan dir is one module).
//   - Protocol-witness / dynamic dispatch.
//   - Access-control visibility (over-resolves slightly — all ports do).
//
// Everything here is gated to rules.LangSwift: the resolver registers
// only for LangSwift and the dispatcher (resolve.go) calls
// GetResolver(lang), so no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// swiftModuleBucket is the single PackageIndex key under which every
// Swift node is registered. Must match the constant returned by
// importPathForNode's `case rules.LangSwift` arm in resolve.go.
const swiftModuleBucket = "swift::module"

// swiftResolver implements LanguageResolver for Swift.
type swiftResolver struct{}

func init() {
	RegisterResolver(&swiftResolver{})
}

// Language reports that this resolver handles Swift.
func (r *swiftResolver) Language() rules.Language { return rules.LangSwift }

// swiftManifestFilenames identify a Swift package / module root.
var swiftManifestFilenames = []string{
	"Package.swift",
}

// ProjectRoot walks up from scanDir looking for a Package.swift. The
// module path is always empty for Swift — every node keys under the
// single shared "swift::module" bucket, not a path-derived namespace.
func (r *swiftResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range swiftManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No manifest found — anchor at scanDir so the framework still has a
	// non-empty manifest path (mirrors the Lua last-resort).
	return abs, "", true
}

// ExtractScope produces a trivial FileScope for a Swift file: the file's
// absolute path plus the constant "swift::module" Package so PackageIndex
// keys every Swift node under one bucket. Swift `import` declarations are
// module-level and introduce no per-symbol aliases, so there is nothing
// to parse here.
func (r *swiftResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	abs := filePath
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(filePath); err == nil {
			abs = a
		}
	}
	return FileScope{
		FilePath: abs,
		Package:  swiftModuleBucket,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}, nil
}

// ResolveCall resolves a Swift call expression to a FuncNode ID by bare-
// suffix lookup across the single shared module bucket.
//
// callee is one of:
//
//	"foo"        — bare name. Resolved against every Swift node's name
//	               basename.
//	"obj.method" — qualified call. The receiver (`obj`) is a runtime value
//	               in Swift (an instance, not an import alias), so only the
//	               trailing method name is used for resolution.
//
// Same-file calls are already wired by the builder; this fires for the
// cross-file case where the callee lives in another file of the same
// module.
func (r *swiftResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" || idx == nil {
		return ResolveResult{}
	}
	wantSuffix := callee
	if i := strings.LastIndex(callee, "."); i >= 0 {
		wantSuffix = callee[i+1:]
	}
	if wantSuffix == "" {
		return ResolveResult{}
	}
	if id, ok := resolveSwiftNodeID(wantSuffix, scope.FilePath, idx); ok {
		return ResolveResult{TargetID: id, Confidence: 0.8}
	}
	return ResolveResult{}
}

// resolveSwiftNodeID looks up a function whose name basename equals
// `wantSuffix` across the single "swift::module" PackageIndex bucket. A
// node named "Foo.getName" or "getName" both satisfy a `getName` call.
//
// The bucket spans EVERY Swift file in the scan dir, so a popular method
// name can match many candidates. Precedence keeps that ambiguity from
// mis-binding order-dependently:
//  1. EXACT name match ("getName") beats a dotted-suffix match
//     ("Foo.getName") — mirrors the Java / PHP exact-first two-pass.
//  2. Among several exact matches, prefer one whose file lives in the
//     SAME DIRECTORY as the caller (callerPath) — the nearest-scope
//     candidate is the likeliest target within one module.
//  3. Still ambiguous (multiple exact matches, none same-dir) → first
//     candidate in bucket order, the pre-existing behaviour. We never
//     drop resolution outright (that would lose recall); Swift v1
//     deliberately over-resolves and the sink/sanitizer two-sided gate
//     suppresses spurious pairs.
func resolveSwiftNodeID(wantSuffix, callerPath string, idx *PackageIndex) (string, bool) {
	if idx == nil || wantSuffix == "" {
		return "", false
	}
	callerDir := ""
	if callerPath != "" {
		callerDir = filepath.Dir(callerPath)
	}
	cands := idx.Lookup(swiftModuleBucket)
	var firstExact, firstSuffix string
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		switch {
		case fnPart == wantSuffix:
			// Same-directory exact match: strongest — return at once.
			if callerDir != "" && filepath.Dir(candID[:colon]) == callerDir {
				return candID, true
			}
			if firstExact == "" {
				firstExact = candID
			}
		case strings.HasSuffix(fnPart, "."+wantSuffix):
			if firstSuffix == "" {
				firstSuffix = candID
			}
		}
	}
	if firstExact != "" {
		return firstExact, true
	}
	if firstSuffix != "" {
		return firstSuffix, true
	}
	return "", false
}
