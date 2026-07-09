// Path-based file classification helpers for the `batou scan` JSONL output.
//
// These are intentionally conservative — a false positive on isDocsFile or
// isGeneratedOrVendor causes a triager to filter out real findings, which
// is worse than filtering out a docs/vendor finding manually. Patterns
// here are the obvious-on-sight ones (extensions, well-known directory
// names, well-known lockfile basenames). Anything fuzzier belongs in a
// follow-up after we have a calibration set.
//
// isTestFile delegates to fpfilter.IsTestFile so we share the same heuristic
// with the scanner's test-file confidence cap (see scanner.go).
package dirscan

import (
	"path/filepath"
	"strings"

	"github.com/turenlabs/batou-core/fpfilter"
)

// isTestFile mirrors fpfilter.IsTestFile (the same heuristic the scanner
// uses to cap confidence on test code). Keep this thin wrapper so the
// JSONL output stays in sync with internal classifications.
func isTestFile(path string) bool {
	return fpfilter.IsTestFile(path)
}

// isInfraFile mirrors fpfilter.IsInfraFile — DB migrations, build tooling,
// and code generators. Same role as isTestFile (caps confidence at 0.3 and
// downgrades severity) but tagged separately so triagers can distinguish
// "intentional pattern in a test" from "intentional pattern in scaffolding".
func isInfraFile(path string) bool {
	return fpfilter.IsInfraFile(path)
}

// docsDirSegments are case-insensitive directory substrings that mark a
// path as documentation. Kept short on purpose: a real source file under
// `src/docs_generator/` should NOT be flagged docs, so we anchor on
// segment boundaries (leading + trailing slash).
var docsDirSegments = []string{
	"/docs/",
	"/doc/",
	"/site/",
}

// docsFileExtensions are file extensions that are unambiguously docs.
// Markdown, reStructuredText, AsciiDoc.
var docsFileExtensions = []string{
	".md",
	".markdown",
	".rst",
	".adoc",
	".asciidoc",
}

// isDocsFile returns true when the path looks like documentation rather
// than executable code. Conservative — only matches obvious doc paths so
// a real .go/.py file with "doc" in its name doesn't get filtered out.
func isDocsFile(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower("/" + filepath.ToSlash(path))

	for _, seg := range docsDirSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	ext := filepath.Ext(lower)
	for _, e := range docsFileExtensions {
		if ext == e {
			return true
		}
	}
	return false
}

// vendorDirSegments are case-insensitive directory substrings that mark a
// path as third-party / generated / vendored code. Anchored on slashes so
// `src/vendoring_logic/` does not match.
var vendorDirSegments = []string{
	"/vendor/",
	"/node_modules/",
	"/__generated__/",
	"/third_party/",
	"/3rdparty/",
	"/bower_components/",
	"/.yarn/",
	"/.pnpm/",
	// Bundled front-end libraries. Conventional web-asset layouts drop
	// third-party JS/CSS under a dedicated directory that is NOT the app's
	// own source. These segments are high-precision: apps put their own code
	// under js/app/, js/src/, js/components/ — never js/lib/ or js/vendor/.
	// (firefly-iii ships jQuery plugins at public/vN/js/lib/... — a bundled
	// typeahead.jquery.js there was wrongly triaged as first-party.) A bare
	// /lib/ is deliberately NOT matched: many apps keep real code there.
	"/js/lib/",
	"/js/vendor/",
	"/assets/vendor/",
	"/static/vendor/",
	// Composer's generated autoloader runtime. The canonical layout is
	// `vendor/composer/` (already matched by /vendor/), but apps that ship a
	// per-component autoloader place it at `<component>/composer/composer/`
	// (Nextcloud puts one under every apps/<app>/composer/composer/ and under
	// lib/composer/composer/). Every file under this doubled segment is a
	// Composer-generated artifact — ClassLoader.php, InstalledVersions.php,
	// autoload_*.php, installed.php, platform_check.php — never the app's own
	// code, so the doubled segment is a precise vendor marker. Anchored on
	// both slashes so a directory literally named `composer/composer` is
	// required (a file like `composer/composer.json` is NOT matched, nor is a
	// single `/composer/` dir that holds a project's own composer.json).
	"/composer/composer/",
}

// generatedFileSuffixes are file-suffix patterns that mark a single file
// as machine-generated or minified. ".generated." is a substring match
// because the conventional layout is `foo.generated.ts` etc.
var generatedFileSuffixes = []string{
	".min.js",
	".min.css",
	".bundle.js",
	".pb.go",     // protoc-gen-go output
	"_pb.go",     // alternative protoc-gen-go convention
	"_pb2.py",    // protoc Python output (CWE-derived)
	"_pb2_grpc.py",
	".pb.cc",
	".pb.h",
	"_generated.go", // common stutter for generated Go
	".g.dart",
	".freezed.dart",
}

// generatedFileSubstrings catches conventional generated-file infixes.
var generatedFileSubstrings = []string{
	".generated.",
	"-generated.",
}

// lockFiles are exact basenames of dependency-manifest lockfiles. These
// are never hand-edited, so any finding on them is noise.
var lockFiles = map[string]struct{}{
	"package-lock.json":    {},
	"yarn.lock":            {},
	"pnpm-lock.yaml":       {},
	"go.sum":               {},
	"cargo.lock":           {},
	"composer.lock":        {},
	"composer.phar":        {},
	"gemfile.lock":         {},
	"poetry.lock":          {},
	"pipfile.lock":         {},
	"flake.lock":           {},
	"shrinkwrap.yaml":      {},
	"npm-shrinkwrap.json":  {},
	"mix.lock":             {},
}

// isGeneratedOrVendor returns true when the path lives under a vendored /
// generated directory, has a generated-file suffix, or is a well-known
// dependency lockfile basename. Conservative on purpose — see file header.
func isGeneratedOrVendor(path string) bool {
	if path == "" {
		return false
	}
	slashed := filepath.ToSlash(path)
	lower := strings.ToLower("/" + slashed)

	for _, seg := range vendorDirSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	for _, suf := range generatedFileSuffixes {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	for _, sub := range generatedFileSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(slashed))
	if _, ok := lockFiles[base]; ok {
		return true
	}
	return false
}
