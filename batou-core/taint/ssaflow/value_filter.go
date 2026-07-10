package ssaflow

import (
	"strings"

	"golang.org/x/tools/go/ssa"
)

// stdlibGlobalPathPrefixes lists pkg paths whose package-level globals are
// safe to exclude from taint propagation. These packages export read-only
// constants/sentinels (HTTP status codes, well-known errors, std streams)
// that can never carry user-controlled data. Treating them as taint roots
// or letting taint propagate through their reads inflates findings without
// representing real cross-trust-boundary flows.
//
// The list is intentionally small and conservative: we only block packages
// whose globals are well-known to be inert. Domain-specific globals (e.g.
// app-defined config singletons) are still walked normally — they are not
// constants and a real flow through them is plausible.
var stdlibGlobalPathPrefixes = []string{
	"net/http",
	"crypto/",
	"crypto",
	"runtime/",
	"runtime",
	"os",       // os.Stdin, os.Stdout, os.Stderr, os.Args (Args is mutable but stays out of scope)
	"io",       // io.EOF and friends
	"errors",   // errors.New constants captured in vars
	"syscall",  // SIGTERM etc.
	"unicode/", // unicode.RangeTable globals
	"unicode",
	"time", // time.UTC, time.Local
}

// isUntaintableSSAValue reports whether v is an SSA value that, by
// construction, cannot carry user-controlled data. Two shapes qualify:
//
//  1. *ssa.Const — every constant (integers, strings, untyped nil, bool
//     literals). Constants are emitted by the SSA builder for source-level
//     literals like `http.StatusBadRequest`, `""`, `nil`, `7`. Treating any
//     of them as a taint root or letting the walker step into them
//     produces FPs (e.g. http.Error's status-code arg surfacing as a
//     "source").
//
//  2. *ssa.Global from a stdlib package whose globals are known-inert
//     (see stdlibGlobalPathPrefixes). These cover stdin/stdout streams,
//     pre-declared error sentinels, status code names exposed as vars,
//     etc. App-defined globals (custom config singletons) are still
//     walked so a real "tainted assignment to a global" pattern is not
//     hidden — only stdlib globals are skipped.
//
// Used by every backward walker in this package (reaches, reachesAnyParam,
// reachesAnyParamSource, reachesWithPointer). A walker that sees an
// untaintable value treats it as a terminal node: not a hit, not a node
// to recurse into.
func isUntaintableSSAValue(v ssa.Value) bool {
	if v == nil {
		return false
	}
	if _, ok := v.(*ssa.Const); ok {
		return true
	}
	if g, ok := v.(*ssa.Global); ok {
		return isStdlibGlobal(g)
	}
	return false
}

// isStdlibGlobal returns true when g lives in a package whose globals are
// known to be inert constants/sentinels. We compare by package path rather
// than the (often-empty) Object().Pkg() name because SSA globals carry the
// full package path via their parent ssa.Package.
func isStdlibGlobal(g *ssa.Global) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
		return false
	}
	path := g.Pkg.Pkg.Path()
	for _, pfx := range stdlibGlobalPathPrefixes {
		// Exact-match or prefix-match for sub-packages (e.g. "crypto/sha256").
		if path == pfx {
			return true
		}
		if strings.HasSuffix(pfx, "/") && strings.HasPrefix(path, pfx) {
			return true
		}
	}
	return false
}
