package tsflow

// Exported access-path helpers (PR3: cross-file field-sensitivity).
//
// The cross-file taint walker in package graph needs the SAME bounded
// access-path abstraction the per-file tsflow engine uses, so that a
// field path recorded on one side of a call boundary (e.g. the sink
// reads `opts.cmd`) composes consistently with the caller's intra-file
// per-field taint (`o.cmd = req.body.cmd`). Rather than reinvent the
// machinery, these thin exported wrappers expose the existing
// boundAccessPath / isFieldKey logic and a standalone proper-prefix
// walk that mirrors taintMap.prefixTainted's read-side semantics.
//
// Keeping them here (next to the unexported originals) guarantees the
// bound (maxAccessPathDepth) and the prefix-walk rules stay in lockstep:
// if the per-file abstraction changes, the cross-file composition follows
// automatically.

// MaxAccessPathDepth is the exported bound on tracked field segments after
// the root identifier of an access path. Mirrors maxAccessPathDepth.
const MaxAccessPathDepth = maxAccessPathDepth

// BoundAccessPath truncates a dotted access path to root +
// MaxAccessPathDepth field segments. Exported wrapper around
// boundAccessPath so package graph can bound cross-file field paths
// with the identical rule the per-file engine uses.
//
//	BoundAccessPath("req.body.user.id")     == "req.body.user"
//	BoundAccessPath("req.body.user.id.sub") == "req.body.user"
//	BoundAccessPath("o.cmd")                == "o.cmd"
func BoundAccessPath(path string) string {
	return boundAccessPath(path)
}

// IsFieldKey reports whether key looks like a shallow field access
// `<base>.<field>` and returns the base identifier when so. Exported
// wrapper around isFieldKey.
func IsFieldKey(key string) (base string, ok bool) {
	return isFieldKey(key)
}

// PrefixTaintedPath reports whether reading the access path `path` should
// be considered tainted given the set of tainted access paths in
// `taintedPaths` (keys are bounded access paths recorded as tainted).
//
// This is the standalone, map-backed dual of taintMap.prefixTainted: a
// read of `path` is tainted if ANY proper prefix of `path` (including
// `path` itself, down to the bare root identifier) is present in
// taintedPaths. Tainting `o.cmd` taints reads of `o.cmd`, `o.cmd.x`, …
// but NOT the sibling `o.other` — exactly the field-sensitivity the
// per-file engine provides, lifted to the cross-file composition.
//
// Callers should bound both the seeded keys and the query path with
// BoundAccessPath so a deep read matches a collapsed seeded prefix.
func PrefixTaintedPath(path string, taintedPaths map[string]bool) bool {
	if len(taintedPaths) == 0 {
		return false
	}
	p := path
	for {
		if taintedPaths[p] {
			return true
		}
		dot := lastIndexByte(p, '.')
		if dot <= 0 {
			return false
		}
		p = p[:dot]
	}
}

// lastIndexByte is a tiny local helper (avoids importing strings here just
// for one call; keeps this export file dependency-free).
func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
