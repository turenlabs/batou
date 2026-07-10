package crypto

import (
	"strings"
	"testing"
)

// reflexiveCompareUngated is the pre-gate reference implementation of
// isReflexiveCompare: it always runs the (backtracking) regex. The OR-set
// pre-gate added to isReflexiveCompare must produce an identical result for
// every line — that is the finding-preserving correctness invariant.
func reflexiveCompareUngated(line string) bool {
	for _, m := range reTimingEqOperands.FindAllStringSubmatch(line, -1) {
		if m[1] != "" && m[1] == m[2] {
			return true
		}
	}
	return false
}

// TestReflexiveCompareGateInvariant asserts the OR-set pre-gate in
// isReflexiveCompare never changes the result versus the ungated reference.
func TestReflexiveCompareGateInvariant(t *testing.T) {
	lines := []string{
		// Reflexive comparisons (gate must NOT skip these).
		"token === token",
		"if (a.id === a.id) {",
		"return secret == secret",
		"hash != hash",
		"x !== x",
		// Non-reflexive comparisons (gate runs regex, result false).
		"if password == secret {",
		"a === b",
		"foo != bar",
		// No comparison operator at all (gate proves no match → skip).
		"const x = foo.bar(baz)",
		"return nil",
		"register(thing)",
		"x = y",                 // single = only: cannot match [!=]==?
		"value := compute(args)", // Go assignment, no ==/!=
		"",
		"   ",
		// Mixed: assignment plus a comparison elsewhere.
		"y = a === a",
		// Unicode / non-ASCII line with a comparison.
		"naïve === naïve",
	}
	for _, line := range lines {
		want := reflexiveCompareUngated(line)
		got := isReflexiveCompare(line)
		if got != want {
			t.Errorf("isReflexiveCompare(%q) = %v, ungated = %v (gate dropped/added a result)", line, got, want)
		}
		// Defensive: if the gate skipped (no ==/!=), the ungated form must agree it is false.
		if !strings.Contains(line, "==") && !strings.Contains(line, "!=") && want {
			t.Errorf("ungated reference matched %q despite no ==/!= — gate assumption is unsound", line)
		}
	}
}
