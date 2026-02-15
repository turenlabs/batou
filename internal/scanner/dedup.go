package scanner

import (
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// Priority tiers for finding classification. Higher values win during
// deduplication when two findings share the same (LineNumber, CWE) key.
const (
	tierRegex           = 10
	tierInterprocedural = 20
	tierAST             = 30
	tierTaint           = 40
)

// DeduplicateFindings groups findings by (LineNumber, CWE) and keeps one
// winner per group.
//
// Priority tiers: taint (40) > AST (30) > interprocedural (20) > regex (10).
// Tiebreakers within a tier: higher severity first, then higher confidence.
// Suppressed findings' tags are merged into the winner so no context is lost.
// Findings without a CWE or line number are never deduplicated.
func DeduplicateFindings(findings []rules.Finding) []rules.Finding {
	if len(findings) <= 1 {
		return findings
	}

	type groupKey struct {
		Line int
		CWE  string
	}

	type group struct {
		winnerIdx int
		members   []int
	}

	groups := make(map[groupKey]*group)
	order := make([]groupKey, 0)

	for i, f := range findings {
		// Never dedup findings without CWE or line number.
		if f.CWEID == "" || f.LineNumber == 0 {
			continue
		}

		key := groupKey{Line: f.LineNumber, CWE: f.CWEID}
		if g, exists := groups[key]; exists {
			g.members = append(g.members, i)
			if beats(findings[i], findings[g.winnerIdx]) {
				g.winnerIdx = i
			}
		} else {
			groups[key] = &group{
				winnerIdx: i,
				members:   []int{i},
			}
			order = append(order, key)
		}
	}

	// Build result preserving the original relative order. Ungrouped findings
	// (no CWE or no line) keep their positions. For each group the winner
	// appears at the position of the first group member.
	seen := make(map[groupKey]bool)
	result := make([]rules.Finding, 0, len(findings))

	for _, f := range findings {
		if f.CWEID == "" || f.LineNumber == 0 {
			result = append(result, f)
			continue
		}

		key := groupKey{Line: f.LineNumber, CWE: f.CWEID}
		if seen[key] {
			continue
		}
		seen[key] = true

		g := groups[key]
		winner := findings[g.winnerIdx]

		// Merge tags from all suppressed findings into the winner.
		for _, mi := range g.members {
			if mi != g.winnerIdx {
				winner.Tags = mergeUniqueTags(winner.Tags, findings[mi].Tags)
			}
		}

		result = append(result, winner)
	}

	return result
}

// findingTier returns the priority tier for a finding based on its tags and
// rule ID.
func findingTier(f *rules.Finding) int {
	// Interprocedural findings carry both "interprocedural" and
	// "taint-analysis" tags, so check interprocedural first.
	if hasTag(f.Tags, "interprocedural") {
		return tierInterprocedural
	}
	if hasTag(f.Tags, "taint-analysis") {
		return tierTaint
	}
	if isASTRuleID(f.RuleID) {
		return tierAST
	}
	return tierRegex
}

// isASTRuleID returns true if the rule ID belongs to any AST analyzer.
// All AST analyzers use rule IDs that contain "AST":
//
//	GTSS-AST-    (Go)         GTSS-PYAST-   (Python)
//	GTSS-JSAST-  (JavaScript) GTSS-JAVAAST- (Java)
//	GTSS-PHPAST- (PHP)        GTSS-RUBYAST- (Ruby)
//	GTSS-CAST-   (C)          GTSS-CS-AST-  (C#)
//	GTSS-KT-AST- (Kotlin)     GTSS-SWIFT-AST- (Swift)
//	GTSS-RUST-AST- (Rust)     GTSS-LUA-AST- (Lua)
//	GTSS-GVY-AST- (Groovy)
func isASTRuleID(ruleID string) bool {
	return strings.Contains(ruleID, "AST")
}

// beats returns true if challenger should replace current as group winner.
func beats(challenger, current rules.Finding) bool {
	ct := findingTier(&challenger)
	wt := findingTier(&current)
	if ct != wt {
		return ct > wt
	}
	// Same tier: higher severity wins.
	if challenger.Severity != current.Severity {
		return challenger.Severity > current.Severity
	}
	// Same severity: higher confidence wins.
	return confidenceRank(challenger.Confidence) > confidenceRank(current.Confidence)
}

// confidenceRank maps the confidence string to a numeric value for comparison.
func confidenceRank(c string) int {
	switch strings.ToLower(c) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// hasTag reports whether tags contains tag.
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// mergeUniqueTags appends any tags from src that are not already in dst.
func mergeUniqueTags(dst, src []string) []string {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d == s {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}
