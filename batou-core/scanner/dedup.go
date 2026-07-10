package scanner

import (
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// Priority tiers for finding classification. Higher values win during
// deduplication when two findings share the same (FilePath, LineNumber, CWE)
// key.
const (
	tierRegex           = 10
	tierInterprocedural = 20
	tierAST             = 30
	tierTaint           = 40
)

// DeduplicateFindings groups findings by (FilePath, LineNumber, CWE) and
// keeps one winner per group.
//
// FilePath is part of the key because the slice mixes per-file findings with
// interprocedural findings whose FilePath can point at a caller in a
// different file (graph.PropagateInterproc emits caller-file findings):
// "line 42, CWE-89" in handler.go and "line 42, CWE-89" in caller.go are
// distinct issues and must both survive.
//
// Caller contract: normalize empty FilePath to the scanned file before
// calling (scanner.Scan does this), otherwise rules that omit FilePath
// split same-file groups and duplicates survive.
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
		File string
		Line int
		CWE  string
	}

	type group struct {
		winnerIdx int
		members   []int
	}

	groups := make(map[groupKey]*group)

	for i, f := range findings {
		// Never dedup findings without CWE or line number.
		if f.CWEID == "" || f.LineNumber == 0 {
			continue
		}

		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		key := groupKey{File: f.FilePath, Line: f.LineNumber, CWE: cwe}
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

		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		key := groupKey{File: f.FilePath, Line: f.LineNumber, CWE: cwe}
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

		// Boost confidence when multiple analysis tiers confirmed the same issue.
		distinctTiers := countDistinctTiers(g.members, findings)
		BoostConfidenceForMultiLayer(&winner, distinctTiers)

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

// astRuleIDPrefixes enumerates the exact rule-ID prefixes emitted by the
// AST analyzers under batou-core/analyzer/. Classification must be an
// anchored prefix match against this set — NOT a substring check — because
// regex rule IDs can contain "AST" as an accidental substring
// (BATOU-FW-FASTAPI-*). A substring match promoted those regex rules into
// the AST tier: ConfBaseAST (0.7) base confidence, dedup wins over true
// regex findings, and Critical regex findings reaching RiskScore
// 1.0×0.7 = 0.7 — a pure regex rule blocking writes, which breaks the
// regex-never-blocks invariant.
//
// When adding a new AST analyzer, add its prefix here and to
// TestDedup_AllASTLanguagePrefixes.
var astRuleIDPrefixes = []string{
	"BATOU-AST-",          // Go (goast)
	"BATOU-PYAST-",        // Python (pyast)
	"BATOU-JSAST-",        // JavaScript/TypeScript (jsast)
	"BATOU-JAVAAST-",      // Java (javaast)
	"BATOU-PHPAST-",       // PHP (phpast)
	"BATOU-RUBYAST-",      // Ruby (rubyast)
	"BATOU-CAST-",         // C/C++ (cast)
	"BATOU-CS-AST-",       // C# (csast)
	"BATOU-KT-AST-",       // Kotlin (ktast)
	"BATOU-SWIFT-AST-",    // Swift (swiftast)
	"BATOU-RUST-AST-",     // Rust (rustast)
	"BATOU-LUA-AST-",      // Lua (luaast)
	"BATOU-GVY-AST-",      // Groovy (gvyast)
	"BATOU-PERL-AST-",     // Perl (perlast)
	"BATOU-SH-AST-",       // Shell (shellast)
	"BATOU-ZIG-AST-",      // Zig (zigast)
	"BATOU-OWNCLOUD-AST-", // PHP ownCloud public-page analyzer (phpast/publicpage)
}

// isASTRuleID returns true if the rule ID belongs to any AST analyzer.
func isASTRuleID(ruleID string) bool {
	for _, p := range astRuleIDPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
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
	cc := confidenceRank(challenger.Confidence)
	wc := confidenceRank(current.Confidence)
	if cc != wc {
		return cc > wc
	}
	// Final tiebreaker: lower RuleID wins (deterministic regardless of
	// goroutine scheduling order when rules run concurrently).
	return challenger.RuleID < current.RuleID
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

// countDistinctTiers returns how many unique analysis tiers are represented
// in a dedup group. Used to compute multi-layer confidence boosts.
func countDistinctTiers(memberIndices []int, findings []rules.Finding) int {
	seen := make(map[int]bool)
	for _, idx := range memberIndices {
		tier := findingTier(&findings[idx])
		seen[tier] = true
	}
	return len(seen)
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
