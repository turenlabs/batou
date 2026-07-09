package scanner

import "github.com/turenlabs/batou-rules/rules"

// Exported aliases for the analysis-tier constants used to classify findings.
// A finding's tier reflects which analysis layer produced (or, after dedup,
// confirmed) it: higher tiers win during deduplication, so a finding whose
// tier is TierRegex in the *final* result is precisely one that nothing else
// confirmed — the prime false-positive source on real codebases.
//
// These mirror the unexported tierRegex/tierInterprocedural/tierAST/tierTaint
// constants in dedup.go; kept in sync there.
const (
	TierRegex           = tierRegex
	TierInterprocedural = tierInterprocedural
	TierAST             = tierAST
	TierTaint           = tierTaint
)

// FindingTier returns the analysis tier that produced or confirmed a finding.
// It is the exported wrapper around findingTier, so packages outside `scanner`
// (e.g. dirscan, hook config) can classify findings without re-implementing
// the tag/rule-ID heuristics.
//
// After DeduplicateFindings, a regex finding that a higher layer confirmed on
// the same line is replaced by the higher-tier winner; so FindingTier(&f) ==
// TierRegex on a deduplicated result means no other layer agreed with it.
func FindingTier(f *rules.Finding) int { return findingTier(f) }

// FilterByMinTier returns the findings whose FindingTier is >= minTier,
// preserving order. minTier == 0 (or any value <= TierRegex) returns the input
// unchanged. Useful for "data-flow-confirmed findings only" views: pass
// TierInterprocedural to drop pure regex hits.
func FilterByMinTier(findings []rules.Finding, minTier int) []rules.Finding {
	if minTier <= TierRegex {
		return findings
	}
	out := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if findingTier(&f) >= minTier {
			out = append(out, f)
		}
	}
	return out
}

// FilterByMinConfidence returns the findings whose ConfidenceScore is >= min,
// preserving order. min <= 0 returns the input unchanged.
func FilterByMinConfidence(findings []rules.Finding, min float64) []rules.Finding {
	if min <= 0 {
		return findings
	}
	out := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if f.ConfidenceScore >= min {
			out = append(out, f)
		}
	}
	return out
}
