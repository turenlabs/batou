package scanner

import "github.com/turenlabs/batou/internal/rules"

// Base confidence scores assigned by analysis tier.
const (
	ConfBaseRegexLow    = 0.3
	ConfBaseRegexMedium = 0.4
	ConfBaseRegexHigh   = 0.5
	ConfBaseAST         = 0.7
	ConfBaseInterproc   = 0.8
	ConfMultiLayerBoost = 0.1
	ConfBlockThreshold  = 0.7
)

// AssignBaseConfidenceScore sets a baseline ConfidenceScore on a finding
// based on which analysis tier produced it. Taint findings already carry
// a float64 score from the taint engine, so those are preserved.
func AssignBaseConfidenceScore(f *rules.Finding) {
	// Taint and interprocedural findings already have a score set
	// at creation time — preserve it.
	if f.ConfidenceScore > 0 {
		return
	}

	tier := findingTier(f)
	switch tier {
	case tierTaint:
		// Should not reach here (taint sets score), but fallback.
		f.ConfidenceScore = 0.6
	case tierAST:
		f.ConfidenceScore = ConfBaseAST
	case tierInterprocedural:
		f.ConfidenceScore = ConfBaseInterproc
	default: // tierRegex
		switch f.Confidence {
		case "high":
			f.ConfidenceScore = ConfBaseRegexHigh
		case "medium":
			f.ConfidenceScore = ConfBaseRegexMedium
		default:
			f.ConfidenceScore = ConfBaseRegexLow
		}
	}
}

// BoostConfidenceForMultiLayer increases a finding's confidence score
// when multiple independent analysis tiers confirmed the same issue.
// Each additional tier beyond the first adds ConfMultiLayerBoost.
// The score is capped at 1.0.
func BoostConfidenceForMultiLayer(f *rules.Finding, distinctTiers int) {
	if distinctTiers <= 1 {
		return
	}
	boost := float64(distinctTiers-1) * ConfMultiLayerBoost
	f.ConfidenceScore += boost
	if f.ConfidenceScore > 1.0 {
		f.ConfidenceScore = 1.0
	}
}
