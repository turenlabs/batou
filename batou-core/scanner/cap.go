package scanner

import (
	"sort"

	"github.com/turenlabs/batou-rules/rules"
)

// Default caps for findings per scan.
const (
	DefaultPerRuleCap = 3
	DefaultPerFileCap = 20
)

// CapFindings limits the number of findings to keep output actionable.
// It applies two caps in order:
//  1. Per-rule cap: at most perRule findings per RuleID (keep highest confidence).
//  2. Per-file cap: at most perFile findings total (keep highest severity, then confidence).
//
// Returns the kept findings and the number of findings that were capped.
func CapFindings(findings []rules.Finding, perRule, perFile int) ([]rules.Finding, int) {
	if len(findings) == 0 {
		return findings, 0
	}

	total := len(findings)

	// Step 1: per-rule cap.
	if perRule > 0 {
		findings = capPerRule(findings, perRule)
	}

	// Step 2: per-file cap.
	if perFile > 0 && len(findings) > perFile {
		findings = capTotal(findings, perFile)
	}

	capped := total - len(findings)
	return findings, capped
}

// findingPriority compares two findings for capping priority.
// Returns true if a should be kept over b.
// Order: analysis tier desc (taint > AST > interproc > regex),
// then severity desc, then confidence desc.
func findingPriority(a, b rules.Finding) bool {
	ta, tb := findingTier(&a), findingTier(&b)
	if ta != tb {
		return ta > tb
	}
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	return a.ConfidenceScore > b.ConfidenceScore
}

// capPerRule keeps the top N findings per RuleID, prioritizing higher-tier
// analysis (taint/AST over regex). Findings that would block writes are
// always kept.
func capPerRule(findings []rules.Finding, n int) []rules.Finding {
	// Group by RuleID.
	groups := make(map[string][]int)
	var order []string
	for i, f := range findings {
		if _, seen := groups[f.RuleID]; !seen {
			order = append(order, f.RuleID)
		}
		groups[f.RuleID] = append(groups[f.RuleID], i)
	}

	keep := make(map[int]bool)
	for _, ruleID := range order {
		indices := groups[ruleID]
		if len(indices) <= n {
			for _, idx := range indices {
				keep[idx] = true
			}
			continue
		}

		sort.Slice(indices, func(a, b int) bool {
			return findingPriority(findings[indices[a]], findings[indices[b]])
		})

		// Always keep blockers; count non-blockers toward the cap.
		kept := 0
		for _, idx := range indices {
			if findings[idx].ShouldBlock() {
				keep[idx] = true
				continue
			}
			if kept < n {
				keep[idx] = true
				kept++
			}
		}
	}

	// Preserve original order.
	result := make([]rules.Finding, 0, len(keep))
	for i, f := range findings {
		if keep[i] {
			result = append(result, f)
		}
	}
	return result
}

// capTotal keeps the top N findings overall, prioritizing higher-tier
// analysis (taint/AST over regex). Findings that would block writes are
// always kept.
func capTotal(findings []rules.Finding, n int) []rules.Finding {
	indices := make([]int, len(findings))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(a, b int) bool {
		return findingPriority(findings[indices[a]], findings[indices[b]])
	})

	keep := make(map[int]bool)
	kept := 0
	for _, idx := range indices {
		if findings[idx].ShouldBlock() {
			keep[idx] = true
			continue
		}
		if kept < n {
			keep[idx] = true
			kept++
		}
	}

	// Preserve original order.
	result := make([]rules.Finding, 0, len(keep))
	for i, f := range findings {
		if keep[i] {
			result = append(result, f)
		}
	}
	return result
}
