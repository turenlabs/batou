package scanner

import (
	"sort"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// Default caps for findings per scan.
const (
	DefaultPerRuleCap = 3
	DefaultPerFileCap = 20

	// DefaultCrossFileSinkCap is the per-(leaf-sink-file, leaf-sink-line,
	// rule_id) cap applied to BATOU-INTERPROC-* findings. The cap *tags*
	// the (N+1)th and beyond as RolledUp=true rather than dropping them,
	// so recall is preserved (every distinct flow stays in the JSONL
	// stream). Downstream consumers can hide the rolled-up entries by
	// default and surface them on demand.
	//
	// 10 is the working sweet spot: harness env-ON has 64 distinct
	// cross-file findings with no group exceeding ~5, so it sees no
	// rollups; Coder env-ON has middleware-chain groups of 50-200 hits
	// at the same leaf sink, so most of the noise gets visibly rolled.
	// Configurable via the --max-per-cross-file-sink scan flag (0
	// disables).
	DefaultCrossFileSinkCap = 10
)

// MarkCrossFileSinkRollups tags BATOU-INTERPROC-* findings with
// RolledUp=true beyond the first `cap` per (leaf-sink-file,
// leaf-sink-line, rule_id) group. The top of each group is selected by
// (severity DESC, confidence_score DESC, file_path ASC, line ASC) so
// the highest-signal representatives stay un-tagged.
//
// Non-INTERPROC findings are passed through untouched. The leaf sink
// position is recovered from the finding's TaintPath; findings whose
// path doesn't end in a TaintStepSink are also passed through (we'd
// silently collapse otherwise unrelated entries).
//
// Returns the input slice with RolledUp set in-place on the relevant
// entries plus the number of entries that were tagged. cap <= 0
// disables the marker entirely.
func MarkCrossFileSinkRollups(findings []rules.Finding, cap int) ([]rules.Finding, int) {
	if cap <= 0 || len(findings) == 0 {
		return findings, 0
	}

	type sinkKey struct {
		file   string
		line   int
		ruleID string
	}

	// Group indices by leaf-sink key. Findings without a recoverable leaf
	// sink (no TaintStepSink in the path, or not a BATOU-INTERPROC- rule)
	// stay un-tagged.
	groups := make(map[sinkKey][]int)
	for i, f := range findings {
		if !strings.HasPrefix(f.RuleID, "BATOU-INTERPROC-") {
			continue
		}
		var leafFile string
		var leafLine int
		for j := len(f.TaintPath) - 1; j >= 0; j-- {
			st := f.TaintPath[j]
			if st.Kind == rules.TaintStepSink {
				leafFile = st.File
				leafLine = st.Line
				break
			}
		}
		if leafFile == "" {
			continue
		}
		k := sinkKey{file: leafFile, line: leafLine, ruleID: f.RuleID}
		groups[k] = append(groups[k], i)
	}

	tagged := 0
	for _, indices := range groups {
		if len(indices) <= cap {
			continue
		}
		// Stable order: highest severity / confidence first; ties broken
		// by file path then line. The kept-top selection matches
		// findingPriority's intent (signal first) but uses a finding-
		// path-stable secondary so two runs on the same data produce
		// identical rollups.
		sort.SliceStable(indices, func(a, b int) bool {
			fa, fb := findings[indices[a]], findings[indices[b]]
			if fa.Severity != fb.Severity {
				return fa.Severity > fb.Severity
			}
			if fa.ConfidenceScore != fb.ConfidenceScore {
				return fa.ConfidenceScore > fb.ConfidenceScore
			}
			if fa.FilePath != fb.FilePath {
				return fa.FilePath < fb.FilePath
			}
			return fa.LineNumber < fb.LineNumber
		})
		for k, idx := range indices {
			if k < cap {
				continue
			}
			findings[idx].RolledUp = true
			tagged++
		}
	}

	return findings, tagged
}

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
