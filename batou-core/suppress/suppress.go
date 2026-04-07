package suppress

import (
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// unsuppressibleRules are rule IDs that cannot be suppressed via batou:ignore.
// SUPPRESS-REVIEW must remain visible so agents fix code instead of suppressing.
var unsuppressibleRules = map[string]bool{
	"BATOU-SUPPRESS-REVIEW": true,
	"BATOU-TIMEOUT":         true,
	"BATOU-PANIC":           true,
}

// IsSuppressed returns true if the given finding is suppressed by any
// active directive in s.
func (s *Suppressions) IsSuppressed(f rules.Finding) bool {
	if unsuppressibleRules[f.RuleID] {
		return false
	}
	line := f.LineNumber
	// Line 0 findings are file-level; treat them as suppressible by
	// directives targeting line 1 (first line of the file).
	if line == 0 {
		line = 1
	}
	targets, ok := s.lineTargets[line]
	if !ok {
		return false
	}
	return matchesTargets(f, targets)
}

// Apply partitions findings into kept and suppressed slices.
func Apply(s *Suppressions, findings []rules.Finding) (kept, suppressed []rules.Finding) {
	if s == nil {
		return findings, nil
	}
	for _, f := range findings {
		if s.IsSuppressed(f) {
			suppressed = append(suppressed, f)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

// SuppressedLines returns a set of line numbers that have active
// suppression directives. Used by the call graph to filter sinks.
func (s *Suppressions) SuppressedLines() map[int]bool {
	if s == nil {
		return nil
	}
	lines := make(map[int]bool, len(s.lineTargets))
	for ln := range s.lineTargets {
		lines[ln] = true
	}
	return lines
}

// matchesTargets checks if a finding matches any of the given targets.
// Targets can be: exact rule ID, category name, or "all".
func matchesTargets(f rules.Finding, targets []string) bool {
	ruleIDLower := strings.ToLower(f.RuleID)
	category := rules.CategoryForRule(f.RuleID)

	for _, t := range targets {
		if t == "all" {
			return true
		}
		if t == ruleIDLower {
			return true
		}
		if t == category {
			return true
		}
		if strings.HasPrefix(ruleIDLower, "batou-taint-") && t == "taint" {
			return true
		}
	}
	return false
}

// categorizeRule delegates to rules.CategoryForRule (single source of truth).
func categorizeRule(ruleID string) string {
	return rules.CategoryForRule(ruleID)
}
