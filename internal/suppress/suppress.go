package suppress

import (
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// IsSuppressed returns true if the given finding is suppressed by any
// active directive in s.
func (s *Suppressions) IsSuppressed(f rules.Finding) bool {
	targets, ok := s.lineTargets[f.LineNumber]
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
	category := categorizeRule(f.RuleID)

	for _, t := range targets {
		if t == "all" {
			return true
		}
		// Exact rule ID match.
		if t == ruleIDLower {
			return true
		}
		// Category match.
		if t == category {
			return true
		}
	}
	return false
}

// categorizeRule extracts a category name from a rule ID prefix.
// Duplicated from internal/hints to avoid import dependency.
func categorizeRule(ruleID string) string {
	if strings.Contains(ruleID, "INJ") {
		return "injection"
	}
	if strings.Contains(ruleID, "XSS") {
		return "xss"
	}
	if strings.Contains(ruleID, "SEC") {
		return "secrets"
	}
	if strings.Contains(ruleID, "CRY") {
		return "crypto"
	}
	if strings.Contains(ruleID, "TRV") {
		return "traversal"
	}
	if strings.Contains(ruleID, "AUTH") {
		return "auth"
	}
	if strings.Contains(ruleID, "SSRF") {
		return "ssrf"
	}
	if strings.Contains(ruleID, "TAINT") {
		return "taint"
	}
	if strings.Contains(ruleID, "DESER") {
		return "deserialize"
	}
	if strings.Contains(ruleID, "REDIR") {
		return "redirect"
	}
	if strings.Contains(ruleID, "NOSQL") {
		return "injection"
	}
	if strings.Contains(ruleID, "XXE") {
		return "xxe"
	}
	if strings.Contains(ruleID, "CORS") {
		return "cors"
	}
	if strings.Contains(ruleID, "LOG") {
		return "logging"
	}
	if strings.Contains(ruleID, "MEM") {
		return "memory"
	}
	if strings.Contains(ruleID, "PROTO") {
		return "prototype"
	}
	if strings.Contains(ruleID, "MASS") {
		return "massassign"
	}
	if strings.Contains(ruleID, "GQL") {
		return "graphql"
	}
	if strings.Contains(ruleID, "MISCONF") {
		return "misconfig"
	}
	if strings.Contains(ruleID, "INTERPROC") {
		return "interprocedural"
	}
	return "general"
}
