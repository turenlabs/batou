package reporter

import (
	"fmt"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ScanResult holds the complete results of a Batou scan.
type ScanResult struct {
	FilePath           string          `json:"file_path"`
	Language           rules.Language  `json:"language"`
	Event              string          `json:"event"` // PreToolUse or PostToolUse
	Findings           []rules.Finding `json:"findings"`
	SuppressedCount    int             `json:"suppressed_count,omitempty"`
	SuppressedFindings []rules.Finding `json:"suppressed_findings,omitempty"`
	RulesRun           int             `json:"rules_run"`
	ScanTimeMs         int64           `json:"scan_time_ms"`
	HintsOutput        string          `json:"hints_output,omitempty"`
	SuppressOnlyEdit   bool            `json:"suppress_only_edit,omitempty"`
	PreSuppressBlock   bool            `json:"pre_suppress_block,omitempty"`
}

// MaxSeverity returns the highest severity among all findings.
func (r *ScanResult) MaxSeverity() rules.Severity {
	max := rules.Info
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// HasFindings returns true if any findings were detected.
func (r *ScanResult) HasFindings() bool {
	return len(r.Findings) > 0
}

// ShouldBlock returns true if any finding warrants blocking the write.
// Requires both Critical severity and high confidence (>= 0.7).
func (r *ScanResult) ShouldBlock() bool {
	for _, f := range r.Findings {
		if f.ShouldBlock() {
			return true
		}
	}
	return false
}

// FormatForClaude formats the scan results as context for Claude.
// This is the string injected into additionalContext so Claude
// sees the findings and can act on them.
func FormatForClaude(result *ScanResult) string {
	if !result.HasFindings() {
		return ""
	}

	var b strings.Builder

	fmt.Fprintf(&b, "\n--- Batou Security Scan [%s] ---\n", result.FilePath)
	fmt.Fprintf(&b, "Language: %s | Findings: %d | Rules checked: %d | Time: %dms\n",
		result.Language, len(result.Findings), result.RulesRun, result.ScanTimeMs)

	// Risk summary bar
	var blocking, high, medium, low int
	for _, f := range result.Findings {
		switch {
		case f.RiskScore >= 0.7:
			blocking++
		case f.RiskScore >= 0.4:
			high++
		case f.RiskScore >= 0.2:
			medium++
		default:
			low++
		}
	}
	parts := []string{}
	if blocking > 0 {
		parts = append(parts, fmt.Sprintf("blocking:%d", blocking))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("high-risk:%d", high))
	}
	if medium > 0 {
		parts = append(parts, fmt.Sprintf("medium-risk:%d", medium))
	}
	if low > 0 {
		parts = append(parts, fmt.Sprintf("low-risk:%d", low))
	}
	fmt.Fprintf(&b, "Risk: %s\n\n", strings.Join(parts, " | "))

	// Detail for each finding
	for i, f := range result.Findings {
		fmt.Fprintf(&b, "(%d) %s\n", i+1, f.FormatDetail())
		if i < len(result.Findings)-1 {
			b.WriteString("\n")
		}
	}

	if result.ShouldBlock() {
		b.WriteString("\nACTION REQUIRED: Critical high-confidence vulnerability detected. This write was BLOCKED.\n")
		b.WriteString("Please fix the vulnerability before writing this file.\n")
	} else if result.MaxSeverity().ShouldWarn() {
		b.WriteString("\nWARNING: High-severity vulnerability detected. Please review and fix.\n")
	}

	b.WriteString("\nFalse positive? Add above the flagged line:\n")
	fmt.Fprintf(&b, "  %s batou:ignore <RULE-ID> -- <reason>\n", commentPrefixForLang(result.Language))

	b.WriteString("--- End Batou Scan ---\n")

	return b.String()
}

// FormatBlockMessage formats a message for blocking a write via stderr.
// This is the most important message Batou produces: it STOPS the write,
// so Claude needs clear guidance on how to rewrite the code.
func FormatBlockMessage(result *ScanResult) string {
	var b strings.Builder

	b.WriteString("Batou BLOCKED WRITE: Critical security vulnerability detected\n\n")

	for _, f := range result.Findings {
		if f.ShouldBlock() {
			fmt.Fprintf(&b, "[%s] %s: %s\n", f.Severity, f.RuleID, f.Title)
			if f.FilePath != "" {
				loc := f.FilePath
				if f.LineNumber > 0 {
					loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
				}
				fmt.Fprintf(&b, "  Location: %s\n", loc)
			}
			if f.MatchedText != "" {
				snippet := f.MatchedText
				if len(snippet) > 120 {
					snippet = snippet[:120] + "..."
				}
				fmt.Fprintf(&b, "  Vulnerable code: %s\n", snippet)
			}
			fmt.Fprintf(&b, "  Why: %s\n", f.Description)
			if f.Suggestion != "" {
				fmt.Fprintf(&b, "  Fix: %s\n", f.Suggestion)
			}
			if f.RiskScore > 0 {
				fmt.Fprintf(&b, "  Risk: %.0f%%\n", f.RiskScore*100)
			}
			if f.CWEID != "" {
				fmt.Fprintf(&b, "  Reference: %s", f.CWEID)
				if f.OWASPCategory != "" {
					fmt.Fprintf(&b, ", %s", f.OWASPCategory)
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("ACTION: Rewrite the code to fix the critical vulnerabilities above, then retry the write.\n")
	fmt.Fprintf(&b, "\nFalse positive? Add above the flagged line:\n  %s batou:ignore <RULE-ID> -- <reason>\n",
		commentPrefixForLang(result.Language))

	return b.String()
}

// commentPrefixForLang returns the single-line comment prefix for a language.
func commentPrefixForLang(lang rules.Language) string {
	switch lang {
	case rules.LangPython, rules.LangRuby, rules.LangPerl, rules.LangShell:
		return "#"
	case rules.LangLua, rules.LangSQL:
		return "--"
	default:
		return "//"
	}
}
