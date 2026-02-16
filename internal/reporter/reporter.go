package reporter

import (
	"fmt"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ScanResult holds the complete results of a Batou scan.
type ScanResult struct {
	FilePath    string          `json:"file_path"`
	Language    rules.Language  `json:"language"`
	Event       string          `json:"event"` // PreToolUse or PostToolUse
	Findings    []rules.Finding `json:"findings"`
	RulesRun    int             `json:"rules_run"`
	ScanTimeMs  int64           `json:"scan_time_ms"`
	HintsOutput string          `json:"hints_output,omitempty"`
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
func (r *ScanResult) ShouldBlock() bool {
	return r.MaxSeverity().ShouldBlock()
}

// CountBySeverity returns the count of findings at each severity level.
func (r *ScanResult) CountBySeverity() map[rules.Severity]int {
	counts := make(map[rules.Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// FormatForClaude formats the scan results as context for Claude.
// This is the string injected into additionalContext so Claude
// sees the findings and can act on them.
func FormatForClaude(result *ScanResult) string {
	if !result.HasFindings() {
		return ""
	}

	var b strings.Builder

	counts := result.CountBySeverity()
	b.WriteString(fmt.Sprintf("\n--- Batou Security Scan [%s] ---\n", result.FilePath))
	b.WriteString(fmt.Sprintf("Language: %s | Findings: %d | Rules checked: %d | Time: %dms\n",
		result.Language, len(result.Findings), result.RulesRun, result.ScanTimeMs))

	// Summary bar
	parts := []string{}
	for _, sev := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low, rules.Info} {
		if c, ok := counts[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", sev, c))
		}
	}
	b.WriteString(fmt.Sprintf("Severity: %s\n\n", strings.Join(parts, " | ")))

	// Detail for each finding
	for i, f := range result.Findings {
		b.WriteString(fmt.Sprintf("(%d) %s\n", i+1, f.FormatDetail()))
		if i < len(result.Findings)-1 {
			b.WriteString("\n")
		}
	}

	if result.ShouldBlock() {
		b.WriteString("\nACTION REQUIRED: Critical vulnerability detected. This write was BLOCKED.\n")
		b.WriteString("Please fix the vulnerability before writing this file.\n")
	} else if result.MaxSeverity().ShouldWarn() {
		b.WriteString("\nWARNING: High-severity vulnerability detected. Please review and fix.\n")
	}

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
		if f.Severity >= rules.Critical {
			b.WriteString(fmt.Sprintf("[%s] %s: %s\n", f.Severity, f.RuleID, f.Title))
			if f.FilePath != "" {
				loc := f.FilePath
				if f.LineNumber > 0 {
					loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
				}
				b.WriteString(fmt.Sprintf("  Location: %s\n", loc))
			}
			if f.MatchedText != "" {
				snippet := f.MatchedText
				if len(snippet) > 120 {
					snippet = snippet[:120] + "..."
				}
				b.WriteString(fmt.Sprintf("  Vulnerable code: %s\n", snippet))
			}
			b.WriteString(fmt.Sprintf("  Why: %s\n", f.Description))
			if f.Suggestion != "" {
				b.WriteString(fmt.Sprintf("  Fix: %s\n", f.Suggestion))
			}
			if f.CWEID != "" {
				b.WriteString(fmt.Sprintf("  Reference: %s", f.CWEID))
				if f.OWASPCategory != "" {
					b.WriteString(fmt.Sprintf(", %s", f.OWASPCategory))
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("ACTION: Rewrite the code to fix the critical vulnerabilities above, then retry the write.\n")

	return b.String()
}
