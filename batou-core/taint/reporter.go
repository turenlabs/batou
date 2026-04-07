package taint

import (
	"fmt"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// FormatFlowForClaude formats a taint flow for Claude's additionalContext.
func FormatFlowForClaude(flow *TaintFlow) string {
	var b strings.Builder

	sev := flow.Sink.Severity
	fmt.Fprintf(&b, "[%s] TAINT FLOW: %s → %s\n",
		sev, flow.Source.Category, flow.Sink.Category)
	fmt.Fprintf(&b, "  Scope: %s\n", flow.ScopeName)
	fmt.Fprintf(&b, "  Source: %s (line %d) — %s\n",
		flow.Source.MethodName, flow.SourceLine, flow.Source.Description)

	if len(flow.Steps) > 0 {
		b.WriteString("  Flow path:\n")
		for i, step := range flow.Steps {
			connector := "├─"
			if i == len(flow.Steps)-1 {
				connector = "└─"
			}
			fmt.Fprintf(&b, "    %s line %d: %s (%s)\n",
				connector, step.Line, step.Description, step.VarName)
		}
	}

	fmt.Fprintf(&b, "  Sink: %s (line %d) — %s\n",
		flow.Sink.MethodName, flow.SinkLine, flow.Sink.Description)

	conf := "HIGH"
	if flow.Confidence < 0.7 {
		conf = "MEDIUM"
	}
	if flow.Confidence < 0.4 {
		conf = "LOW"
	}
	fmt.Fprintf(&b, "  Confidence: %s (%.0f%%)\n", conf, flow.Confidence*100)

	if flow.Sink.CWEID != "" {
		fmt.Fprintf(&b, "  CWE: %s | OWASP: %s\n", flow.Sink.CWEID, flow.Sink.OWASPCategory)
	}

	return b.String()
}

// FormatFlowsReport formats multiple taint flows into a complete report section.
func FormatFlowsReport(flows []TaintFlow, filePath string, lang rules.Language, scanTimeMs int64) string {
	if len(flows) == 0 {
		return ""
	}

	var b strings.Builder

	fmt.Fprintf(&b, "\n--- Batou Taint Analysis [%s] ---\n", filePath)
	fmt.Fprintf(&b, "Language: %s | Taint flows: %d | Time: %dms\n\n",
		lang, len(flows), scanTimeMs)

	// Count by severity
	sevCounts := make(map[rules.Severity]int)
	for _, f := range flows {
		sevCounts[f.Sink.Severity]++
	}
	parts := []string{}
	for _, sev := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
		if c, ok := sevCounts[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", sev, c))
		}
	}
	fmt.Fprintf(&b, "Severity: %s\n\n", strings.Join(parts, " | "))

	for i, flow := range flows {
		fmt.Fprintf(&b, "FLOW %d:\n", i+1)
		b.WriteString(FormatFlowForClaude(&flow))
		b.WriteString("\n")
	}

	b.WriteString("--- End Taint Analysis ---\n")
	return b.String()
}
