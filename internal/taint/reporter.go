package taint

import (
	"fmt"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// FormatFlowForClaude formats a taint flow for Claude's additionalContext.
func FormatFlowForClaude(flow *TaintFlow) string {
	var b strings.Builder

	sev := flow.Sink.Severity
	b.WriteString(fmt.Sprintf("[%s] TAINT FLOW: %s → %s\n",
		sev, flow.Source.Category, flow.Sink.Category))
	b.WriteString(fmt.Sprintf("  Scope: %s\n", flow.ScopeName))
	b.WriteString(fmt.Sprintf("  Source: %s (line %d) — %s\n",
		flow.Source.MethodName, flow.SourceLine, flow.Source.Description))

	if len(flow.Steps) > 0 {
		b.WriteString("  Flow path:\n")
		for i, step := range flow.Steps {
			connector := "├─"
			if i == len(flow.Steps)-1 {
				connector = "└─"
			}
			b.WriteString(fmt.Sprintf("    %s line %d: %s (%s)\n",
				connector, step.Line, step.Description, step.VarName))
		}
	}

	b.WriteString(fmt.Sprintf("  Sink: %s (line %d) — %s\n",
		flow.Sink.MethodName, flow.SinkLine, flow.Sink.Description))

	conf := "HIGH"
	if flow.Confidence < 0.7 {
		conf = "MEDIUM"
	}
	if flow.Confidence < 0.4 {
		conf = "LOW"
	}
	b.WriteString(fmt.Sprintf("  Confidence: %s (%.0f%%)\n", conf, flow.Confidence*100))

	if flow.Sink.CWEID != "" {
		b.WriteString(fmt.Sprintf("  CWE: %s | OWASP: %s\n", flow.Sink.CWEID, flow.Sink.OWASPCategory))
	}

	return b.String()
}

// FormatFlowsReport formats multiple taint flows into a complete report section.
func FormatFlowsReport(flows []TaintFlow, filePath string, lang rules.Language, scanTimeMs int64) string {
	if len(flows) == 0 {
		return ""
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n--- GTSS Taint Analysis [%s] ---\n", filePath))
	b.WriteString(fmt.Sprintf("Language: %s | Taint flows: %d | Time: %dms\n\n",
		lang, len(flows), scanTimeMs))

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
	b.WriteString(fmt.Sprintf("Severity: %s\n\n", strings.Join(parts, " | ")))

	for i, flow := range flows {
		b.WriteString(fmt.Sprintf("FLOW %d:\n", i+1))
		b.WriteString(FormatFlowForClaude(&flow))
		b.WriteString("\n")
	}

	b.WriteString("--- End Taint Analysis ---\n")
	return b.String()
}
