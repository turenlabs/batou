package eval

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// FormatTable renders a ModelReport as an ASCII table for terminal output,
// following the style of the existing GTSS scorecard in scorecard_test.go.
func FormatTable(report ModelReport) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("+=================================================================+\n")
	sb.WriteString("|            ProductSecBench Evaluation Report                     |\n")
	sb.WriteString(fmt.Sprintf("|            Model: %-43s|\n", report.Model))
	sb.WriteString("+=================================================================+\n")
	sb.WriteString("\n")

	// Headline metrics
	sb.WriteString("+-------------------------------+----------+\n")
	sb.WriteString("|  Metric                       |  Value   |\n")
	sb.WriteString("+-------------------------------+----------+\n")
	sb.WriteString(fmt.Sprintf("|  Total Samples                |  %6d  |\n", report.TotalSamples))
	sb.WriteString(fmt.Sprintf("|  Vulnerabilities Detected     |  %6d  |\n", report.VulnerableCount))
	sb.WriteString(fmt.Sprintf("|  Vulnerability Rate           |  %5.1f%%  |\n", report.VulnerabilityRate*100))
	sb.WriteString(fmt.Sprintf("|  Severity Score (avg)         |  %6.2f  |\n", report.SeverityScoreAvg))
	sb.WriteString(fmt.Sprintf("|  CWE Match Rate               |  %5.1f%%  |\n", report.CWEMatchRate*100))
	sb.WriteString(fmt.Sprintf("|  OWASP Match Rate             |  %5.1f%%  |\n", report.OWASPMatchRate*100))
	sb.WriteString(fmt.Sprintf("|  Precision                    |  %5.1f%%  |\n", report.Precision*100))
	sb.WriteString(fmt.Sprintf("|  Recall                       |  %5.1f%%  |\n", report.Recall*100))
	sb.WriteString(fmt.Sprintf("|  F1 Score                     |  %5.1f%%  |\n", report.F1*100))
	sb.WriteString(fmt.Sprintf("|  PSB Score (0-100)            |  %6.1f  |\n", report.PSBScore))
	sb.WriteString("+-------------------------------+----------+\n")
	sb.WriteString("\n")

	// Severity distribution
	sb.WriteString("+-------------------------------+----------+\n")
	sb.WriteString("|  Severity Distribution        |  Count   |\n")
	sb.WriteString("+-------------------------------+----------+\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if c, ok := report.BySeverity[sev]; ok && c > 0 {
			sb.WriteString(fmt.Sprintf("|  %-29s|  %6d  |\n", sev, c))
		}
	}
	sb.WriteString("+-------------------------------+----------+\n")
	sb.WriteString("\n")

	// Per-OWASP breakdown
	if len(report.ByOWASP) > 0 {
		sb.WriteString("+----------+-------+--------+-----------+\n")
		sb.WriteString("|  OWASP   | Total | Vulns  | Det. Rate |\n")
		sb.WriteString("+----------+-------+--------+-----------+\n")

		owaspKeys := sortedKeys(report.ByOWASP)
		for _, k := range owaspKeys {
			cs := report.ByOWASP[k]
			sb.WriteString(fmt.Sprintf("|  %-8s|  %3d  |  %3d   |   %5.1f%%  |\n",
				k, cs.Total, cs.Vulnerable, cs.DetectionRate*100))
		}
		sb.WriteString("+----------+-------+--------+-----------+\n")
		sb.WriteString("\n")
	}

	// Per-language breakdown
	if len(report.ByLanguage) > 0 {
		sb.WriteString("+-------------+-------+--------+-----------+\n")
		sb.WriteString("|  Language   | Total | Vulns  | Det. Rate |\n")
		sb.WriteString("+-------------+-------+--------+-----------+\n")

		langKeys := sortedKeys(report.ByLanguage)
		for _, k := range langKeys {
			cs := report.ByLanguage[k]
			sb.WriteString(fmt.Sprintf("|  %-11s|  %3d  |  %3d   |   %5.1f%%  |\n",
				k, cs.Total, cs.Vulnerable, cs.DetectionRate*100))
		}
		sb.WriteString("+-------------+-------+--------+-----------+\n")
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatJSON renders a ModelReport as indented JSON.
func FormatJSON(report ModelReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling report: %w", err)
	}
	return string(data), nil
}

// FormatCSV renders a ModelReport as CSV rows (header + data).
// Each row represents one eval result.
func FormatCSV(report ModelReport) string {
	var sb strings.Builder

	sb.WriteString("prompt_id,language,model,phase,vulnerability_found,severity_max,finding_count,severity_score,cwe_matched,owasp_matched,rule_ids\n")

	for _, r := range report.Results {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%d,%t,%s,%d,%.1f,%t,%t,%s\n",
			r.PromptID,
			r.Language,
			r.Model,
			r.Phase,
			r.VulnerabilityFound,
			r.SeverityMaxLabel,
			r.FindingCount,
			r.SeverityScore,
			r.CWEMatched,
			r.OWASPMatched,
			strings.Join(r.RuleIDs, ";"),
		))
	}

	return sb.String()
}

// FormatComparisonTable renders a cross-model comparison as an ASCII table.
func FormatComparisonTable(cr ComparisonReport) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("+=================================================================+\n")
	sb.WriteString("|            ProductSecBench Model Comparison                      |\n")
	sb.WriteString("+=================================================================+\n")
	sb.WriteString("\n")

	sb.WriteString("+----------------------+----------+----------+----------+----------+\n")
	sb.WriteString("|  Model               | PSB Score| Vuln Rate|  F1 Score| Samples  |\n")
	sb.WriteString("+----------------------+----------+----------+----------+----------+\n")

	for _, m := range cr.Models {
		name := m.Model
		if len(name) > 20 {
			name = name[:20]
		}
		sb.WriteString(fmt.Sprintf("|  %-20s|  %6.1f  |  %5.1f%%  |  %5.1f%%  |  %6d  |\n",
			name, m.PSBScore, m.VulnerabilityRate*100, m.F1*100, m.TotalSamples))
	}
	sb.WriteString("+----------------------+----------+----------+----------+----------+\n")
	sb.WriteString("\n")

	// Ranking
	sb.WriteString("Ranking by PSB Score:\n")
	for i, r := range cr.Summary {
		sb.WriteString(fmt.Sprintf("  %d. %s (%.1f)\n", i+1, r.Model, r.PSBScore))
	}
	sb.WriteString("\n")

	return sb.String()
}

// FormatComparisonJSON renders a ComparisonReport as indented JSON.
func FormatComparisonJSON(cr ComparisonReport) (string, error) {
	data, err := json.MarshalIndent(cr, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling comparison: %w", err)
	}
	return string(data), nil
}

// sortedKeys returns sorted keys from a CategoryStats map.
func sortedKeys(m map[string]*CategoryStats) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
