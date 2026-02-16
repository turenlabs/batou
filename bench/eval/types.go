// Package eval provides the ProductSecBench evaluation harness.
//
// It uses Batou's scanner infrastructure to score LLM-generated code samples
// against a corpus of security-focused prompts, computing per-model metrics
// like vulnerability rate, severity distribution, OWASP coverage, and a
// composite ProductSec Score (0-100).
package eval

import (
	"github.com/turenlabs/batou/internal/rules"
)

// SeverityWeight maps severity levels to numeric weights used in composite scoring.
var SeverityWeight = map[rules.Severity]float64{
	rules.Critical: 10.0,
	rules.High:     7.0,
	rules.Medium:   4.0,
	rules.Low:      1.0,
	rules.Info:     0.0,
}

// Prompt describes a single benchmark prompt from the corpus.
// Fields mirror the YAML schema but are parsed from JSON (zero-deps).
type Prompt struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	OWASP       string   `json:"owasp"`        // e.g. "A03"
	CWEs        []string `json:"cwes"`          // e.g. ["CWE-89"]
	Languages   []string `json:"languages"`     // e.g. ["python","go"]
	Difficulty  string   `json:"difficulty"`     // easy, medium, hard
	Category    string   `json:"category"`       // e.g. "injection"
	PromptText  string   `json:"prompt_text"`    // the actual prompt sent to the LLM
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// GeneratedSample represents code produced by an LLM for a given prompt.
type GeneratedSample struct {
	PromptID string `json:"prompt_id"`
	Language string `json:"language"` // e.g. "python"
	Code     string `json:"code"`
	Model    string `json:"model,omitempty"`
	Phase    int    `json:"phase,omitempty"` // 1=initial, 4=after-hint
}

// EvalResult holds scoring results for a single sample.
type EvalResult struct {
	PromptID           string         `json:"prompt_id"`
	Language           string         `json:"language"`
	Model              string         `json:"model,omitempty"`
	Phase              int            `json:"phase,omitempty"`
	VulnerabilityFound bool           `json:"vulnerability_found"`
	SeverityMax        rules.Severity `json:"severity_max"`
	SeverityMaxLabel   string         `json:"severity_max_label"`
	RuleIDs            []string       `json:"rule_ids"`
	CWEMatched         bool           `json:"cwe_matched"`
	OWASPMatched       bool           `json:"owasp_matched"`
	FindingCount       int            `json:"finding_count"`
	SeverityScore      float64        `json:"severity_score"`
}

// ModelReport aggregates metrics across all samples for one model.
type ModelReport struct {
	Model              string  `json:"model"`
	TotalSamples       int     `json:"total_samples"`
	VulnerableCount    int     `json:"vulnerable_count"`
	VulnerabilityRate  float64 `json:"vulnerability_rate"`
	SeverityScoreTotal float64 `json:"severity_score_total"`
	SeverityScoreAvg   float64 `json:"severity_score_avg"`
	CWEMatchRate       float64 `json:"cwe_match_rate"`
	OWASPMatchRate     float64 `json:"owasp_match_rate"`
	Precision          float64 `json:"precision"`
	Recall             float64 `json:"recall"`
	F1                 float64 `json:"f1"`
	PSBScore           float64 `json:"psb_score"` // composite 0-100

	// Breakdowns
	ByOWASP    map[string]*CategoryStats `json:"by_owasp"`
	ByLanguage map[string]*CategoryStats `json:"by_language"`
	BySeverity map[string]int            `json:"by_severity"`

	Results []EvalResult `json:"results,omitempty"`
}

// CategoryStats holds aggregate stats for an OWASP category or language.
type CategoryStats struct {
	Total          int     `json:"total"`
	Vulnerable     int     `json:"vulnerable"`
	DetectionRate  float64 `json:"detection_rate"`
	AvgSeverity    float64 `json:"avg_severity"`
}

// ComparisonReport compares multiple models side by side.
type ComparisonReport struct {
	Models  []ModelReport `json:"models"`
	Summary []ModelRank   `json:"summary"`
}

// ModelRank is a single row in the comparison summary.
type ModelRank struct {
	Model             string  `json:"model"`
	PSBScore          float64 `json:"psb_score"`
	VulnerabilityRate float64 `json:"vulnerability_rate"`
	F1                float64 `json:"f1"`
}
