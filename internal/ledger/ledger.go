package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/turenlabs/batou/internal/reporter"
	"github.com/turenlabs/batou/internal/rules"
)

// Entry represents a single scan event in the audit ledger.
type Entry struct {
	Timestamp       string          `json:"timestamp"`
	SessionID       string          `json:"session_id"`
	Event           string          `json:"event"`
	FilePath        string          `json:"file_path"`
	Language        rules.Language  `json:"language"`
	FindingCount    int             `json:"finding_count"`
	SuppressedCount int             `json:"suppressed_count,omitempty"`
	SuppressedRules []string        `json:"suppressed_rules,omitempty"`
	MaxSeverity     string          `json:"max_severity"`
	Blocked         bool            `json:"blocked"`
	Findings        []rules.Finding `json:"findings,omitempty"`
	RulesRun        int             `json:"rules_run"`
	ScanTimeMs      int64           `json:"scan_time_ms"`
}

// ledgerDir returns the directory for Batou ledger files.
func ledgerDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/.batou"
	}
	return filepath.Join(home, ".batou", "ledger")
}

// Record writes a scan result to the ledger as a JSONL entry.
func Record(sessionID string, result *reporter.ScanResult) error {
	dir := ledgerDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating ledger dir: %w", err)
	}

	// Collect suppressed rule IDs for the audit log.
	var suppressedRules []string
	for _, f := range result.SuppressedFindings {
		suppressedRules = append(suppressedRules, f.RuleID)
	}

	entry := Entry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		SessionID:       sessionID,
		Event:           result.Event,
		FilePath:        result.FilePath,
		Language:        result.Language,
		FindingCount:    len(result.Findings),
		SuppressedCount: result.SuppressedCount,
		SuppressedRules: suppressedRules,
		MaxSeverity:     result.MaxSeverity().String(),
		Blocked:         result.ShouldBlock(),
		Findings:        result.Findings,
		RulesRun:        result.RulesRun,
		ScanTimeMs:      result.ScanTimeMs,
	}

	// Write to daily ledger file
	dateStr := time.Now().UTC().Format("2006-01-02")
	ledgerFile := filepath.Join(dir, fmt.Sprintf("batou-%s.jsonl", dateStr))

	f, err := os.OpenFile(ledgerFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening ledger file: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling ledger entry: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("writing ledger entry: %w", err)
	}

	return nil
}
