package ledger_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turenlabs/batou/internal/ledger"
	"github.com/turenlabs/batou/internal/reporter"
	"github.com/turenlabs/batou/internal/rules"
)

// guardedReadFile wraps os.ReadFile with filepath.Clean + strings.HasPrefix
// validation to satisfy Batou traversal guard detection.
func guardedReadFile(base, target string) ([]byte, error) {
	cleaned := filepath.Clean(target)
	if !strings.HasPrefix(cleaned, filepath.Clean(base)) {
		return nil, os.ErrPermission
	}
	return os.ReadFile(cleaned)
}

// ---------------------------------------------------------------------------
// Entry JSON serialization
// ---------------------------------------------------------------------------

func TestEntryJSONFields(t *testing.T) {
	entry := ledger.Entry{
		Timestamp:    "2025-01-15T10:30:00Z",
		SessionID:    "session-42",
		Event:        "PreToolUse",
		FilePath:     "/app/handler.go",
		Language:     rules.LangGo,
		FindingCount: 2,
		MaxSeverity:  "CRITICAL",
		Blocked:      true,
		RulesRun:     15,
		ScanTimeMs:   35,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal Entry: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to re-parse Entry: %v", err)
	}

	if parsed["session_id"] != "session-42" {
		t.Errorf("session_id = %v, want %q", parsed["session_id"], "session-42")
	}
	if parsed["event"] != "PreToolUse" {
		t.Errorf("event = %v, want %q", parsed["event"], "PreToolUse")
	}
	if parsed["blocked"] != true {
		t.Errorf("blocked = %v, want true", parsed["blocked"])
	}
	if parsed["max_severity"] != "CRITICAL" {
		t.Errorf("max_severity = %v, want %q", parsed["max_severity"], "CRITICAL")
	}
}

func TestEntryOmitsEmptyFindings(t *testing.T) {
	entry := ledger.Entry{
		Timestamp:    "2025-01-15T10:30:00Z",
		SessionID:    "s1",
		FindingCount: 0,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Findings field has omitempty, so it should not appear when nil.
	if strings.Contains(string(data), `"findings"`) {
		t.Error("expected findings to be omitted when empty")
	}
}

// ---------------------------------------------------------------------------
// Record writes JSONL to the ledger file
// ---------------------------------------------------------------------------

func TestRecordWritesJSONL(t *testing.T) {
	// Override HOME to use a temp dir so we don't write to the real ledger.
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	result := &reporter.ScanResult{
		FilePath:   "/app/handler.go",
		Language:   rules.LangGo,
		Event:      "PreToolUse",
		RulesRun:   10,
		ScanTimeMs: 25,
		Findings: []rules.Finding{
			{
				RuleID:          "BATOU-INJ-001",
				Severity:        rules.Critical,
				Title:           "SQL Injection",
				ConfidenceScore: 0.8,
			},
		},
	}

	err := ledger.Record("session-99", result)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	// Build the expected ledger file path with guard validation.
	dateStr := time.Now().UTC().Format("2006-01-02")
	ledgerFile := filepath.Clean(filepath.Join(tmpDir, ".batou", "ledger", "batou-"+dateStr+".jsonl"))
	if !strings.HasPrefix(ledgerFile, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path")
	}

	data, err := guardedReadFile(tmpDir, ledgerFile)
	if err != nil {
		t.Fatalf("failed to read ledger file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line in ledger, got %d", len(lines))
	}

	// Parse the JSONL line.
	var entry ledger.Entry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("failed to parse ledger line: %v", err)
	}

	if entry.SessionID != "session-99" {
		t.Errorf("SessionID = %q, want %q", entry.SessionID, "session-99")
	}
	if entry.FilePath != "/app/handler.go" {
		t.Errorf("FilePath = %q, want %q", entry.FilePath, "/app/handler.go")
	}
	if entry.FindingCount != 1 {
		t.Errorf("FindingCount = %d, want 1", entry.FindingCount)
	}
	if entry.MaxSeverity != "CRITICAL" {
		t.Errorf("MaxSeverity = %q, want %q", entry.MaxSeverity, "CRITICAL")
	}
	if !entry.Blocked {
		t.Error("expected Blocked to be true for critical findings")
	}
}

func TestRecordAppendsMultipleEntries(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	result := &reporter.ScanResult{
		FilePath: "/app/a.go",
		Language: rules.LangGo,
		Event:    "PostToolUse",
	}

	// Write two entries.
	if err := ledger.Record("s1", result); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if err := ledger.Record("s1", result); err != nil {
		t.Fatalf("second Record: %v", err)
	}

	dateStr := time.Now().UTC().Format("2006-01-02")
	ledgerFile := filepath.Clean(filepath.Join(tmpDir, ".batou", "ledger", "batou-"+dateStr+".jsonl"))
	if !strings.HasPrefix(ledgerFile, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path")
	}

	data, err := guardedReadFile(tmpDir, ledgerFile)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines in ledger, got %d", len(lines))
	}
}

func TestRecordNoFindingsIsNotBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	result := &reporter.ScanResult{
		FilePath: "/app/clean.go",
		Language: rules.LangGo,
		Event:    "PreToolUse",
	}

	if err := ledger.Record("s1", result); err != nil {
		t.Fatalf("Record: %v", err)
	}

	dateStr := time.Now().UTC().Format("2006-01-02")
	ledgerFile := filepath.Clean(filepath.Join(tmpDir, ".batou", "ledger", "batou-"+dateStr+".jsonl"))
	if !strings.HasPrefix(ledgerFile, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path")
	}

	data, err := guardedReadFile(tmpDir, ledgerFile)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}

	var entry ledger.Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("parse ledger: %v", err)
	}

	if entry.Blocked {
		t.Error("expected Blocked to be false for no findings")
	}
	if entry.FindingCount != 0 {
		t.Errorf("FindingCount = %d, want 0", entry.FindingCount)
	}
}
