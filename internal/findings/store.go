// Package findings provides project-local persistence of security findings.
//
// Findings are stored in .batou/findings.json at the git root (or cwd).
// Each hook invocation upserts findings — new ones are added, existing ones
// get their LastSeen updated, and findings that disappear are marked resolved.
package findings

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/turenlabs/batou/internal/rules"
)

// Status tracks the lifecycle of a finding.
type Status string

const (
	StatusActive     Status = "active"
	StatusSuppressed Status = "suppressed"
	StatusResolved   Status = "resolved"
)

// Record is a persisted finding with lifecycle metadata.
type Record struct {
	// Identity
	Key    string `json:"key"` // dedup key: hash of ruleID + filePath + matchContext
	RuleID string `json:"rule_id"`

	// Finding details
	FilePath      string         `json:"file_path"`
	LineNumber    int            `json:"line_number,omitempty"`
	Title         string         `json:"title"`
	Severity      rules.Severity `json:"severity"`
	SeverityLabel string         `json:"severity_label"`
	Confidence    string         `json:"confidence,omitempty"`
	CWEID         string         `json:"cwe_id,omitempty"`
	OWASPCategory string         `json:"owasp_category,omitempty"`
	MatchedText   string         `json:"matched_text,omitempty"`
	Suggestion    string         `json:"suggestion,omitempty"`

	// Lifecycle
	Status    Status `json:"status"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Count     int    `json:"count"` // number of times seen

	// Suppression info (when status == suppressed)
	SuppressReason string `json:"suppress_reason,omitempty"`
}

// Store manages the findings database file.
type Store struct {
	path    string
	records map[string]*Record // keyed by Record.Key
}

// FindRoot locates the .batou directory, creating it if needed.
// Searches for the git root first, falls back to cwd.
func FindRoot() (string, error) {
	// Try git root
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	var root string
	if err == nil {
		root = strings.TrimSpace(string(out))
	} else {
		root, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("getting cwd: %w", err)
		}
	}

	batouDir := filepath.Join(root, ".batou")
	if err := os.MkdirAll(batouDir, 0755); err != nil {
		return "", fmt.Errorf("creating .batou dir: %w", err)
	}
	return batouDir, nil
}

// Open loads the findings store from .batou/findings.json.
// Creates an empty store if the file doesn't exist.
func Open(batouDir string) (*Store, error) {
	path := filepath.Join(batouDir, "findings.json")
	s := &Store{
		path:    path,
		records: make(map[string]*Record),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading findings store: %w", err)
	}

	var records []*Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parsing findings store: %w", err)
	}

	for _, r := range records {
		s.records[r.Key] = r
	}
	return s, nil
}

// Save writes the store back to disk atomically.
func (s *Store) Save() error {
	records := s.allRecords()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling findings: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("writing findings temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("renaming findings file: %w", err)
	}
	return nil
}

// Upsert adds or updates a finding. Returns true if the finding is new.
func (s *Store) Upsert(f rules.Finding) bool {
	key := DedupKey(f)
	now := time.Now().UTC().Format(time.RFC3339)

	if existing, ok := s.records[key]; ok {
		existing.LastSeen = now
		existing.Count++
		existing.LineNumber = f.LineNumber
		existing.Title = f.Title
		existing.MatchedText = f.MatchedText
		if existing.Status == StatusResolved {
			existing.Status = StatusActive
		}
		return false
	}

	s.records[key] = &Record{
		Key:           key,
		RuleID:        f.RuleID,
		FilePath:      f.FilePath,
		LineNumber:    f.LineNumber,
		Title:         f.Title,
		Severity:      f.Severity,
		SeverityLabel: f.Severity.String(),
		Confidence:    f.Confidence,
		CWEID:         f.CWEID,
		OWASPCategory: f.OWASPCategory,
		MatchedText:   f.MatchedText,
		Suggestion:    f.Suggestion,
		Status:        StatusActive,
		FirstSeen:     now,
		LastSeen:      now,
		Count:         1,
	}
	return true
}

// UpsertSuppressed records a finding that was suppressed by a batou:ignore directive.
func (s *Store) UpsertSuppressed(f rules.Finding, reason string) {
	key := DedupKey(f)
	now := time.Now().UTC().Format(time.RFC3339)

	if existing, ok := s.records[key]; ok {
		existing.LastSeen = now
		existing.Count++
		existing.Status = StatusSuppressed
		existing.SuppressReason = reason
		return
	}

	s.records[key] = &Record{
		Key:            key,
		RuleID:         f.RuleID,
		FilePath:       f.FilePath,
		LineNumber:     f.LineNumber,
		Title:          f.Title,
		Severity:       f.Severity,
		SeverityLabel:  f.Severity.String(),
		Confidence:     f.Confidence,
		CWEID:          f.CWEID,
		OWASPCategory:  f.OWASPCategory,
		MatchedText:    f.MatchedText,
		Suggestion:     f.Suggestion,
		Status:         StatusSuppressed,
		FirstSeen:      now,
		LastSeen:       now,
		Count:          1,
		SuppressReason: reason,
	}
}

// MarkResolved marks all active findings for a file+ruleID combo as resolved
// if they weren't seen in the current scan. Call after upserting all findings
// from a scan of a particular file.
func (s *Store) MarkResolved(filePath string, seenKeys map[string]bool) {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range s.records {
		if r.FilePath == filePath && r.Status == StatusActive {
			if !seenKeys[r.Key] {
				r.Status = StatusResolved
				r.LastSeen = now
			}
		}
	}
}

// Active returns all findings with status "active", sorted by severity (highest first).
func (s *Store) Active() []*Record {
	return s.filter(func(r *Record) bool { return r.Status == StatusActive })
}

// Suppressed returns all findings with status "suppressed".
func (s *Store) Suppressed() []*Record {
	return s.filter(func(r *Record) bool { return r.Status == StatusSuppressed })
}

// Resolved returns all findings with status "resolved".
func (s *Store) Resolved() []*Record {
	return s.filter(func(r *Record) bool { return r.Status == StatusResolved })
}

// All returns all records regardless of status.
func (s *Store) All() []*Record {
	return s.allRecords()
}

// Summary returns counts by severity for active findings.
func (s *Store) Summary() map[string]int {
	counts := make(map[string]int)
	for _, r := range s.records {
		if r.Status == StatusActive {
			counts[r.SeverityLabel]++
		}
	}
	return counts
}

// CountByStatus returns total counts per status.
func (s *Store) CountByStatus() map[Status]int {
	counts := make(map[Status]int)
	for _, r := range s.records {
		counts[r.Status]++
	}
	return counts
}

func (s *Store) filter(fn func(*Record) bool) []*Record {
	var out []*Record
	for _, r := range s.records {
		if fn(r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].FilePath < out[j].FilePath
	})
	return out
}

func (s *Store) allRecords() []*Record {
	out := make([]*Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].FilePath < out[j].FilePath
	})
	return out
}

// DedupKey generates a stable key for a finding.
// Uses ruleID + filePath + normalized match context (not line number, since lines shift).
func DedupKey(f rules.Finding) string {
	// Normalize: use first 80 chars of matched text to absorb minor edits
	match := f.MatchedText
	if len(match) > 80 {
		match = match[:80]
	}
	raw := f.RuleID + "|" + f.FilePath + "|" + match
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:12]) // 24-char hex
}
