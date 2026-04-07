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
	"syscall"
	"time"

	"github.com/turenlabs/batou-rules/rules"
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
	Confidence      string         `json:"confidence,omitempty"`
	ConfidenceScore float64        `json:"confidence_score,omitempty"`
	CWEID           string         `json:"cwe_id,omitempty"`
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
	path     string
	records  map[string]*Record // keyed by Record.Key
	lockFile *os.File           // exclusive lock held during Open→Save
}

// FindRoot locates the .batou directory, creating it if needed.
// Searches for the git root first (anchored to filePath's directory),
// then falls back to the file's parent directory. This ensures findings
// are stored near the scanned file, not in a random cwd.
func FindRoot(filePath ...string) (string, error) {
	// Determine the directory to anchor the search.
	anchor := ""
	if len(filePath) > 0 && filePath[0] != "" {
		anchor = filepath.Dir(filePath[0])
	}

	// Try git root from the file's directory.
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	if anchor != "" {
		cmd.Dir = anchor
	}
	out, err := cmd.Output()
	var root string
	if err == nil {
		root = strings.TrimSpace(string(out))
	} else if anchor != "" {
		// No git root — use the file's directory.
		root = anchor
	} else {
		// No file path and no git root — last resort: cwd.
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
// Acquires an exclusive file lock to prevent concurrent corruption.
func Open(batouDir string) (*Store, error) {
	path := filepath.Join(batouDir, "findings.json")
	lockPath := filepath.Join(batouDir, "findings.lock")

	// Acquire exclusive lock with timeout. If we can't get it in 2s,
	// proceed without the lock rather than blocking the scan.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		// Can't open lock file — proceed without lock
		fmt.Fprintf(os.Stderr, "Batou: findings lock unavailable: %v\n", err)
	} else if err := tryLock(lockFile, 2*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings lock timeout, proceeding unlocked\n")
		_ = lockFile.Close()
		lockFile = nil
	}

	s := &Store{
		path:     path,
		records:  make(map[string]*Record),
		lockFile: lockFile,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		s.unlock() // release lock before returning error
		return nil, fmt.Errorf("reading findings store: %w", err)
	}

	var records []*Record
	if err := json.Unmarshal(data, &records); err != nil {
		// Self-heal: corrupted findings.json (e.g. concatenated arrays from
		// old versions). Start fresh rather than failing every scan.
		fmt.Fprintf(os.Stderr, "Batou: findings store corrupted, starting fresh: %v\n", err)
		return s, nil
	}

	for _, r := range records {
		s.records[r.Key] = r
	}
	return s, nil
}

// Save writes the store back to disk atomically and releases the file lock.
func (s *Store) Save() error {
	defer s.unlock()

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
		existing.ConfidenceScore = f.ConfidenceScore
		if existing.Status == StatusResolved {
			existing.Status = StatusActive
		}
		return false
	}

	s.records[key] = &Record{
		Key:             key,
		RuleID:          f.RuleID,
		FilePath:        f.FilePath,
		LineNumber:      f.LineNumber,
		Title:           f.Title,
		Severity:        f.Severity,
		SeverityLabel:   f.Severity.String(),
		Confidence:      f.Confidence,
		ConfidenceScore: f.ConfidenceScore,
		CWEID:           f.CWEID,
		OWASPCategory:   f.OWASPCategory,
		MatchedText:     f.MatchedText,
		Suggestion:      f.Suggestion,
		Status:          StatusActive,
		FirstSeen:       now,
		LastSeen:        now,
		Count:           1,
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
		Key:             key,
		RuleID:          f.RuleID,
		FilePath:        f.FilePath,
		LineNumber:      f.LineNumber,
		Title:           f.Title,
		Severity:        f.Severity,
		SeverityLabel:   f.Severity.String(),
		Confidence:      f.Confidence,
		ConfidenceScore: f.ConfidenceScore,
		CWEID:           f.CWEID,
		OWASPCategory:   f.OWASPCategory,
		MatchedText:     f.MatchedText,
		Suggestion:      f.Suggestion,
		Status:          StatusSuppressed,
		FirstSeen:       now,
		LastSeen:        now,
		Count:           1,
		SuppressReason:  reason,
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

// Deltas captures the lifecycle changes between a new scan and the stored state.
type Deltas struct {
	New        []rules.Finding // First time seen
	Recurring  []rules.Finding // Seen before (with Count from store)
	Fixed      []Record        // Were active, now gone from scan
	Suppressed []Record        // Marked as suppressed

	recurringCounts map[string]int // key → count (unexported, accessed via RecurringCount)
}

// RecurringCount returns the store's Count for a recurring finding (how many
// times it has been seen including this scan). Returns 0 if not found.
func (d *Deltas) RecurringCount(f rules.Finding) int {
	key := DedupKey(f)
	for _, r := range d.Recurring {
		if DedupKey(r) == key {
			return d.recurringCounts[key]
		}
	}
	return 0
}

// ComputeDeltas compares the current scan findings for a file against the
// stored state. It upserts findings, marks missing ones as resolved, and
// returns the lifecycle deltas for hint rendering.
// suppressedFindings are included in seenKeys so MarkResolved doesn't
// incorrectly mark them as resolved (they transition to suppressed separately).
func (s *Store) ComputeDeltas(filePath string, currentFindings []rules.Finding, suppressedFindings ...[]rules.Finding) *Deltas {
	d := &Deltas{
		recurringCounts: make(map[string]int),
	}

	seenKeys := make(map[string]bool)

	// Include suppressed findings in seenKeys so MarkResolved doesn't
	// mark them as resolved — they'll be transitioned to suppressed
	// by UpsertSuppressed separately.
	for _, sf := range suppressedFindings {
		for _, f := range sf {
			seenKeys[DedupKey(f)] = true
		}
	}

	for _, f := range currentFindings {
		key := DedupKey(f)
		seenKeys[key] = true

		if existing, ok := s.records[key]; ok && existing.Status != StatusResolved {
			// Existing active/suppressed finding — recurring
			d.Recurring = append(d.Recurring, f)
			// Increment count to reflect this scan (Upsert will also do this,
			// but we capture the post-increment value for hint display)
			d.recurringCounts[key] = existing.Count + 1
		} else {
			d.New = append(d.New, f)
		}

		// Upsert into the store
		s.Upsert(f)
	}

	// Find active findings for this file that are no longer present → fixed
	for _, r := range s.records {
		if r.FilePath == filePath && r.Status == StatusActive && !seenKeys[r.Key] {
			d.Fixed = append(d.Fixed, *r)
		}
	}

	// Collect only NEWLY suppressed findings — those that were active before
	// this scan and are now being suppressed. Already-suppressed findings from
	// prior scans should not be re-sent to downstream consumers.
	for _, sf := range suppressedFindings {
		for _, f := range sf {
			key := DedupKey(f)
			if existing, ok := s.records[key]; ok && existing.Status == StatusActive {
				d.Suppressed = append(d.Suppressed, *existing)
			}
		}
	}

	// Mark resolved
	s.MarkResolved(filePath, seenKeys)

	return d
}

// DedupKey generates a stable key for a finding that persists across scans.
//
// For taint findings (BATOU-TAINT-*): uses RuleID + FilePath + CWEID.
// This is stable because the taint category and file don't change even when
// the flow description text shifts due to line number changes.
//
// For other findings: uses RuleID + FilePath + normalized MatchedText.
// MatchedText is the actual code pattern which is stable for regex/AST findings.
//
// Line numbers are excluded — they shift when code is edited above the finding.
func DedupKey(f rules.Finding) string {
	var raw string
	if strings.HasPrefix(f.RuleID, "BATOU-TAINT") || strings.HasPrefix(f.RuleID, "BATOU-INTERPROC") {
		// Taint/interproc findings: use CWE as the stable anchor.
		// Same taint category in the same file = same finding.
		raw = f.RuleID + "|" + f.FilePath + "|" + f.CWEID
	} else {
		// Regex/AST findings: use matched text as the anchor.
		match := f.MatchedText
		if len(match) > 80 {
			match = match[:80]
		}
		raw = f.RuleID + "|" + f.FilePath + "|" + match
	}
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:12]) // 24-char hex
}

// tryLock attempts to acquire an exclusive flock with a timeout.
// Uses non-blocking LOCK_NB in a retry loop to avoid permanent deadlock
// if a previous batou process crashed while holding the lock.
func tryLock(f *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("lock timeout after %s", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// unlock releases the file lock acquired during Open and removes the lock file.
func (s *Store) unlock() {
	if s.lockFile != nil {
		name := s.lockFile.Name()
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		_ = s.lockFile.Close()
		s.lockFile = nil
		// Best-effort cleanup — lock file is harmless if removal fails
		// (e.g., another process already removed it).
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Batou: lock cleanup: %v\n", err)
		}
	}
}
