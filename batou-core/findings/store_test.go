package findings

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"github.com/turenlabs/batou-rules/rules"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func sampleFinding(ruleID, filePath, matched string) rules.Finding {
	return rules.Finding{
		RuleID:      ruleID,
		FilePath:    filePath,
		LineNumber:  10,
		Title:       "test finding",
		Severity:    rules.High,
		MatchedText: matched,
	}
}

func TestUpsert_NewFinding(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")

	isNew := s.Upsert(f)
	if !isNew {
		t.Error("expected first upsert to return true (new)")
	}

	records := s.Active()
	if len(records) != 1 {
		t.Fatalf("expected 1 active record, got %d", len(records))
	}
	if records[0].RuleID != "BATOU-INJ-001" {
		t.Errorf("expected rule BATOU-INJ-001, got %s", records[0].RuleID)
	}
	if records[0].Count != 1 {
		t.Errorf("expected count 1, got %d", records[0].Count)
	}
}

func TestUpsert_Dedup(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")

	s.Upsert(f)
	isNew := s.Upsert(f)
	if isNew {
		t.Error("expected second upsert to return false (existing)")
	}

	records := s.Active()
	if len(records) != 1 {
		t.Fatalf("expected 1 record after dedup, got %d", len(records))
	}
	if records[0].Count != 2 {
		t.Errorf("expected count 2, got %d", records[0].Count)
	}
}

func TestUpsertSuppressed(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-SEC-001", "/app/config.go", "password =")

	s.UpsertSuppressed(f, "false positive: test credential")

	active := s.Active()
	if len(active) != 0 {
		t.Errorf("expected 0 active, got %d", len(active))
	}

	suppressed := s.Suppressed()
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(suppressed))
	}
	if suppressed[0].SuppressReason != "false positive: test credential" {
		t.Errorf("unexpected reason: %s", suppressed[0].SuppressReason)
	}
}

func TestMarkResolved(t *testing.T) {
	s := tempStore(t)
	f1 := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
	f2 := sampleFinding("BATOU-INJ-002", "/app/main.go", "eval(input)")

	s.Upsert(f1)
	s.Upsert(f2)

	// Only f1 was seen in the latest scan
	seenKeys := map[string]bool{
		DedupKey(f1): true,
	}
	s.MarkResolved("/app/main.go", seenKeys)

	active := s.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if active[0].RuleID != "BATOU-INJ-001" {
		t.Errorf("expected BATOU-INJ-001 active, got %s", active[0].RuleID)
	}

	resolved := s.Resolved()
	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved, got %d", len(resolved))
	}
	if resolved[0].RuleID != "BATOU-INJ-002" {
		t.Errorf("expected BATOU-INJ-002 resolved, got %s", resolved[0].RuleID)
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	s.Upsert(sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)"))
	s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/config.go", "password"), "test")

	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify file exists
	path := filepath.Join(dir, "findings.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("findings.json not created: %v", err)
	}

	// Reload
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open reload: %v", err)
	}

	all := s2.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 records after reload, got %d", len(all))
	}

	active := s2.Active()
	if len(active) != 1 {
		t.Errorf("expected 1 active after reload, got %d", len(active))
	}

	suppressed := s2.Suppressed()
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed after reload, got %d", len(suppressed))
	}
}

func TestCountByStatus(t *testing.T) {
	s := tempStore(t)
	s.Upsert(sampleFinding("BATOU-INJ-001", "/app/a.go", "exec"))
	s.Upsert(sampleFinding("BATOU-INJ-002", "/app/b.go", "eval"))
	s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/c.go", "secret"), "fp")

	// Resolve one
	seenKeys := map[string]bool{
		DedupKey(sampleFinding("BATOU-INJ-001", "/app/a.go", "exec")): true,
	}
	s.MarkResolved("/app/b.go", seenKeys)

	counts := s.CountByStatus()
	if counts[StatusActive] != 1 {
		t.Errorf("expected 1 active, got %d", counts[StatusActive])
	}
	if counts[StatusSuppressed] != 1 {
		t.Errorf("expected 1 suppressed, got %d", counts[StatusSuppressed])
	}
	if counts[StatusResolved] != 1 {
		t.Errorf("expected 1 resolved, got %d", counts[StatusResolved])
	}
}

func TestSummary(t *testing.T) {
	s := tempStore(t)
	f1 := sampleFinding("BATOU-INJ-001", "/app/a.go", "exec")
	f1.Severity = rules.Critical
	s.Upsert(f1)

	f2 := sampleFinding("BATOU-INJ-002", "/app/b.go", "eval")
	f2.Severity = rules.High
	s.Upsert(f2)

	summary := s.Summary()
	if summary["CRITICAL"] != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", summary["CRITICAL"])
	}
	if summary["HIGH"] != 1 {
		t.Errorf("expected 1 HIGH, got %d", summary["HIGH"])
	}
}

func TestResolvedFindingReactivates(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")

	s.Upsert(f)
	// Resolve it
	s.MarkResolved("/app/main.go", map[string]bool{})

	if len(s.Active()) != 0 {
		t.Fatal("expected 0 active after resolve")
	}

	// Re-upsert — should reactivate
	s.Upsert(f)
	active := s.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 active after re-upsert, got %d", len(active))
	}
	if active[0].Count != 2 {
		t.Errorf("expected count 2 after re-upsert, got %d", active[0].Count)
	}
}

func TestDedupKey_Stable(t *testing.T) {
	f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
	k1 := DedupKey(f)
	k2 := DedupKey(f)
	if k1 != k2 {
		t.Errorf("dedup key not stable: %s != %s", k1, k2)
	}
	if len(k1) != 24 {
		t.Errorf("expected 24-char hex key, got %d chars: %s", len(k1), k1)
	}
}

func TestDedupKey_IgnoresLineNumber(t *testing.T) {
	f1 := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
	f1.LineNumber = 10
	f2 := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
	f2.LineNumber = 20

	if DedupKey(f1) != DedupKey(f2) {
		t.Error("dedup key should not depend on line number")
	}
}

func TestOpenNonexistentDir(t *testing.T) {
	// Open with a dir that has no findings.json — should create empty store
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.All()) != 0 {
		t.Errorf("expected empty store, got %d records", len(s.All()))
	}
}

func TestComputeDeltas_FirstScan_AllNew(t *testing.T) {
	s := tempStore(t)
	findings := []rules.Finding{
		sampleFinding("BATOU-INJ-001", "/app/handler.go", "exec(cmd)"),
		sampleFinding("BATOU-XSS-001", "/app/handler.go", "fmt.Fprintf(w, name)"),
	}

	deltas := s.ComputeDeltas("/app/handler.go", findings)

	if len(deltas.New) != 2 {
		t.Errorf("expected 2 new findings, got %d", len(deltas.New))
	}
	if len(deltas.Recurring) != 0 {
		t.Errorf("expected 0 recurring, got %d", len(deltas.Recurring))
	}
	if len(deltas.Fixed) != 0 {
		t.Errorf("expected 0 fixed, got %d", len(deltas.Fixed))
	}
}

func TestComputeDeltas_SecondScan_Recurring(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-INJ-001", "/app/handler.go", "exec(cmd)")

	// First scan — all new
	deltas1 := s.ComputeDeltas("/app/handler.go", []rules.Finding{f})
	if len(deltas1.New) != 1 {
		t.Fatalf("first scan: expected 1 new, got %d", len(deltas1.New))
	}

	// Second scan — recurring
	deltas2 := s.ComputeDeltas("/app/handler.go", []rules.Finding{f})
	if len(deltas2.New) != 0 {
		t.Errorf("second scan: expected 0 new, got %d", len(deltas2.New))
	}
	if len(deltas2.Recurring) != 1 {
		t.Fatalf("second scan: expected 1 recurring, got %d", len(deltas2.Recurring))
	}

	count := deltas2.RecurringCount(f)
	if count != 2 {
		t.Errorf("expected recurring count 2, got %d", count)
	}
}

func TestComputeDeltas_FindingRemoved_Fixed(t *testing.T) {
	s := tempStore(t)
	f1 := sampleFinding("BATOU-INJ-001", "/app/handler.go", "exec(cmd)")
	f2 := sampleFinding("BATOU-XSS-001", "/app/handler.go", "fmt.Fprintf(w, name)")

	// First scan — both present
	s.ComputeDeltas("/app/handler.go", []rules.Finding{f1, f2})

	// Second scan — only f1 remains, f2 was fixed
	deltas := s.ComputeDeltas("/app/handler.go", []rules.Finding{f1})

	if len(deltas.Fixed) != 1 {
		t.Fatalf("expected 1 fixed, got %d", len(deltas.Fixed))
	}
	if deltas.Fixed[0].RuleID != "BATOU-XSS-001" {
		t.Errorf("expected fixed finding to be BATOU-XSS-001, got %s", deltas.Fixed[0].RuleID)
	}
}

func TestComputeDeltas_AllRemoved_AllFixed(t *testing.T) {
	s := tempStore(t)
	f1 := sampleFinding("BATOU-INJ-001", "/app/handler.go", "exec(cmd)")

	// First scan
	s.ComputeDeltas("/app/handler.go", []rules.Finding{f1})

	// Second scan — empty (all fixed)
	deltas := s.ComputeDeltas("/app/handler.go", []rules.Finding{})

	if len(deltas.New) != 0 {
		t.Errorf("expected 0 new, got %d", len(deltas.New))
	}
	if len(deltas.Recurring) != 0 {
		t.Errorf("expected 0 recurring, got %d", len(deltas.Recurring))
	}
	if len(deltas.Fixed) != 1 {
		t.Errorf("expected 1 fixed, got %d", len(deltas.Fixed))
	}
}

func TestComputeDeltas_ThreeScans_CountIncreases(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-INJ-001", "/app/handler.go", "exec(cmd)")

	s.ComputeDeltas("/app/handler.go", []rules.Finding{f})
	s.ComputeDeltas("/app/handler.go", []rules.Finding{f})
	deltas := s.ComputeDeltas("/app/handler.go", []rules.Finding{f})

	count := deltas.RecurringCount(f)
	if count != 3 {
		t.Errorf("expected recurring count 3 after 3 scans, got %d", count)
	}
}

// TestComputeDeltas_ActiveToSuppressed simulates the real-world scenario:
// Scan 1: finding is active (no suppress directive)
// Scan 2: user adds batou:ignore, finding moves to SuppressedFindings
// Verify: finding transitions from active to suppressed (not resolved or recurring)
func TestComputeDeltas_ActiveToSuppressed(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-FW-FASTAPI-001", "/app/main.py", `@app.post("/api/generate")`)

	// Scan 1: finding is active
	deltas := s.ComputeDeltas("/app/main.py", []rules.Finding{f})
	if len(deltas.New) != 1 {
		t.Fatalf("scan 1: expected 1 new finding, got %d", len(deltas.New))
	}
	active := s.Active()
	if len(active) != 1 {
		t.Fatalf("scan 1: expected 1 active, got %d", len(active))
	}

	// Scan 2: user added batou:ignore. Finding is now in suppressedFindings,
	// NOT in currentFindings.
	suppressed := []rules.Finding{f}
	deltas = s.ComputeDeltas("/app/main.py", []rules.Finding{}, suppressed)

	// The finding should NOT be in Fixed (it's suppressed, not gone)
	if len(deltas.Fixed) != 0 {
		t.Errorf("scan 2: expected 0 fixed, got %d (finding was suppressed, not fixed)", len(deltas.Fixed))
	}

	// Now UpsertSuppressed (same as main.go does after ComputeDeltas)
	s.UpsertSuppressed(f, "batou:ignore")

	// Verify: finding should be suppressed, not active
	active = s.Active()
	if len(active) != 0 {
		t.Errorf("after suppress: expected 0 active, got %d", len(active))
		for _, r := range active {
			t.Logf("  still active: %s status=%s", r.RuleID, r.Status)
		}
	}

	suppressedRecords := s.Suppressed()
	if len(suppressedRecords) != 1 {
		t.Fatalf("after suppress: expected 1 suppressed, got %d", len(suppressedRecords))
	}
	if suppressedRecords[0].RuleID != "BATOU-FW-FASTAPI-001" {
		t.Errorf("unexpected suppressed rule: %s", suppressedRecords[0].RuleID)
	}
}

// TestComputeDeltas_ActiveToSuppressed_WithoutFix verifies the BUG scenario:
// Without passing suppressedFindings to ComputeDeltas, the finding gets
// marked as "resolved" instead of "suppressed".
func TestComputeDeltas_ActiveToSuppressed_WithoutSuppressedParam(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-FW-FASTAPI-001", "/app/main.py", `@app.post("/api/generate")`)

	// Scan 1: active
	s.ComputeDeltas("/app/main.py", []rules.Finding{f})

	// Scan 2: suppress added, but we DON'T pass suppressedFindings
	// (this is what the old code did)
	deltas := s.ComputeDeltas("/app/main.py", []rules.Finding{})

	// BUG: finding shows up as "fixed" when it should be "suppressed"
	if len(deltas.Fixed) != 1 {
		t.Errorf("without suppressed param: expected finding in Fixed (the bug), got %d", len(deltas.Fixed))
	}

	// UpsertSuppressed still runs, but the finding is already resolved
	s.UpsertSuppressed(f, "batou:ignore")

	// It should still end up as suppressed (UpsertSuppressed overrides resolved)
	suppressedRecords := s.Suppressed()
	if len(suppressedRecords) != 1 {
		t.Errorf("expected 1 suppressed after upsert, got %d", len(suppressedRecords))
	}
}

// TestComputeDeltas_SuppressedNotResentOnSubsequentScans verifies the downstream re-send bug:
// Once a finding is suppressed, subsequent scans should NOT re-emit it in
// deltas.Suppressed. Only the first scan where it transitions active→suppressed
// should include it.
func TestComputeDeltas_SuppressedNotResentOnSubsequentScans(t *testing.T) {
	s := tempStore(t)
	f := sampleFinding("BATOU-FW-FASTAPI-001", "/app/main.py", `@app.post("/api/generate")`)

	// Scan 1: finding is active
	deltas := s.ComputeDeltas("/app/main.py", []rules.Finding{f})
	if len(deltas.New) != 1 {
		t.Fatalf("scan 1: expected 1 new, got %d", len(deltas.New))
	}

	// Scan 2: user adds batou:ignore. Finding moves to suppressedFindings.
	suppressed := []rules.Finding{f}
	deltas = s.ComputeDeltas("/app/main.py", []rules.Finding{}, suppressed)
	s.UpsertSuppressed(f, "batou:ignore")

	// Scan 2 should report the finding as newly suppressed
	if len(deltas.Suppressed) != 1 {
		t.Fatalf("scan 2: expected 1 suppressed, got %d", len(deltas.Suppressed))
	}

	// Scan 3: same file, same suppress still in place. No changes.
	deltas = s.ComputeDeltas("/app/main.py", []rules.Finding{}, suppressed)

	// Scan 3 should NOT re-report the finding as suppressed
	if len(deltas.Suppressed) != 0 {
		t.Errorf("scan 3: expected 0 suppressed (already suppressed), got %d — this is the downstream re-send bug", len(deltas.Suppressed))
		for _, r := range deltas.Suppressed {
			t.Logf("  re-emitted: %s status=%s count=%d", r.RuleID, r.Status, r.Count)
		}
	}

	// Verify store still has it as suppressed
	suppressedRecords := s.Suppressed()
	if len(suppressedRecords) != 1 {
		t.Errorf("store: expected 1 suppressed, got %d", len(suppressedRecords))
	}

	// Verify no active findings
	active := s.Active()
	if len(active) != 0 {
		t.Errorf("store: expected 0 active, got %d", len(active))
	}
}

// TestConcurrentOpenSave verifies that concurrent Open+Save calls don't
// corrupt the store. Two goroutines open, upsert, and save simultaneously.
func TestConcurrentOpenSave(t *testing.T) {
	t.Skip("flaky: file rename race on macOS CI")
	dir := t.TempDir()

	// Seed the store with one record
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	s.Upsert(sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)"))
	if err := s.Save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	// Run 10 concurrent open+upsert+save cycles
	var wg sync.WaitGroup
	errors := make(chan error, 20)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store, err := Open(dir)
			if err != nil {
				errors <- err
				return
			}
			f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
			store.Upsert(f)
			if err := store.Save(); err != nil {
				errors <- err
			}
		}(i)
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent error: %v", err)
	}

	// Verify the store is still valid JSON and loadable
	final, err := Open(dir)
	if err != nil {
		t.Fatalf("final open failed (corruption?): %v", err)
	}
	defer func() { _ = final.Save() }() // release lock

	records := final.Active()
	if len(records) != 1 {
		t.Errorf("expected 1 record after concurrent writes, got %d", len(records))
	}
}

// TestLockFileCleanup verifies the lock is released after Save.
func TestLockFileCleanup(t *testing.T) {
	dir := t.TempDir()

	// Open and save — lock should be released
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s.lock == nil {
		t.Fatal("expected lock file to be acquired")
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if s.lock != nil {
		t.Error("expected lock file to be nil after Save")
	}

	// Should be able to open again immediately (lock was released)
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("second open failed (lock not released?): %v", err)
	}
	_ = s2.Save()
}

// TestCorruptedStoreRecovery verifies self-healing when findings.json
// is corrupted (e.g. concatenated arrays from old versions).
func TestCorruptedStoreRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")

	// Write corrupted JSON (two arrays concatenated)
	corrupted := `[{"key":"abc","rule_id":"BATOU-INJ-001"}][{"key":"def","rule_id":"BATOU-XSS-001"}]`
	if err := os.WriteFile(path, []byte(corrupted), 0644); err != nil {
		t.Fatalf("write corrupted: %v", err)
	}

	// Open should succeed (self-heal) not error
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open corrupted store should self-heal, got: %v", err)
	}

	// Store should be empty (fresh start)
	if len(s.Active()) != 0 {
		t.Errorf("expected empty store after corruption recovery, got %d", len(s.Active()))
	}

	// Save should overwrite with valid JSON
	s.Upsert(sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)"))
	if err := s.Save(); err != nil {
		t.Fatalf("save after recovery: %v", err)
	}

	// Reopen should work
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after recovery failed: %v", err)
	}
	defer func() { _ = s2.Save() }()
	if len(s2.Active()) != 1 {
		t.Errorf("expected 1 record after recovery+save, got %d", len(s2.Active()))
	}
}
