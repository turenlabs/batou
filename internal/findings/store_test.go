package findings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou/internal/rules"
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
