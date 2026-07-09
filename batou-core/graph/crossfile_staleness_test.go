package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadCallerFile_StalenessGate verifies that loadCallerFile skips a file
// whose current content no longer matches the graph's scan-time whole-file
// baseline hash (so persisted StartLine/EndLine spans that would slice the
// wrong lines are never used), while leaving unchanged files, files with no
// baseline, and nil-graph callers exactly as before.
func TestLoadCallerFile_StalenessGate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "handler.go")
	current := "package main\nfunc H() { db.Query(userInput) }\n"
	if err := os.WriteFile(path, []byte(current), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Run("matching baseline proceeds", func(t *testing.T) {
		cg := NewCallGraph(dir, "s")
		cg.SetFileTaintCache(path, FileContentHash(current), 0)
		got, ok := loadCallerFile(cg, path, map[string]string{})
		if !ok || got != current {
			t.Errorf("fresh file should load: ok=%v len=%d", ok, len(got))
		}
	})

	t.Run("stale baseline skips", func(t *testing.T) {
		cg := NewCallGraph(dir, "s")
		// Baseline recorded a DIFFERENT content hash — the file moved/changed
		// out-of-band since the graph was built.
		cg.SetFileTaintCache(path, FileContentHash("old different content"), 0)
		if _, ok := loadCallerFile(cg, path, map[string]string{}); ok {
			t.Error("stale file (hash mismatch) must be skipped")
		}
	})

	t.Run("no baseline proceeds", func(t *testing.T) {
		cg := NewCallGraph(dir, "s") // no FileTaintCache entry for path
		if _, ok := loadCallerFile(cg, path, map[string]string{}); !ok {
			t.Error("file with no baseline must proceed (no spurious skip)")
		}
	})

	t.Run("nil graph proceeds", func(t *testing.T) {
		if _, ok := loadCallerFile(nil, path, map[string]string{}); !ok {
			t.Error("nil graph must proceed (staleness gate is opt-in)")
		}
	})

	t.Run("CRLF file matches LF-normalized baseline", func(t *testing.T) {
		// The scanner hashes CRLF-normalized content; a CRLF-on-disk file must
		// still match its baseline, not be spuriously skipped as stale.
		crlfPath := filepath.Join(dir, "crlf.go")
		lf := "package main\nfunc H() {}\n"
		crlf := "package main\r\nfunc H() {}\r\n"
		if err := os.WriteFile(crlfPath, []byte(crlf), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		cg := NewCallGraph(dir, "s")
		cg.SetFileTaintCache(crlfPath, FileContentHash(lf), 0) // baseline is LF-normalized
		if _, ok := loadCallerFile(cg, crlfPath, map[string]string{}); !ok {
			t.Error("CRLF file matching its LF-normalized baseline must proceed")
		}
	})

	t.Run("pre-populated content is trusted fresh", func(t *testing.T) {
		// Content already in the map (e.g. the hook's just-written file) is
		// trusted even when a stale baseline exists — it bypasses the disk read.
		cg := NewCallGraph(dir, "s")
		cg.SetFileTaintCache(path, FileContentHash("stale"), 0)
		fc := map[string]string{path: current}
		got, ok := loadCallerFile(cg, path, fc)
		if !ok || got != current {
			t.Errorf("pre-populated content should be returned as-is: ok=%v", ok)
		}
	})
}
