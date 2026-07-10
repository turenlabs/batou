package scanner_test

// Large-file performance baseline + anti-cheat harness.
//
// This file is the PM-owned ground truth for the large-file perf campaign:
//   - BenchmarkLargeFileScan: faithful hook-mode scanner.Scan per fixture,
//     for `go test -bench -cpuprofile/-memprofile`.
//   - TestLargeFileBaseline (env-gated BATOU_LARGEFILE=1): runs each fixture
//     once, prints a timing/timeout/finding table, and writes a canonical
//     golden finding-SET (RuleID\tLineNumber, sorted) per fixture to
//     $BATOU_GOLDEN_DIR. Optimizations must keep this set byte-identical.
//
// Why a SET and not a byte-diff: scan is nondeterministic in confidence-score
// ties (map-iteration order over rules), so the stable invariant is the set of
// (RuleID, LineNumber) pairs, compared as a set.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/scanner"
)

type largeFixture struct {
	lang string // dir name under testdata/largefiles
	file string // base filename, e.g. large_10k.go
	path string // absolute path
}

// largeFixtures enumerates the committed large-file corpus.
func largeFixtures(tb testing.TB) []largeFixture {
	tb.Helper()
	root := filepath.Join("..", "testdata", "largefiles")
	if r := os.Getenv("BATOU_LARGEFILE_ROOT"); r != "" {
		root = r // PM override: point at scratch stress corpus without committing >10k fixtures
	}
	var out []largeFixture
	// batou:ignore file_read -- test harness; root is a PM-supplied trusted env path (corpus dir), not attacker input
	langs, err := os.ReadDir(root)
	if err != nil {
		tb.Fatalf("read largefiles root: %v", err)
	}
	for _, ld := range langs {
		if !ld.IsDir() {
			continue
		}
		ldir := filepath.Join(root, ld.Name())
		// batou:ignore file_read -- test harness; ldir derives from the trusted PM env corpus root, not attacker input
		files, err := os.ReadDir(ldir)
		if err != nil {
			tb.Fatalf("read %s: %v", ldir, err)
		}
		for _, fe := range files {
			if fe.IsDir() {
				continue
			}
			abs, _ := filepath.Abs(filepath.Join(ldir, fe.Name()))
			out = append(out, largeFixture{lang: ld.Name(), file: fe.Name(), path: abs})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].lang != out[j].lang {
			return out[i].lang < out[j].lang
		}
		return out[i].file < out[j].file
	})
	return out
}

func (f largeFixture) label() string { return f.lang + "/" + f.file }

// scanLargeFixture runs one faithful hook-mode scan rooted in an isolated cwd
// so the call-graph phase runs for real without touching the repo's .batou.
func scanLargeFixture(tb testing.TB, f largeFixture, cwd string) (findings int, timedOut, panicked bool, golden []string, ms int64) {
	tb.Helper()
	content, err := os.ReadFile(f.path)
	if err != nil {
		tb.Fatalf("read fixture %s: %v", f.path, err)
	}
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		SessionID:     "largefile-baseline",
		Cwd:           cwd,
		ToolInput: hook.ToolInput{
			FilePath: filepath.Join(cwd, "src", f.file),
			Content:  string(content),
		},
	}
	start := time.Now()
	res := scanner.Scan(input)
	ms = time.Since(start).Milliseconds()
	set := make(map[string]struct{}, len(res.Findings))
	for _, fd := range res.Findings {
		switch fd.RuleID {
		case "BATOU-TIMEOUT":
			timedOut = true
		case "BATOU-PANIC":
			panicked = true
		}
		set[fmt.Sprintf("%s\t%d", fd.RuleID, fd.LineNumber)] = struct{}{}
	}
	golden = make([]string, 0, len(set))
	for k := range set {
		golden = append(golden, k)
	}
	sort.Strings(golden)
	return len(res.Findings), timedOut, panicked, golden, ms
}

// BenchmarkLargeFileScan measures one full scanner.Scan per fixture.
// Profile it with:
//
//	go test -run=NONE -bench=BenchmarkLargeFileScan -benchtime=5x \
//	  -cpuprofile=cpu.out -memprofile=mem.out ./batou-core/scanner/
func BenchmarkLargeFileScan(b *testing.B) {
	for _, f := range largeFixtures(b) {
		content, err := os.ReadFile(f.path)
		if err != nil {
			b.Fatalf("read %s: %v", f.path, err)
		}
		b.Run(f.label(), func(b *testing.B) {
			cwd := b.TempDir()
			input := &hook.Input{
				HookEventName: "PreToolUse",
				ToolName:      "Write",
				SessionID:     "largefile-bench",
				Cwd:           cwd,
				ToolInput: hook.ToolInput{
					FilePath: filepath.Join(cwd, "src", f.file),
					Content:  string(content),
				},
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(content)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanner.Scan(input)
			}
			b.StopTimer()
			b.ReportMetric(float64(strings.Count(string(content), "\n")), "loc")
		})
	}
}

// TestLargeFileBaseline prints the timing/timeout/finding baseline table and
// writes golden finding-sets. Env-gated so it never runs in the normal suite.
//
//	BATOU_LARGEFILE=1 BATOU_GOLDEN_DIR=/path go test -run TestLargeFileBaseline \
//	  -count=1 -timeout 600s ./batou-core/scanner/
func TestLargeFileBaseline(t *testing.T) {
	if os.Getenv("BATOU_LARGEFILE") == "" {
		t.Skip("set BATOU_LARGEFILE=1 to run the large-file baseline")
	}
	goldenDir := os.Getenv("BATOU_GOLDEN_DIR")
	if goldenDir != "" {
		// batou:ignore file_write -- test harness; goldenDir is a PM-supplied trusted env path, not user input
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
	}
	fixtures := largeFixtures(t)
	t.Logf("%-26s %8s %8s %8s %9s %8s", "fixture", "bytes", "ms", "findings", "timeout?", "panic?")
	for _, f := range fixtures {
		fi, _ := os.Stat(f.path)
		cwd := t.TempDir()
		n, timedOut, panicked, golden, ms := scanLargeFixture(t, f, cwd)
		t.Logf("%-26s %8d %8d %8d %9v %8v", f.label(), fi.Size(), ms, n, timedOut, panicked)
		if goldenDir != "" {
			name := strings.ReplaceAll(f.label(), "/", "__") + ".golden"
			// batou:ignore file_write -- test harness; goldenDir is a PM-supplied trusted env path, name is sanitized fixture label
			if err := os.WriteFile(filepath.Join(goldenDir, name), []byte(strings.Join(golden, "\n")+"\n"), 0o644); err != nil {
				t.Fatalf("write golden %s: %v", name, err)
			}
		}
	}
}

// TestLargeFileScansWithoutTimeout is the large-file robustness gate. Every
// committed large fixture (1k-10k LOC across Go/Python/JS/C) must scan to
// completion under the production scan timeout, producing real findings and
// never the BATOU-TIMEOUT or BATOU-PANIC sentinels.
//
// This is the regression guard for the perf campaign: a reintroduced per-node
// O(filesize) operation (the class of bug that made Python scanning quadratic)
// would push large files far past any reasonable budget, degrade detection to
// the partial-harvest path (raw, undeduped findings), and trip this test.
//
// The scan deadline is a WALL-CLOCK cap, and CI runs the package under the race
// detector. On busy self-hosted CI runners -race inflates
// wall-clock far more than the ~10x of the old GitHub 2-core runners, and
// CONCURRENT CI runs (e.g. a PR run plus the main-push run from a merge) starve
// each other's cores: a 10k-line fixture that scans in ~0.08s un-instrumented
// passes solo at a 60s budget but was observed to blow past it under cross-run
// contention. Asserting the production 10s cap here measures instrumentation +
// scheduling overhead, not an algorithmic regression. Two adjustments keep the
// assertion sound under -race without weakening it:
//   - BATOU_SCAN_TIMEOUT raises the per-scan budget to a race-appropriate value
//     with headroom for contention. A genuine O(filesize) blowup (the bug class
//     this guards — it hangs for minutes) dwarfs even this budget by orders of
//     magnitude, so the guard still catches it; only the detector's and
//     scheduler's constant-factor overhead is tolerated.
//   - the fixtures scan SERIALLY (no t.Parallel) so concurrent scans within this
//     test don't starve each other. Serial keeps the timing predictable.
func TestLargeFileScansWithoutTimeout(t *testing.T) {
	// Budget for the race detector's wall-clock inflation plus CI cross-run
	// contention; production keeps the 10s default (this env var is never set
	// outside tests). Safe under t.Setenv because the subtests below are serial.
	t.Setenv("BATOU_SCAN_TIMEOUT", "240s")
	for _, f := range largeFixtures(t) {
		f := f
		t.Run(f.label(), func(t *testing.T) {
			cwd := t.TempDir()
			n, timedOut, panicked, _, ms := scanLargeFixture(t, f, cwd)
			if timedOut {
				t.Errorf("%s hit the scan timeout after %dms: large-file perf regression — "+
					"detection silently degraded to the partial-harvest path", f.label(), ms)
			}
			if panicked {
				t.Errorf("%s produced a BATOU-PANIC sentinel: a rule panicked during the scan", f.label())
			}
			if n == 0 {
				t.Errorf("%s produced 0 findings (%dms): the fixtures are seeded with real vulns, so a "+
					"zero result means the scan broke or early-exited", f.label(), ms)
			}
		})
	}
}
