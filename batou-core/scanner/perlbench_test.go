package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPerlBench(t *testing.T) {
	root := projectRoot()
	// batou:ignore-start traversal -- test harness paths are built from compile-time project root, not user input
	csvPath := filepath.Join(root, "testdata", "bench", "perl", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "perl")
	// batou:ignore-end

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Perl benchmark fixtures not found; run: python3 tools/gen_bench_fixtures.py")
	}

	// Confidence gate: only count findings whose ConfidenceScore is at least
	// 0.5 (ConfBaseRegexHigh). Real Perl/CGI flows are confirmed by the
	// tsflow taint engine — including the newly added top-level/script-body
	// pass — and land at high confidence (0.8–1.0). Without a gate, the
	// harness counted regex-only low/medium findings (0.3–0.4) as detections;
	// those merely name-matched a dangerous function and the pipeline emits
	// them as hints, not blocks (RiskScore < 0.7). That all-tier noise was
	// masking the real top-level-flow hole, so gate it out here.
	runOWASPBenchMinConf(t, "perl", csvPath, testcodeDir, ".pl", 0.5)
}
