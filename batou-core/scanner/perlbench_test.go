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

	runOWASPBench(t, "perl", csvPath, testcodeDir, ".pl")
}
