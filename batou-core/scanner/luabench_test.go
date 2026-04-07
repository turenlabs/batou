package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLuaBench(t *testing.T) {
	root := projectRoot()
	// batou:ignore-start traversal -- test harness paths are built from compile-time project root, not user input
	csvPath := filepath.Join(root, "testdata", "bench", "lua", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "lua")
	// batou:ignore-end

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Lua benchmark fixtures not found; run: python3 tools/gen_bench_fixtures.py")
	}

	runOWASPBench(t, "lua", csvPath, testcodeDir, ".lua")
}
