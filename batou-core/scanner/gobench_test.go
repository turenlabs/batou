package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "go", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "go")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Go benchmark fixtures not found; run: python3 tools/gen_go_bench.py")
	}

	runOWASPBench(t, "go", csvPath, testcodeDir, ".go")
}
