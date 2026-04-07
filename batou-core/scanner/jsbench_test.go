package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJSBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "javascript", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "javascript")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("JavaScript benchmark fixtures not found")
	}

	runOWASPBench(t, "javascript", csvPath, testcodeDir, ".js")
}
