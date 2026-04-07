package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPHPBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "php", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "php")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("PHP benchmark fixtures not found")
	}

	runOWASPBench(t, "php", csvPath, testcodeDir, ".php")
}
