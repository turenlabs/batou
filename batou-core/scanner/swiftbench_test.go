package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwiftBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "swift", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "swift")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Swift benchmark fixtures not found")
	}

	runOWASPBench(t, "swift", csvPath, testcodeDir, ".swift")
}
