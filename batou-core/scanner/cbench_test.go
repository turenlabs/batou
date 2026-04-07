package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
)

func TestCBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "c", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "c")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("C benchmark fixtures not found")
	}

	runOWASPBench(t, "c", csvPath, testcodeDir, ".c")
}
