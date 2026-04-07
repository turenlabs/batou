package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
)

func TestRustBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "rust", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "rust")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Rust benchmark fixtures not found")
	}

	runOWASPBench(t, "rust", csvPath, testcodeDir, ".rs")
}
